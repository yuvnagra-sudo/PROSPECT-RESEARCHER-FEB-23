// formula.mjs — Formula engine for computed columns
// Evaluates expressions with column references like {column_name}

// ─── Tokenizer ─────────────────────────────────────────────────────────────
const TOKEN = {
  REF: 'REF', STR: 'STR', NUM: 'NUM', BOOL: 'BOOL',
  OP: 'OP', FUNC: 'FUNC', LPAREN: '(', RPAREN: ')', COMMA: ',',
};

function tokenize(expr) {
  const tokens = [];
  let i = 0;
  const s = expr.trim();
  while (i < s.length) {
    // Skip whitespace
    if (/\s/.test(s[i])) { i++; continue; }
    // Column reference: {column_name}
    if (s[i] === '{') {
      const end = s.indexOf('}', i);
      if (end === -1) throw new Error(`Unclosed { at position ${i}`);
      tokens.push({ type: TOKEN.REF, value: s.slice(i + 1, end).trim() });
      i = end + 1;
      continue;
    }
    // String literal: "..." or '...'
    if (s[i] === '"' || s[i] === "'") {
      const q = s[i]; let j = i + 1; let val = '';
      while (j < s.length && s[j] !== q) {
        if (s[j] === '\\' && j + 1 < s.length) { val += s[j + 1]; j += 2; } else { val += s[j]; j++; }
      }
      tokens.push({ type: TOKEN.STR, value: val });
      i = j + 1;
      continue;
    }
    // Number
    if (/[\d.]/.test(s[i])) {
      let j = i;
      while (j < s.length && /[\d.]/.test(s[j])) j++;
      tokens.push({ type: TOKEN.NUM, value: parseFloat(s.slice(i, j)) });
      i = j;
      continue;
    }
    // Operators: ==, !=, <=, >=, <, >, +, -, *, /
    if ('=!<>+-*/'.includes(s[i])) {
      if (i + 1 < s.length && s[i + 1] === '=') {
        tokens.push({ type: TOKEN.OP, value: s.slice(i, i + 2) });
        i += 2;
      } else {
        tokens.push({ type: TOKEN.OP, value: s[i] });
        i++;
      }
      continue;
    }
    // Parens, comma
    if (s[i] === '(') { tokens.push({ type: TOKEN.LPAREN }); i++; continue; }
    if (s[i] === ')') { tokens.push({ type: TOKEN.RPAREN }); i++; continue; }
    if (s[i] === ',') { tokens.push({ type: TOKEN.COMMA }); i++; continue; }
    // Keywords / function names
    if (/[a-zA-Z_]/.test(s[i])) {
      let j = i;
      while (j < s.length && /[a-zA-Z_0-9]/.test(s[j])) j++;
      const word = s.slice(i, j);
      const upper = word.toUpperCase();
      if (upper === 'TRUE') tokens.push({ type: TOKEN.BOOL, value: true });
      else if (upper === 'FALSE') tokens.push({ type: TOKEN.BOOL, value: false });
      else if (upper === 'AND' || upper === 'OR' || upper === 'NOT') tokens.push({ type: TOKEN.OP, value: upper });
      else tokens.push({ type: TOKEN.FUNC, value: upper });
      i = j;
      continue;
    }
    throw new Error(`Unexpected character '${s[i]}' at position ${i}`);
  }
  return tokens;
}

// ─── Parser (recursive descent) ────────────────────────────────────────────
function parse(tokens) {
  let pos = 0;
  function peek() { return tokens[pos] || null; }
  function eat(type) {
    const t = tokens[pos];
    if (!t || (type && t.type !== type)) throw new Error(`Expected ${type} at pos ${pos}, got ${t?.type || 'EOF'}`);
    pos++;
    return t;
  }

  function parseExpr() { return parseOr(); }

  function parseOr() {
    let left = parseAnd();
    while (peek()?.type === TOKEN.OP && peek().value === 'OR') {
      eat(); left = { op: 'OR', left, right: parseAnd() };
    }
    return left;
  }

  function parseAnd() {
    let left = parseNot();
    while (peek()?.type === TOKEN.OP && peek().value === 'AND') {
      eat(); left = { op: 'AND', left, right: parseNot() };
    }
    return left;
  }

  function parseNot() {
    if (peek()?.type === TOKEN.OP && peek().value === 'NOT') {
      eat(); return { op: 'NOT', arg: parseNot() };
    }
    return parseComparison();
  }

  function parseComparison() {
    let left = parseAddSub();
    const ops = ['==', '!=', '<', '>', '<=', '>='];
    while (peek()?.type === TOKEN.OP && ops.includes(peek().value)) {
      const op = eat().value;
      left = { op, left, right: parseAddSub() };
    }
    return left;
  }

  function parseAddSub() {
    let left = parseMulDiv();
    while (peek()?.type === TOKEN.OP && (peek().value === '+' || peek().value === '-')) {
      const op = eat().value;
      left = { op, left, right: parseMulDiv() };
    }
    return left;
  }

  function parseMulDiv() {
    let left = parseAtom();
    while (peek()?.type === TOKEN.OP && (peek().value === '*' || peek().value === '/')) {
      const op = eat().value;
      left = { op, left, right: parseAtom() };
    }
    return left;
  }

  function parseAtom() {
    const t = peek();
    if (!t) throw new Error('Unexpected end of expression');

    // Function call
    if (t.type === TOKEN.FUNC) {
      const name = eat().value;
      eat(TOKEN.LPAREN);
      const args = [];
      if (peek()?.type !== TOKEN.RPAREN) {
        args.push(parseExpr());
        while (peek()?.type === TOKEN.COMMA) { eat(); args.push(parseExpr()); }
      }
      eat(TOKEN.RPAREN);
      return { func: name, args };
    }

    // Parenthesized expression
    if (t.type === TOKEN.LPAREN) {
      eat(); const inner = parseExpr(); eat(TOKEN.RPAREN); return inner;
    }

    // Literals and references
    if (t.type === TOKEN.NUM) { eat(); return { lit: t.value }; }
    if (t.type === TOKEN.STR) { eat(); return { lit: t.value }; }
    if (t.type === TOKEN.BOOL) { eat(); return { lit: t.value }; }
    if (t.type === TOKEN.REF) { eat(); return { ref: t.value }; }

    throw new Error(`Unexpected token ${t.type} (${t.value}) at pos ${pos}`);
  }

  const ast = parseExpr();
  if (pos < tokens.length) throw new Error(`Unexpected token after expression at pos ${pos}`);
  return ast;
}

// ─── Evaluator ─────────────────────────────────────────────────────────────
function evaluate(ast, rowData) {
  if (ast.lit !== undefined) return ast.lit;

  if (ast.ref !== undefined) {
    const val = rowData[ast.ref];
    if (val === undefined || val === null) return '';
    return val;
  }

  if (ast.func) {
    const args = ast.args.map(a => evaluate(a, rowData));
    switch (ast.func) {
      case 'IF': return truthy(args[0]) ? args[1] : (args[2] ?? '');
      case 'CONCAT': return args.join('');
      case 'COALESCE': return args.find(a => a !== '' && a !== null && a !== undefined) ?? '';
      case 'CONTAINS': return String(args[0] || '').toLowerCase().includes(String(args[1] || '').toLowerCase()) ? true : false;
      case 'LEN': return String(args[0] || '').length;
      case 'UPPER': return String(args[0] || '').toUpperCase();
      case 'LOWER': return String(args[0] || '').toLowerCase();
      case 'TRIM': return String(args[0] || '').trim();
      case 'LEFT': return String(args[0] || '').slice(0, Number(args[1]) || 0);
      case 'RIGHT': return String(args[0] || '').slice(-(Number(args[1]) || 0));
      case 'REPLACE': return String(args[0] || '').replace(new RegExp(escReg(String(args[1] || '')), 'gi'), String(args[2] || ''));
      case 'ROUND': return Math.round(Number(args[0]) || 0);
      case 'ABS': return Math.abs(Number(args[0]) || 0);
      case 'MIN': return Math.min(...args.map(Number));
      case 'MAX': return Math.max(...args.map(Number));
      case 'ISEMPTY': return args[0] === '' || args[0] === null || args[0] === undefined;
      case 'ISNOTEMPTY': return args[0] !== '' && args[0] !== null && args[0] !== undefined;
      case 'TONUMBER': return Number(args[0]) || 0;
      case 'TOSTRING': return String(args[0] ?? '');
      default: throw new Error(`Unknown function: ${ast.func}`);
    }
  }

  if (ast.op) {
    if (ast.op === 'NOT') return !truthy(evaluate(ast.arg, rowData));
    const left = evaluate(ast.left, rowData);
    const right = evaluate(ast.right, rowData);
    switch (ast.op) {
      case 'AND': return truthy(left) && truthy(right);
      case 'OR': return truthy(left) || truthy(right);
      case '==': return String(left) === String(right);
      case '!=': return String(left) !== String(right);
      case '<': return Number(left) < Number(right);
      case '>': return Number(left) > Number(right);
      case '<=': return Number(left) <= Number(right);
      case '>=': return Number(left) >= Number(right);
      case '+': {
        const nl = Number(left), nr = Number(right);
        return (!isNaN(nl) && !isNaN(nr) && left !== '' && right !== '') ? nl + nr : String(left) + String(right);
      }
      case '-': return (Number(left) || 0) - (Number(right) || 0);
      case '*': return (Number(left) || 0) * (Number(right) || 0);
      case '/': { const d = Number(right); return d === 0 ? '#DIV/0!' : (Number(left) || 0) / d; }
      default: throw new Error(`Unknown op: ${ast.op}`);
    }
  }

  throw new Error('Invalid AST node');
}

function truthy(v) {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') return v !== '' && v.toLowerCase() !== 'false' && v !== '0';
  return !!v;
}

function escReg(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ─── Extract column references from a formula ─────────────────────────────
export function extractRefs(formula) {
  const refs = [];
  const re = /\{([^}]+)\}/g;
  let m;
  while ((m = re.exec(formula)) !== null) refs.push(m[1].trim());
  return [...new Set(refs)];
}

// ─── Public API ────────────────────────────────────────────────────────────
export function evalFormula(formula, rowData) {
  try {
    const tokens = tokenize(formula);
    const ast = parse(tokens);
    const result = evaluate(ast, rowData);
    // Convert booleans to strings for CSV
    if (typeof result === 'boolean') return result ? 'Yes' : 'No';
    return result;
  } catch (e) {
    return `#ERROR: ${e.message}`;
  }
}

// ─── Validate formula syntax (returns null if valid, error string if not) ──
export function validateFormula(formula) {
  try {
    const tokens = tokenize(formula);
    parse(tokens);
    return null;
  } catch (e) {
    return e.message;
  }
}
