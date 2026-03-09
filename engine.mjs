// engine.mjs — Column execution engine
// Resolves dependencies, groups LLM columns, executes in waves

import { evalFormula, extractRefs } from './formula.mjs';
import { executeConnector } from './connectors.mjs';

// ─── Dependency Resolution ─────────────────────────────────────────────────

// Build execution plan from column definitions
// Returns array of "waves" — each wave is a set of columns that can execute in parallel
export function buildExecutionPlan(columns) {
  // Auto-detect dependencies from formulas, conditions, and input mappings
  const colById = new Map();
  const colByName = new Map();
  for (const col of columns) {
    colById.set(col.id, col);
    colByName.set(col.id, col);
    // Also index by name (lowercase, underscored) for formula references
    const nameKey = col.name.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, '_');
    colByName.set(nameKey, col);
  }

  // Resolve all dependencies
  for (const col of columns) {
    const deps = new Set(col.dependsOn || []);

    // Formula references → dependencies
    if (col.type === 'formula' && col.formula) {
      for (const ref of extractRefs(col.formula)) {
        const dep = findCol(columns, ref);
        if (dep && dep.id !== col.id) deps.add(dep.id);
      }
    }

    // Conditional wrapper → depends on the condition refs + wrapped column
    if (col.type === 'conditional') {
      if (col.condition) {
        for (const ref of extractRefs(col.condition)) {
          const dep = findCol(columns, ref);
          if (dep && dep.id !== col.id) deps.add(dep.id);
        }
      }
      if (col.wrappedColumnId) deps.add(col.wrappedColumnId);
    }

    // API input mapping references → dependencies
    if (col.type === 'api' && col.apiConfig?.inputMapping) {
      for (const val of Object.values(col.apiConfig.inputMapping)) {
        for (const ref of extractRefs(String(val))) {
          const dep = findCol(columns, ref);
          if (dep && dep.id !== col.id) deps.add(dep.id);
        }
      }
    }

    // LLM columns that reference other columns in their prompt
    if (col.type === 'llm' && col.llmConfig?.prompt) {
      for (const ref of extractRefs(col.llmConfig.prompt)) {
        const dep = findCol(columns, ref);
        if (dep && dep.id !== col.id) deps.add(dep.id);
      }
    }

    col._resolvedDeps = [...deps];
  }

  // Topological sort into waves
  const executed = new Set();
  const waves = [];
  const remaining = new Set(columns.map(c => c.id));

  // Input columns always go first (wave 0)
  const inputCols = columns.filter(c => c.type === 'input');
  if (inputCols.length) {
    waves.push(inputCols.map(c => c.id));
    for (const c of inputCols) { executed.add(c.id); remaining.delete(c.id); }
  }

  let safetyCounter = 0;
  while (remaining.size > 0 && safetyCounter < 50) {
    safetyCounter++;
    const wave = [];
    for (const id of remaining) {
      const col = colById.get(id);
      const deps = col._resolvedDeps || [];
      if (deps.every(d => executed.has(d))) {
        wave.push(id);
      }
    }
    if (wave.length === 0) {
      // Circular dependency — force remaining into final wave
      waves.push([...remaining]);
      break;
    }
    waves.push(wave);
    for (const id of wave) { executed.add(id); remaining.delete(id); }
  }

  return waves;
}

function findCol(columns, ref) {
  // Try exact ID match
  const byId = columns.find(c => c.id === ref);
  if (byId) return byId;
  // Try by name (normalized)
  const normRef = ref.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, '_');
  return columns.find(c => {
    const normName = c.name.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, '_');
    return normName === normRef || c.id === normRef;
  });
}

// ─── Row Executor ──────────────────────────────────────────────────────────

// Execute all columns for a single row
// rowData: { col_id: value } — starts with input columns populated
// columns: full column definitions
// context: { callLLM, getApiKey, emit, provider, signal }
export async function executeRow(rowData, columns, plan, context) {
  const colById = new Map(columns.map(c => [c.id, c]));
  const costs = { inputTokens: 0, outputTokens: 0, cacheRead: 0, cacheWrite: 0, apiCalls: 0, llmCalls: 0, totalCost: 0 };
  const errors = {};

  for (const wave of plan) {
    // Group LLM columns in this wave by group ID
    const llmGroups = new Map(); // groupId → [column, ...]
    const nonLlm = [];

    for (const colId of wave) {
      const col = colById.get(colId);
      if (!col || col.type === 'input') continue; // inputs already populated

      if (col.type === 'llm') {
        const group = col.llmConfig?.group || col.id; // ungrouped = own group
        if (!llmGroups.has(group)) llmGroups.set(group, []);
        llmGroups.get(group).push(col);
      } else {
        nonLlm.push(col);
      }
    }

    // Execute non-LLM columns in parallel
    const nonLlmPromises = nonLlm.map(async (col) => {
      try {
        if (context.signal?.aborted) return;

        if (col.type === 'formula') {
          rowData[col.id] = String(evalFormula(col.formula, rowData) ?? '');
        }

        else if (col.type === 'conditional') {
          // Evaluate condition
          const condResult = evalFormula(col.condition, rowData);
          if (condResult === true || condResult === 'Yes' || condResult === 'true') {
            // Condition met — but the wrapped column executes via its own wave
            // Just mark the condition as passed
            rowData[col.id] = 'true';
          } else {
            rowData[col.id] = '';
          }
        }

        else if (col.type === 'api') {
          const connector = col.apiConfig?.connector;
          if (!connector) { rowData[col.id] = ''; return; }

          // Build params from input mapping
          const params = {};
          if (col.apiConfig.inputMapping) {
            for (const [param, template] of Object.entries(col.apiConfig.inputMapping)) {
              params[param] = resolveTemplate(template, rowData);
            }
          }

          // Get API key if needed
          const apiKey = col.apiConfig.keyName ? context.getApiKey(col.apiConfig.keyName) : null;
          costs.apiCalls++;

          const result = await executeConnector(connector, params, apiKey, col.apiConfig.customConfig);

          if (result.error) {
            errors[col.id] = result.error;
          }

          // If column specifies a specific output field, extract it
          if (col.apiConfig.outputField) {
            rowData[col.id] = String(result[col.apiConfig.outputField] ?? '');
          } else {
            // Map all outputs to columns that reference this connector
            // The column itself gets the first output field or a summary
            for (const [key, val] of Object.entries(result)) {
              if (key === 'error') continue;
              // Check if there's a column that maps to this output
              const targetCol = columns.find(c =>
                c.type === 'api' &&
                c.apiConfig?.connector === connector &&
                c.apiConfig?.outputField === key &&
                c.id !== col.id
              );
              if (targetCol) {
                rowData[targetCol.id] = String(val ?? '');
              }
            }
            // Store primary output in this column
            const primaryField = col.apiConfig.outputField || Object.keys(result).find(k => k !== 'error');
            rowData[col.id] = String(result[primaryField] ?? '');
          }
        }
      } catch (e) {
        errors[col.id] = e.message;
        rowData[col.id] = '';
      }
    });

    // Execute LLM groups in parallel (each group = one LLM call)
    const llmPromises = [...llmGroups.entries()].map(async ([groupId, groupCols]) => {
      try {
        if (context.signal?.aborted) return;

        // Build the prompt for this group
        const sectionDefs = groupCols.map(c => ({
          key: c.id,
          label: c.name,
          instruction: c.llmConfig?.instruction || '',
        }));

        // Use custom prompt if the group has one, otherwise auto-generate
        const groupConfig = groupCols[0].llmConfig || {};
        let systemPrompt;

        if (groupConfig.systemPrompt) {
          systemPrompt = groupConfig.systemPrompt;
        } else {
          systemPrompt = buildGroupPrompt(sectionDefs, groupConfig);
        }

        // Build user message with all available row data
        const userMessage = buildUserMessage(rowData, columns);

        // Wrap with JSON format instructions
        const keyList = sectionDefs.map(s => `"${s.key}"`).join(', ');
        const wrappedPrompt = `${systemPrompt}

---
OUTPUT FORMAT: Return a single valid JSON object with these exact keys: ${keyList}
Every value must be a plain text string. If data is unavailable, write "".
Do NOT wrap in code fences.`;

        const provider = groupConfig.provider || context.provider;
        const temperature = groupConfig.temperature ?? 0;
        const webSearch = groupConfig.webSearch !== false;

        costs.llmCalls++;

        const result = await context.callLLM(
          userMessage, provider, wrappedPrompt, webSearch,
          temperature, context.signal
        );

        costs.inputTokens += result.inputTokens || 0;
        costs.outputTokens += result.outputTokens || 0;
        costs.cacheRead += result.cacheRead || 0;
        costs.cacheWrite += result.cacheWrite || 0;

        // Parse response — try JSON first
        const parsed = parseGroupResponse(result.research, sectionDefs);

        // Distribute to columns
        for (const col of groupCols) {
          rowData[col.id] = parsed[col.id] || '';
        }
      } catch (e) {
        for (const col of groupCols) {
          errors[col.id] = e.message || String(e);
          rowData[col.id] = '';
        }
      }
    });

    // Wait for all columns in this wave
    await Promise.all([...nonLlmPromises, ...llmPromises]);
  }

  return { data: rowData, costs, errors };
}

// ─── Prompt Builders ───────────────────────────────────────────────────────

function buildGroupPrompt(sectionDefs, config) {
  const role = config.role || 'expert B2B researcher';
  let prompt = `You are an ${role}. Research the prospect and provide:\n\n`;
  sectionDefs.forEach((s, i) => {
    prompt += `${i + 1}. **${s.label}**`;
    if (s.instruction) prompt += ` — ${s.instruction}`;
    prompt += '\n';
  });
  prompt += '\nBe specific and actionable. Use concrete details, names, dates, and numbers.';
  return prompt;
}

function buildUserMessage(rowData, columns) {
  const inputCols = columns.filter(c => c.type === 'input');
  let msg = 'Research this prospect:\n\n';
  for (const col of inputCols) {
    const val = rowData[col.id];
    if (val && String(val).trim()) {
      msg += `**${col.name}:** ${val}\n`;
    }
  }
  // Include any already-computed columns as context
  const computedCols = columns.filter(c => c.type !== 'input' && c.type !== 'llm' && rowData[c.id]);
  if (computedCols.length) {
    msg += '\n--- ADDITIONAL DATA ---\n';
    for (const col of computedCols) {
      const val = rowData[col.id];
      if (val && String(val).trim() && !String(val).startsWith('#ERROR')) {
        msg += `**${col.name}:** ${val}\n`;
      }
    }
  }
  msg += '\nUse web search to find the most current information.';
  return msg;
}

function resolveTemplate(template, rowData) {
  return String(template).replace(/\{([^}]+)\}/g, (_, ref) => {
    return rowData[ref] || rowData[ref.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, '_')] || '';
  });
}

// ─── Response Parsing ──────────────────────────────────────────────────────

function parseGroupResponse(text, sectionDefs) {
  if (!text) return {};
  const result = {};

  // Try JSON parse
  const cleaned = text.trim().replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?\s*```\s*$/, '').trim();

  // Try direct parse
  let parsed = null;
  try { parsed = JSON.parse(cleaned); } catch {}

  // Try extracting JSON from within text
  if (!parsed) {
    const first = cleaned.indexOf('{');
    const last = cleaned.lastIndexOf('}');
    if (first >= 0 && last > first) {
      try { parsed = JSON.parse(cleaned.slice(first, last + 1)); } catch {}
    }
  }

  if (parsed && typeof parsed === 'object') {
    for (const s of sectionDefs) {
      if (parsed[s.key] !== undefined) {
        result[s.key] = cleanValue(parsed[s.key]);
      } else {
        // Fuzzy match
        const normKey = s.key.toLowerCase().replace(/[^a-z0-9]/g, '');
        const match = Object.keys(parsed).find(k =>
          k.toLowerCase().replace(/[^a-z0-9]/g, '') === normKey
        );
        if (match) result[s.key] = cleanValue(parsed[match]);
        else result[s.key] = '';
      }
    }
    return result;
  }

  // Fallback: split by numbered sections
  const numSplit = text.split(/(?:^|\n)\s*\d+\.\s/);
  if (numSplit.length > 1) {
    const chunks = numSplit.slice(1);
    for (let i = 0; i < sectionDefs.length; i++) {
      result[sectionDefs[i].key] = i < chunks.length
        ? chunks[i].replace(/^\*\*[^*]+\*\*\s*[-:]?\s*/, '').trim()
        : '';
    }
    return result;
  }

  // Last resort: put everything in first column
  if (sectionDefs.length) result[sectionDefs[0].key] = text;
  return result;
}

function cleanValue(v) {
  if (typeof v === 'string') return v.trim();
  if (Array.isArray(v)) return v.map(x => typeof x === 'string' ? x : JSON.stringify(x)).join('; ');
  if (typeof v === 'object' && v !== null) return Object.entries(v).map(([k, x]) => `${k}: ${x}`).join('; ');
  return String(v);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// Convert old-style sections to new column definitions
export function sectionsToColumns(sections, csvHeaders, colMap) {
  const columns = [];

  // Input columns from CSV
  if (colMap) {
    for (const [role, header] of Object.entries(colMap)) {
      if (!header) continue;
      columns.push({
        id: role,
        name: header,
        type: 'input',
      });
    }
  }

  // LLM columns from sections — all in one group for cost efficiency
  if (sections && sections.length) {
    for (const s of sections) {
      columns.push({
        id: s.key,
        name: s.label,
        type: 'llm',
        llmConfig: { group: 'research', webSearch: true, temperature: 0 },
      });
    }
  }

  return columns;
}
