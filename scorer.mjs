// scorer.mjs — Audit Scorer & Findings Extractor
// Ported from score_and_personalize.py

// ─── Helpers ──────────────────────────────────────────────────────────────────
function safeInt(val, def = null) { const n = parseInt(val); return isNaN(n) ? def : n; }
function safeFloat(val, def = null) { const n = parseFloat(val); return isNaN(n) ? def : n; }
function tbool(val) { return String(val || '').trim().toLowerCase() === 'true'; }

// ─── Data Quality Classifier ──────────────────────────────────────────────────
export function classifyDataQuality(row) {
  const alive   = (row['Site Alive']  || '').trim();
  const flags   = (row['Site Flags']  || '').trim();
  const title   = (row['Title']       || '').trim();
  const docKb   = safeFloat(row['Doc Size KB'], 0);
  const weightKb= safeFloat(row['Total Weight (KB)'], 0);
  const requests= safeInt(row['Requests'], 0);
  const platform= (row['Platform']    || '').trim();
  const perfM   = safeInt(row['Performance (Mobile)']);
  const status  = (row['Status']      || '').trim().toLowerCase();

  if (alive === 'No' || flags.includes('connection-failed')) return 'dead';
  if (status !== 'success') return 'dead';
  if (title.toLowerCase() === 'access denied') return 'crawler_blocked';
  if (title.toLowerCase() === 'default web site page') return 'default_page';
  if (!title && docKb <= 1 && requests <= 1 && weightKb <= 5) return 'broken';
  if (docKb <= 1 && weightKb <= 20 && ['', 'Unknown'].includes(platform)) {
    if (perfM !== null && perfM >= 90 && requests <= 6) return 'empty_shell';
  }
  if (!title && docKb <= 5 && ['', 'Unknown'].includes(platform)) return 'empty_shell';
  return 'good';
}

// ─── Findings Extractor ───────────────────────────────────────────────────────
export function extractFindings(row) {
  const findings = [];
  const add = (sev, cat, text, conf = 'medium') => findings.push({ sev, cat, text, conf });

  // ── Performance ─────────────────────────────────────────────────────────────
  const perfM = safeInt(row['Performance (Mobile)']);
  const perfD = safeInt(row['Performance (Desktop)']);

  if (perfM !== null && perfD !== null) {
    if (perfM >= 80 && perfD >= 80)
      add('GOOD', 'performance', `Strong performance: ${perfM}/100 mobile, ${perfD}/100 desktop`);
    else if (perfM < 30)
      add('HIGH', 'performance', `Very poor mobile performance (${perfM}/100)`);
    else if (perfM < 50)
      add('HIGH', 'performance', `Poor mobile performance (${perfM}/100, desktop ${perfD}/100)`);
    else if (perfM < 70)
      add('MED', 'performance', `Below-average mobile performance (${perfM}/100, desktop ${perfD}/100)`);

    if (Math.abs(perfD - perfM) > 35)
      add('MED', 'performance', `Large desktop/mobile gap (${perfD} desktop vs ${perfM} mobile)`);
  }

  const lcpM = safeFloat(row['LCP ms (Lab)']);
  if (lcpM && lcpM > 4000 && lcpM <= 30000) {
    const s = Math.round(lcpM / 100) / 10;
    add(s > 10 ? 'HIGH' : 'MED', 'performance', `LCP ${s}s on mobile (time until main content visible)`);
  }

  const cls = safeFloat(row['CLS Score (Lab)']);
  if (cls && cls > 0.25)     add('HIGH', 'performance', `CLS ${cls} (layout shift, Google threshold is 0.1)`);
  else if (cls && cls > 0.1) add('MED',  'performance', `CLS ${cls} (moderate layout shift, Google threshold is 0.1)`);

  const tbt = safeFloat(row['TBT ms (Lab)']);
  if (tbt && tbt > 5000)     add('HIGH', 'performance', `TBT ${Math.round(tbt/100)/10}s on mobile (page feels frozen during load)`);
  else if (tbt && tbt > 1000)add('MED',  'performance', `TBT ${Math.round(tbt)}ms on mobile (page feels sluggish during load)`);

  const weightKb = safeFloat(row['Total Weight (KB)'], 0);
  if (weightKb > 20000)      add('MED', 'performance', `Page weight ${Math.round(weightKb/102.4)/10} MB`, 'high');
  else if (weightKb > 10000) add('LOW', 'performance', `Page weight ${Math.round(weightKb/102.4)/10} MB`, 'high');

  const docKb = safeFloat(row['Doc Size KB'], 0);
  if (docKb > 500) add('MED', 'performance', `HTML document ${Math.round(docKb)}KB (typical under 100KB)`, 'high');

  const requests = safeInt(row['Requests']);
  if (requests && requests > 150) add('LOW', 'performance', `${requests} HTTP requests`, 'high');

  const unusedJs = safeFloat(row['Unused JS (KB)'], 0);
  if (unusedJs && unusedJs > 500) add('LOW', 'tech', `${Math.round(unusedJs)}KB unused JavaScript`);

  const unusedCss = safeFloat(row['Unused CSS (KB)'], 0);
  if (unusedCss && unusedCss > 100) add('LOW', 'tech', `${Math.round(unusedCss)}KB unused CSS`);

  // ── SEO ──────────────────────────────────────────────────────────────────────
  if (tbool(row['Is Noindex'])) {
    add('CRITICAL', 'seo', "Noindex tag set, Google told not to index the site", 'high');
  } else {
    const metaLen = safeInt(row['Meta Desc Length'], 0);
    if (!(row['Meta Description'] || '').trim() || metaLen === 0)
      add('HIGH', 'seo', 'No meta description detected');

    const titleLen = safeInt(row['Title Length'], 0);
    if (titleLen === 0)        add('MED', 'seo', 'No title tag detected');
    else if (titleLen < 20)    add('LOW', 'seo', `Title very short (${titleLen} chars)`, 'high');
    else if (titleLen > 70)    add('LOW', 'seo', `Title too long (${titleLen} chars, Google truncates ~60)`, 'high');

    const h1 = safeInt(row['H1 Count'], 0);
    if (h1 === 0)     add('MED', 'seo', 'No H1 heading tag detected');
    else if (h1 > 3)  add('LOW', 'seo', `${h1} H1 tags (recommended: 1)`, 'high');

    if (!tbool(row['Has Canonical'])) add('LOW', 'seo', 'No canonical tag');

    const hasSitemap = tbool(row['Has Sitemap']);
    const hasJsonLD  = tbool(row['Has JSON-LD']);
    const seoScore   = safeInt(row['SEO (Mobile)']);
    if (hasSitemap && tbool(row['Has Canonical'])) {
      const parts = ['sitemap', 'canonical'];
      if (hasJsonLD) parts.push('structured data');
      if (seoScore && seoScore >= 90)
        add('GOOD', 'seo', `Solid technical SEO (${seoScore}/100): ${parts.join(', ')}`, 'high');
    }
    if (!hasSitemap && docKb > 50) add('LOW', 'seo', 'No XML sitemap detected');
  }

  // ── Security ─────────────────────────────────────────────────────────────────
  if (!tbool(row['HTTPS Works'])) {
    add('CRITICAL', 'security', "HTTPS not working, browsers show 'Not Secure' warning", 'high');
  } else {
    if (!tbool(row['HTTP→HTTPS Redirect']))
      add('MED', 'security', 'HTTP does not redirect to HTTPS');
  }

  const pairs = [
    ['HSTS', row['HSTS']], ['CSP', row['CSP Header']],
    ['X-Content-Type-Options', row['X-Content-Type-Options']],
    ['X-Frame-Options', row['X-Frame-Options']],
  ];
  const present = pairs.filter(([, v]) => (v || '').trim()).map(([n]) => n);
  const missing = pairs.filter(([, v]) => !(v || '').trim()).map(([n]) => n);
  if (present.length >= 3) add('GOOD', 'security', `Security headers configured: ${present.join(', ')}`, 'high');
  else if (missing.length >= 3) add('LOW', 'security', `Missing security headers: ${missing.join(', ')}`, 'high');

  // ── Accessibility ─────────────────────────────────────────────────────────────
  const acc = safeInt(row['Accessibility (Mobile)']);
  if (acc !== null) {
    if (acc >= 95)    add('GOOD', 'accessibility', `Accessibility ${acc}/100`);
    else if (acc < 60)add('MED',  'accessibility', `Low accessibility (${acc}/100)`);
  }

  // ── Conversion ────────────────────────────────────────────────────────────────
  const convFeatures = [
    ['Has Contact Form', 'contact form'], ['Has Scheduling', 'scheduling'],
    ['Has Chat Widget', 'chat'], ['Has Client Portal', 'client portal'],
    ['Has Email Capture', 'email capture'], ['Has Click-to-Call', 'click-to-call'],
    ['Has Calculator/Tool', 'calculator/tool'],
  ].filter(([k]) => tbool(row[k])).map(([, v]) => v);

  if (convFeatures.length >= 3)    add('GOOD', 'conversion', `Has ${convFeatures.join(', ')}`, 'low');
  else if (convFeatures.length === 0) add('MED', 'conversion', 'No conversion elements detected (no form, scheduling, chat, email capture)', 'low');

  const hasAnalytics = (row['Has Analytics'] || '').trim().toLowerCase();
  if (!hasAnalytics || hasAnalytics === 'false')
    add('LOW', 'conversion', 'No analytics detected in HTML (possible false positive if using tag manager)', 'low');

  // ── Platform ──────────────────────────────────────────────────────────────────
  const platform = (row['Platform'] || '').trim();
  if (platform && platform !== 'Unknown') add('LOW', 'tech', `Platform: ${platform}`, 'high');

  return findings;
}

// ─── Scoring ──────────────────────────────────────────────────────────────────
const SEV_POINTS = { CRITICAL: 25, HIGH: 10, MED: 4, LOW: 1, GOOD: 0 };

export function scoreFromFindings(findings) {
  return Math.max(0, findings.reduce((s, f) => s - (SEV_POINTS[f.sev] || 0), 100));
}

export function findingsToSummary(findings) {
  return findings.map(f => `[${f.sev}] ${f.text}`).join(' | ');
}

// ─── Prompt Builders ─────────────────────────────────────────────────────────
const PROMPT_GOOD = `Write a personalized website audit summary for a cold email. This goes into a {{{{audit_insert}}}} merge field. The recipient should read this and think "this person actually looked at my site and knows what they're talking about."

STRUCTURE:
- Open with whatever stands out most about this site, good or bad. If the site does something well, say so first. Earned credibility makes the problems land harder.
- Walk through every finding that matters. Don't skip findings just to be brief. If the audit found it, the recipient deserves to know.
- Group related findings naturally. Performance issues together, SEO issues together, security together. Don't use headers or labels though, just flow between topics with natural transitions.
- Close with the one thing that would make the biggest difference if they fixed it. Not a pitch, just an honest "if I had to pick one thing" observation.

HEDGING RULES (this is critical, get this right):
- "high" confidence findings are verifiable facts (page weight, title length, platform). Use light hedges: "it looks like", "appears to have."
- "medium" confidence findings come from automated Lighthouse scans that fluctuate between runs. Use moderate hedges: "came in around", "in our scan", "at the time we checked." Never present a Lighthouse score as a fixed number. Always "around X" or "roughly X."
- "low" confidence findings could be wrong because of JavaScript rendering, tag managers, or dynamic loading. Use strong hedges: "we didn't detect", "it's possible our scan missed this", "worth double-checking." Always offer the innocent explanation.
- GOOD findings: state directly, no hedge needed. Compliments should feel confident.
- When in doubt, hedge more not less. One false claim kills all credibility.

TONE AND FORMAT:
- Peer to peer. Not salesy, not condescending, not overly formal. Write like a knowledgeable colleague sharing what they found.
- 8th grade reading level. When you use a technical term, immediately explain what it means in plain English. Example: "CLS (that's the metric for how much things jump around on screen while the page loads)"
- No bullet points. No numbered lists. No headers. Flowing paragraphs only.
- No em dashes. Commas and periods only.
- Don't say "I noticed" or "I found." Say "our scan showed" or "when we checked" or "it looks like."
- Don't end with a question, CTA, or pitch. The email template handles that. Just end with your honest "biggest single improvement" observation.
- Don't start with "Hi" or any greeting. This is a merge field that goes mid-email.
- Don't use the phrases "indicates", "demonstrates", "utilize", "leverage", "ensure", or "I'd recommend." These sound like AI wrote them.

SCORE CONTEXT:
- 85+: This is a well-built site. Lead with genuine praise, mention the minor things almost as afterthoughts.
- 65-84: Mixed bag. Acknowledge what's working, then get into what's not.
- 50-64: More problems than strengths. Lead with the biggest issue but still give credit where it's earned.
- Below 50: Significant issues. Be direct about the biggest problem but stay respectful. These people didn't ask for your opinion, so deliver hard truths gently.

COMPANY: {company}
URL: {url}
SCORE: {score}/100

FINDINGS (sorted by impact, with confidence level):
{findings_block}

Write the audit summary now.`;

const PROMPT_BLOCKED = `Write a personalized website audit summary for a cold email where the scan couldn't get reliable data. This goes into a {{{{audit_insert}}}} merge field.

Even though we couldn't get full audit data, this is still a finding worth sharing. The fact that our crawler couldn't access the site properly is itself useful information, because search engine crawlers may be having the same experience.

RULES:
- Write 3-5 sentences. Explain what happened, why it might matter, and what the innocent explanation could be.
- Hedge heavily throughout. Use "when we checked" / "at the time of our scan" / "appeared to." Never state the problem as a definitive fact.
- Always offer the benign explanation (temporary downtime, JS rendering, bot protection that's working as intended, mid-migration, etc.)
- Then explain why it's still worth knowing: if Googlebot or other search crawlers hit the same thing, it could affect how the site shows up in search results.
- Don't end with a question, CTA, or pitch.
- No em dashes. No bullet points.
- 8th grade reading level.
- Don't start with "Hi" or any greeting.
- Don't say "I noticed" or "I found." Say "when we ran a scan" or "our audit tool."

COMPANY: {company}
URL: {url}
ISSUE TYPE: {quality}
WHAT HAPPENED: {description}

Write the audit summary now.`;

const QUALITY_DESCRIPTIONS = {
  dead:            "The site didn't respond during our scan. Could be temporarily down or blocking automated requests.",
  broken:          "The site showed a server error (like a PHP or database error) instead of actual content. Could be temporary.",
  default_page:    "The site showed a generic hosting provider default page instead of the business's actual website. Often a DNS or SSL config issue, or the site was mid-migration.",
  crawler_blocked: "The site returned 'Access Denied' to our crawler. It probably works in a regular browser but may be blocking bots. If Googlebot gets the same treatment, it could affect indexing.",
  empty_shell:     "The page had virtually no content when our crawler loaded it. Could be a parked domain, placeholder, or a JS-heavy site that requires a full browser to render.",
};

export function buildPromptContext(company, url, score, quality, findings) {
  if (quality !== 'good') {
    const desc = QUALITY_DESCRIPTIONS[quality] || 'The audit data was unreliable for unknown reasons.';
    return PROMPT_BLOCKED
      .replace('{company}', company).replace('{url}', url)
      .replace('{quality}', quality).replace('{description}', desc);
  }
  const sevOrder = { CRITICAL: 0, HIGH: 1, MED: 2, LOW: 3, GOOD: 4 };
  const sorted = [...findings].sort((a, b) => (sevOrder[a.sev] ?? 5) - (sevOrder[b.sev] ?? 5));
  const block = sorted.map(f => `  [${f.sev}] (${f.cat}, confidence: ${f.conf}) ${f.text}`).join('\n');
  return PROMPT_GOOD
    .replace('{company}', company).replace('{url}', url)
    .replace('{score}', score).replace('{findings_block}', block);
}

// ─── Main scorer ─────────────────────────────────────────────────────────────
// rows: array of {header: value} objects (from parseCSV)
export function scoreRows(rows) {
  return rows.map(row => {
    const company = (row['Company'] || '').trim();
    const url     = (row['URL']     || '').trim();
    const quality = classifyDataQuality(row);

    let findings, score, summary;
    if (quality === 'good') {
      findings = extractFindings(row);
      score    = scoreFromFindings(findings);
      summary  = findingsToSummary(findings);
    } else {
      findings = [];
      score    = -1;
      summary  = `[${quality.toUpperCase()}] Audit data unreliable`;
    }

    const prompt = buildPromptContext(company, url, score, quality, findings);
    return { company, url, quality, score, summary, prompt };
  });
}

// ─── Excel builder (requires exceljs) ────────────────────────────────────────
export async function buildExcel(results) {
  const ExcelJS = (await import('exceljs')).default;
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Audit Results');

  const headers = ['Company', 'URL', 'data_quality', 'score', 'findings_summary', 'prompt_context'];
  ws.addRow(headers);
  const hRow = ws.getRow(1);
  hRow.font = { bold: true, size: 11 };
  hRow.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9E1F2' } };
  hRow.alignment = { horizontal: 'center' };
  hRow.commit();

  for (const r of results) {
    const row = ws.addRow([r.company, r.url, r.quality, r.score === -1 ? '' : r.score, r.summary, r.prompt]);
    row.alignment = { vertical: 'top', wrapText: true };

    // Color-code score cell (col 4)
    const scoreCell = row.getCell(4);
    if (r.score === -1) {
      scoreCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF2F2F2' } };
      scoreCell.font = { color: { argb: 'FF808080' } };
    } else if (r.score >= 85) {
      scoreCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFC6EFCE' } };
      scoreCell.font = { color: { argb: 'FF006100' } };
    } else if (r.score >= 65) {
      scoreCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFEB9C' } };
      scoreCell.font = { color: { argb: 'FF9C5700' } };
    } else {
      scoreCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFC7CE' } };
      scoreCell.font = { color: { argb: 'FF9C0006' } };
    }
    row.commit();
  }

  ws.columns = [
    { width: 30 }, // Company
    { width: 40 }, // URL
    { width: 16 }, // data_quality
    { width: 8  }, // score
    { width: 80 }, // findings_summary
    { width: 100}, // prompt_context
  ];
  ws.views = [{ state: 'frozen', ySplit: 1 }];
  ws.autoFilter = { from: 'A1', to: `F${results.length + 1}` };

  return wb.xlsx.writeBuffer();
}
