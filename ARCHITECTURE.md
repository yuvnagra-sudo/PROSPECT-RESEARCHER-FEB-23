# Prospect Researcher v7 — Column Engine Architecture

## New Modules

### formula.mjs — Expression evaluator
Evaluates spreadsheet-like formulas with column references.

**Functions:**
- `evalFormula(formula, rowData)` → computed value
- `validateFormula(formula)` → null (valid) or error string
- `extractRefs(formula)` → array of referenced column IDs

**Supported:**
- References: `{column_name}`
- Math: `+`, `-`, `*`, `/`
- Comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Logic: `AND`, `OR`, `NOT`
- Functions: `IF`, `CONCAT`, `COALESCE`, `CONTAINS`, `LEN`, `UPPER`, `LOWER`, `TRIM`, `LEFT`, `RIGHT`, `REPLACE`, `ROUND`, `ABS`, `MIN`, `MAX`, `ISEMPTY`, `ISNOTEMPTY`, `TONUMBER`, `TOSTRING`

**Examples:**
```
IF({pagespeed} < 50 AND {has_booking} == "No", "High Priority", "Normal")
CONCAT({first_name}, " ", {last_name})
COALESCE({calendly}, {contact_form}, "No booking system")
IF(CONTAINS({platform}, "Wix"), "DIY builder", "Custom")
IF({copyright_year} < 2023, CONCAT("Outdated (", {copyright_year}, ")"), "Current")
```

### connectors.mjs — API connector registry
Built-in integrations and custom HTTP connector.

**Built-in connectors:**

| ID | Name | Key Required | Inputs | Outputs |
|---|---|---|---|---|
| `google_pagespeed` | Google PageSpeed | No (optional) | url | performance, seo, accessibility, best_practices, fcp, lcp, cls, tbt |
| `website_audit` | Website Audit | No | url | 30+ fields: performance, response_ms, https_works, platform, copyright_year, contact methods, top 3 issues, etc. |
| `http_check` | HTTP Check | No | url | status_code, response_ms, final_url, server, reachable |
| `dns_mx` | DNS MX Lookup | No | domain | email_provider, mx_record, has_spf |
| `custom_http` | Custom HTTP API | Configurable | Configurable | Configurable |

**Custom HTTP connector config:**
```json
{
  "url": "https://api.example.com/lookup?domain={domain}",
  "method": "GET",
  "authType": "bearer",
  "headers": { "Accept": "application/json" },
  "outputMapping": {
    "company_size": "data.employees",
    "industry": "data.industry.name",
    "revenue": "data.financials.revenue"
  }
}
```

### engine.mjs — Execution engine
Resolves column dependencies and executes in waves.

**Functions:**
- `buildExecutionPlan(columns)` → array of waves (each wave = array of column IDs)
- `executeRow(rowData, columns, plan, context)` → { data, costs, errors }
- `sectionsToColumns(sections, csvHeaders, colMap)` → backwards-compatible conversion

## Column Definition Schema

```javascript
{
  id: 'col_id',           // unique, used as key in rowData
  name: 'Display Name',   // shown in table header and CSV export
  type: 'input' | 'api' | 'llm' | 'formula' | 'conditional',
  dependsOn: [],           // explicit dependencies (auto-detected from formulas/mappings)

  // For type: 'api'
  apiConfig: {
    connector: 'google_pagespeed',     // registered connector ID
    inputMapping: { url: '{website}' }, // interpolate column refs
    outputField: 'performance',         // extract specific field from connector output
    keyName: 'PAGESPEED_API_KEY',      // which user key to use
    customConfig: {},                   // for custom_http connector
  },

  // For type: 'llm'
  llmConfig: {
    group: 'research',       // columns in same group = ONE LLM call (cost saving)
    provider: null,          // null = use job default
    temperature: 0,          // 0 for data, 0.4-0.6 for copy
    webSearch: true,
    instruction: '',         // per-column research instruction
    systemPrompt: '',        // override system prompt for this group
    role: '',                // AI role (e.g., "B2B sales researcher")
  },

  // For type: 'formula'
  formula: 'IF({pagespeed} < 50, "Bad", "OK")',

  // For type: 'conditional'
  condition: '{website} != ""',
  wrappedColumnId: 'some_col',
}
```

## LLM Grouping for Cost Reduction

Columns with the same `llmConfig.group` value execute as a SINGLE LLM call.
The engine auto-generates a prompt asking for all grouped columns at once,
parses the JSON response, and distributes values to individual columns.

**Example — 5 columns, 2 LLM calls:**
```
Group "research" (temperature 0, web search ON):
  - Company Snapshot
  - Pain Points  
  - Recent Triggers
→ ONE call, returns JSON with 3 keys

Group "copy" (temperature 0.5, web search OFF):
  - Outreach Hook
→ ONE call, consumes research output as context

Free columns (no LLM call):
  - PageSpeed Score (API)
  - Priority (formula)
```

**Cost comparison:**
- Old way: 1 LLM call for all 5 sections = can't control temperature per section
- New way: 2 LLM calls (research @ temp 0, copy @ temp 0.5) = better quality, similar cost
- Clay way: 5 separate LLM calls = 5x cost

## Execution Flow

```
CSV Upload → Parse → Map to Input Columns
                ↓
        Build Execution Plan
                ↓
    ┌─── Wave 0: Input columns (from CSV)
    │
    ├─── Wave 1: API columns (pagespeed, audit, dns)
    │            + LLM group "research" (in parallel)
    │
    ├─── Wave 2: Formula columns (depend on wave 1)
    │            + LLM group "copy" (depends on wave 1)
    │
    └─── Wave 3: Final formulas (depend on wave 2)
                ↓
         Store results → Emit SSE → Export CSV
```

## How Templates Map to Columns

Old template = prompt + sections.
New template = column set.

**Example: "Website Services Prospecting" template becomes:**

```javascript
{
  name: 'Website Services Prospecting',
  columns: [
    // Input columns (from CSV)
    { id: 'company', name: 'Company', type: 'input' },
    { id: 'website', name: 'Website', type: 'input' },

    // API columns (free, no LLM)
    { id: 'audit', name: 'Full Audit', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'summary' }},
    { id: 'pagespeed', name: 'PageSpeed Score', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'performance' }},
    { id: 'platform', name: 'Platform', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'platform' }},
    { id: 'copyright_year', name: 'Copyright Year', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'copyright_year' }},
    { id: 'has_booking', name: 'Has Booking', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'has_booking_widget' }},
    { id: 'has_contact', name: 'Has Contact Form', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'has_contact_form' }},
    { id: 'top_issue', name: 'Top Issue', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'top_issue' }},
    { id: 'issue_2', name: 'Issue 2', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'issue_2' }},
    { id: 'issue_3', name: 'Issue 3', type: 'api',
      apiConfig: { connector: 'website_audit', inputMapping: { url: '{website}' }, outputField: 'issue_3' }},
    { id: 'email_provider', name: 'Email Provider', type: 'api',
      apiConfig: { connector: 'dns_mx', inputMapping: { domain: '{website}' }, outputField: 'email_provider' }},

    // LLM columns — grouped for cost efficiency
    { id: 'snapshot', name: 'Company Snapshot', type: 'llm',
      llmConfig: { group: 'research', temperature: 0, webSearch: true,
        instruction: 'What they do, who they serve, approximate size' }},
    { id: 'pain_points', name: 'Pain Points', type: 'llm',
      llmConfig: { group: 'research', temperature: 0, webSearch: true,
        instruction: '2-3 specific operational challenges. Be concrete.' }},

    // Formula columns (free)
    { id: 'priority', name: 'Priority', type: 'formula',
      formula: 'IF({pagespeed} < 50 AND {has_booking} == "No", "Hot", IF({pagespeed} < 70, "Warm", "Low"))' },

    // Copy column — separate LLM group, higher temperature, depends on research
    { id: 'outreach_hook', name: 'Outreach Hook', type: 'llm',
      dependsOn: ['snapshot', 'pain_points', 'pagespeed', 'top_issue'],
      llmConfig: {
        group: 'copy', temperature: 0.5, webSearch: false,
        instruction: 'Cold email opening line. Formula: name specific pain/metric → why it matters → quantify negative effect → tie to dollar cost. 1-2 sentences. Sound human.',
        systemPrompt: 'You are a direct-response copywriter. Write cold email opening lines that reference specific data about the prospect. Use this formula: 1) Name the pain point or metric 2) State why it matters 3) Quantify the negative effect 4) Tie to financial cost. Be specific. No fluff. No generic openers.',
      }},
  ]
}
```

**Result: 17 columns. Only 2 LLM calls. 10 columns from free API data. 1 formula column.**

## Integration with server.mjs

The new engine modules are imported into server.mjs. The existing worker loop
delegates to `executeRow()` instead of directly calling `callLLM()`. The column
definitions are stored in the job's `sections_json` field (extended to hold the
full column schema).

Backwards compatibility: `sectionsToColumns()` converts old-style section
definitions to the new column format, so existing jobs continue to work.

New API endpoints needed:
- `GET /api/connectors` — list available connectors
- `POST /api/validate-formula` — validate a formula expression
- `POST /api/columns/preview` — preview execution plan for a column set

## UI Integration Points

The UI needs a column editor (Step 2 of the wizard) that lets users:
1. Add columns of each type
2. Configure API connectors (select connector, map inputs, pick output field)
3. Group LLM columns (drag into groups)
4. Write formulas with autocomplete for column references
5. Set conditions for conditional columns
6. Preview the execution plan (show wave diagram)

The table view shows columns filling in real-time as each wave completes —
API columns fill first, then LLM research, then formulas, then copy.
