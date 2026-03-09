// connectors.mjs — API connector registry
// Each connector: async (params, apiKey?) → { key: value, ... }

import { auditWebsite } from './audit.mjs';

const TIMEOUT = 15000;

// ─── Built-in Connectors ───────────────────────────────────────────────────

async function googlePagespeed(params, apiKey) {
  const url = params.url;
  if (!url) return { error: 'No URL provided' };
  const psUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=mobile&category=performance&category=seo&category=accessibility&category=best-practices${apiKey ? '&key=' + apiKey : ''}`;
  const res = await fetch(psUrl, { signal: AbortSignal.timeout(55000) });
  if (!res.ok) return { error: `PageSpeed API ${res.status}` };
  const data = await res.json();
  const cats = data.lighthouseResult?.categories || {};
  const audits = data.lighthouseResult?.audits || {};
  const score = (cat) => cat?.score != null ? Math.round(cat.score * 100) : null;
  return {
    performance: score(cats['performance']),
    seo: score(cats['seo']),
    accessibility: score(cats['accessibility']),
    best_practices: score(cats['best-practices']),
    fcp: audits['first-contentful-paint']?.displayValue || null,
    lcp: audits['largest-contentful-paint']?.displayValue || null,
    cls: audits['cumulative-layout-shift']?.displayValue || null,
    tbt: audits['total-blocking-time']?.displayValue || null,
  };
}

async function websiteAudit(params) {
  const url = params.url;
  if (!url) return { error: 'No URL provided' };
  const result = await auditWebsite(url);
  const m = result.metrics || {};
  const issues = result.issues || [];
  const cm = m.contactMethods || {};
  return {
    performance: m.performance,
    seo_score: m.seo,
    accessibility: m.accessibility,
    response_ms: m.responseMs,
    https_works: m.httpsWorks ? 'Yes' : 'No',
    http_redirects: m.httpRedirects ? 'Yes' : 'No',
    title: m.title || '',
    title_length: m.titleLength,
    meta_desc_length: m.metaDescLength,
    has_meta_desc: m.metaDesc ? 'Yes' : 'No',
    h1_count: m.h1Count,
    has_viewport: m.viewport ? 'Yes' : 'No',
    has_canonical: m.hasCanonical ? 'Yes' : 'No',
    is_noindex: m.isNoindex ? 'Yes' : 'No',
    has_json_ld: m.hasJsonLD ? 'Yes' : 'No',
    has_favicon: m.hasFavicon ? 'Yes' : 'No',
    has_analytics: m.hasAnalytics ? 'Yes' : 'No',
    has_sitemap: m.hasSitemap ? 'Yes' : 'No',
    platform: m.platform || '',
    copyright_year: m.copyrightYear || '',
    has_contact_form: cm.hasContactForm ? 'Yes' : 'No',
    has_calendly: cm.hasCalendly ? 'Yes' : 'No',
    has_booking_widget: cm.hasBookingWidget ? 'Yes' : 'No',
    has_click_to_call: cm.hasClickToCall ? 'Yes' : 'No',
    has_email_link: cm.hasEmail ? 'Yes' : 'No',
    doc_size_kb: m.docSizeKB,
    issue_count: issues.length,
    top_issue: issues[0] ? `[${issues[0].severity.toUpperCase()}] ${issues[0].title}` : '',
    top_issue_detail: issues[0]?.detail || '',
    issue_2: issues[1] ? `[${issues[1].severity.toUpperCase()}] ${issues[1].title}` : '',
    issue_2_detail: issues[1]?.detail || '',
    issue_3: issues[2] ? `[${issues[2].severity.toUpperCase()}] ${issues[2].title}` : '',
    issue_3_detail: issues[2]?.detail || '',
    summary: result.summary || '',
  };
}

async function httpCheck(params) {
  const url = params.url;
  if (!url) return { error: 'No URL provided' };
  const normalized = /^https?:\/\//i.test(url) ? url : 'https://' + url;
  try {
    const t0 = Date.now();
    const res = await fetch(normalized, {
      signal: AbortSignal.timeout(TIMEOUT),
      redirect: 'follow',
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; ProspectResearcher/2.0)' },
    });
    const ms = Date.now() - t0;
    return {
      status_code: res.status,
      response_ms: ms,
      final_url: res.url,
      server: res.headers.get('server') || '',
      reachable: 'Yes',
    };
  } catch (e) {
    return { status_code: 0, response_ms: 0, final_url: '', server: '', reachable: 'No', error: e.message };
  }
}

async function dnsMx(params) {
  const { resolve } = await import('dns/promises');
  const domain = params.domain;
  if (!domain) return { error: 'No domain provided' };
  // Extract domain from URL if needed
  let d = domain;
  try { d = new URL(d.startsWith('http') ? d : 'https://' + d).hostname; } catch {}
  try {
    const mx = await resolve(d, 'MX');
    const top = mx.sort((a, b) => a.priority - b.priority)[0]?.exchange || '';
    let provider = 'Unknown';
    if (/google|gmail|googlemail/i.test(top)) provider = 'Google Workspace';
    else if (/outlook|microsoft|hotmail/i.test(top)) provider = 'Microsoft 365';
    else if (/zoho/i.test(top)) provider = 'Zoho Mail';
    else if (/protonmail/i.test(top)) provider = 'ProtonMail';
    else if (/mimecast/i.test(top)) provider = 'Mimecast';
    else if (/barracuda/i.test(top)) provider = 'Barracuda';
    else if (top) provider = top.split('.').slice(-2).join('.');
    // Check SPF
    let hasSPF = false;
    try { const txt = await resolve(d, 'TXT'); hasSPF = txt.some(r => r.join('').includes('v=spf1')); } catch {}
    return { email_provider: provider, mx_record: top, has_spf: hasSPF ? 'Yes' : 'No' };
  } catch (e) {
    return { email_provider: '', mx_record: '', has_spf: '', error: e.message };
  }
}

// ─── Custom HTTP Connector ─────────────────────────────────────────────────
// User defines: url template, method, headers, auth type, response extraction
async function customHttp(params, apiKey, config) {
  if (!config?.url) return { error: 'No URL template in connector config' };
  // Interpolate {param} references in URL
  let url = config.url;
  for (const [k, v] of Object.entries(params)) {
    url = url.replace(new RegExp(`\\{${k}\\}`, 'g'), encodeURIComponent(v || ''));
  }
  const headers = { ...(config.headers || {}) };
  // Auth
  if (config.authType === 'bearer' && apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  else if (config.authType === 'header' && config.authHeader && apiKey) headers[config.authHeader] = apiKey;
  else if (config.authType === 'query' && config.authParam && apiKey) {
    const sep = url.includes('?') ? '&' : '?';
    url += `${sep}${config.authParam}=${encodeURIComponent(apiKey)}`;
  }
  try {
    const res = await fetch(url, {
      method: config.method || 'GET',
      headers,
      signal: AbortSignal.timeout(config.timeout || TIMEOUT),
      body: config.method === 'POST' && config.body ? JSON.stringify(config.body) : undefined,
    });
    if (!res.ok) return { error: `HTTP ${res.status}` };
    const data = await res.json();
    // Extract fields using dot-path or return full response
    if (config.outputMapping && typeof config.outputMapping === 'object') {
      const result = {};
      for (const [outKey, jsonPath] of Object.entries(config.outputMapping)) {
        result[outKey] = getNestedValue(data, jsonPath);
      }
      return result;
    }
    return data;
  } catch (e) {
    return { error: e.message };
  }
}

function getNestedValue(obj, path) {
  if (!path || !obj) return null;
  const parts = path.split('.');
  let current = obj;
  for (const part of parts) {
    if (current == null) return null;
    // Handle array index: "items[0]"
    const m = part.match(/^(\w+)\[(\d+)\]$/);
    if (m) {
      current = current[m[1]];
      if (Array.isArray(current)) current = current[parseInt(m[2])];
      else return null;
    } else {
      current = current[part];
    }
  }
  if (typeof current === 'object') return JSON.stringify(current);
  return current;
}

// ─── Connector Registry ────────────────────────────────────────────────────

const BUILTIN_CONNECTORS = {
  google_pagespeed: {
    name: 'Google PageSpeed',
    description: 'Mobile performance, SEO, accessibility scores',
    keyName: 'PAGESPEED_API_KEY',
    keyRequired: false,
    inputFields: ['url'],
    outputFields: ['performance', 'seo', 'accessibility', 'best_practices', 'fcp', 'lcp', 'cls', 'tbt'],
    fn: googlePagespeed,
  },
  website_audit: {
    name: 'Website Audit',
    description: 'Full technical audit — SEO, security, performance, issues',
    keyRequired: false,
    inputFields: ['url'],
    outputFields: [
      'performance', 'seo_score', 'accessibility', 'response_ms',
      'https_works', 'http_redirects', 'title', 'title_length',
      'has_meta_desc', 'meta_desc_length', 'h1_count', 'has_viewport',
      'has_canonical', 'is_noindex', 'has_json_ld', 'has_favicon',
      'has_analytics', 'has_sitemap', 'platform', 'copyright_year',
      'has_contact_form', 'has_calendly', 'has_booking_widget',
      'has_click_to_call', 'has_email_link', 'doc_size_kb',
      'issue_count', 'top_issue', 'top_issue_detail',
      'issue_2', 'issue_2_detail', 'issue_3', 'issue_3_detail',
      'summary',
    ],
    fn: websiteAudit,
  },
  http_check: {
    name: 'HTTP Check',
    description: 'Basic reachability, response time, status code',
    keyRequired: false,
    inputFields: ['url'],
    outputFields: ['status_code', 'response_ms', 'final_url', 'server', 'reachable'],
    fn: httpCheck,
  },
  dns_mx: {
    name: 'DNS MX Lookup',
    description: 'Email provider detection from domain',
    keyRequired: false,
    inputFields: ['domain'],
    outputFields: ['email_provider', 'mx_record', 'has_spf'],
    fn: dnsMx,
  },
  custom_http: {
    name: 'Custom HTTP API',
    description: 'Call any REST API with custom URL, headers, and auth',
    keyRequired: false,
    inputFields: [],
    outputFields: [],
    fn: customHttp,
    isCustom: true,
  },
};

export function getConnector(id) {
  return BUILTIN_CONNECTORS[id] || null;
}

export function listConnectors() {
  const result = {};
  for (const [id, c] of Object.entries(BUILTIN_CONNECTORS)) {
    result[id] = {
      name: c.name,
      description: c.description,
      keyName: c.keyName,
      keyRequired: c.keyRequired,
      inputFields: c.inputFields,
      outputFields: c.outputFields,
      isCustom: !!c.isCustom,
    };
  }
  return result;
}

// Execute a connector with params and optional API key
export async function executeConnector(connectorId, params, apiKey, customConfig) {
  const connector = BUILTIN_CONNECTORS[connectorId];
  if (!connector) throw new Error(`Unknown connector: ${connectorId}`);
  if (connector.isCustom) return connector.fn(params, apiKey, customConfig);
  return connector.fn(params, apiKey);
}
