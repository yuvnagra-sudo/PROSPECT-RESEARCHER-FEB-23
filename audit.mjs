// audit.mjs — Website audit pipeline for Prospect Researcher
// Uses only Node 18+ built-ins (fetch, AbortSignal.timeout). No extra deps.

const TIMEOUT_HTTP = 18000; // increased from 12s — handles slower sites
const TIMEOUT_PAGESPEED = 30000;
const PAGESPEED_API_KEY = process.env.PAGESPEED_API_KEY || '';

// ─── URL helpers ──────────────────────────────────────────────────────────────
function normalizeUrl(raw) {
  let url = (raw || '').trim();
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  return url;
}
function getOrigin(url) {
  try { return new URL(url).origin; } catch { return ''; }
}

// ─── HTML entity decoder ─────────────────────────────────────────────────────
function decodeHtmlEntities(str) {
  if (!str) return str;
  return str
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

// ─── HTML parsers (regex only, no cheerio) ───────────────────────────────────
function parseTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? decodeHtmlEntities(m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim()) : null;
}
function parseMetaDesc(html) {
  const m = html.match(/<meta\s+(?:[^>]*?\s+)?name=["']description["'][^>]*content=["']([^"']*)/i)
    || html.match(/<meta\s+(?:[^>]*?\s+)?content=["']([^"']*?)["'][^>]*name=["']description["']/i);
  return m ? decodeHtmlEntities(m[1].trim()) : null;
}
function parseH1s(html) {
  return [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)]
    .map(m => decodeHtmlEntities(m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim()));
}
function parseViewport(html) {
  return /<meta\s+(?:[^>]*?\s+)?name=["']viewport["'][^>]*>/i.test(html);
}
function parseOGTags(html) {
  const result = {};
  for (const prop of ['og:title', 'og:description', 'og:image']) {
    const pat = prop.replace(/:/g, '\\:');
    const m = html.match(new RegExp('<meta\\s+(?:[^>]*?\\s+)?property=["\']' + pat + '["\'][^>]*content=["\']([^"\']*)', 'i'))
      || html.match(new RegExp('<meta\\s+(?:[^>]*?\\s+)?content=["\']([^"\']*?)["\'][^>]*property=["\']' + pat + '["\']', 'i'));
    result[prop] = m ? m[1].trim() : null;
  }
  return result;
}
function parseJsonLD(html) {
  // Check JSON-LD, Microdata (itemscope/itemtype), and RDFa — all accepted by Google
  return /<script[^>]+type=["']application\/ld\+json["'][^>]*>/i.test(html)
    || /\bitemscope\b[^>]*\bitemtype\s*=/i.test(html)
    || /\bvocab\s*=\s*["']https?:\/\/schema\.org/i.test(html);
}
function parseImageAltCoverage(html) {
  const allImgs = [...html.matchAll(/<img\b[^>]*>/gi)];
  if (!allImgs.length) return { total: 0, withAlt: 0, coverage: 1 };
  // alt="" is correct for decorative images (WCAG) — only flag truly missing alt attributes
  const withAlt = allImgs.filter(m => /\balt\s*=/i.test(m[0])).length;
  return { total: allImgs.length, withAlt, coverage: withAlt / allImgs.length };
}
function parseCanonical(html) {
  return /<link\s+(?:[^>]*?\s+)?rel=["']canonical["'][^>]*>/i.test(html);
}
function parseRobotsNoindex(html) {
  return /<meta\s+(?:[^>]*?\s+)?name=["']robots["'][^>]*content=["'][^"']*noindex/i.test(html);
}
function parseMixedContent(html, pageUrl) {
  if (!pageUrl.startsWith('https')) return [];
  // Strip scripts, styles, comments, and JSON-LD blocks — http:// in JS/CSS/data is not mixed content
  const stripped = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '');
  const refs = [];
  // Only match actual resource-loading HTML attributes on tags that matter
  const pat = /<(?:img|link|script|source|video|audio|iframe)\b[^>]*\s(?:src|href)=["'](http:\/\/[^"'\s>]{4,})/gi;
  let m;
  while ((m = pat.exec(stripped)) !== null) {
    if (!m[1].startsWith('http://localhost')) refs.push(m[1].slice(0, 100));
  }
  return [...new Set(refs)].slice(0, 5);
}
function parseAnalytics(html) {
  return {
    hasGA: /googletagmanager\.com|google-analytics\.com|gtag\(|_gaq\.push|ga\(['"]create/i.test(html),
    hasGTM: /GTM-[A-Z0-9]+|googletagmanager\.com\/gtm\.js/i.test(html),
    hasOther: /segment\.com\/analytics|heap\.io|mixpanel|hotjar|plausible\.io|fathom\.io|umami\./i.test(html),
  };
}
function parseFavicon(html) {
  return /<link[^>]+rel=["'](?:shortcut )?icon["'][^>]*>/i.test(html)
    || /<link[^>]+rel=["'][^"']*apple-touch-icon[^"']*["'][^>]*>/i.test(html);
}
function parsePlatform(html) {
  if (/wp-content\/|wp-includes\//i.test(html)) return 'WordPress';
  if (/cdn\.shopify\.com/i.test(html)) return 'Shopify';
  if (/static1\.squarespace\.com|squarespace\.com\/universal|sqsp\.net/i.test(html)) return 'Squarespace';
  if (/static\.parastorage\.com|wixstatic\.com|wixsite\.com/i.test(html)) return 'Wix';
  if (/assets\.website-files\.com|webflow\.io/i.test(html)) return 'Webflow';
  if (/weebly\.com/i.test(html)) return 'Weebly';
  if (/godaddy\.com|secureserver\.net/i.test(html)) return 'GoDaddy';
  if (/framer\.com\/m\//i.test(html)) return 'Framer';
  if (/hs-scripts\.com|hubspot\.com\/hs-fs/i.test(html)) return 'HubSpot';
  const gen = html.match(/<meta\s+(?:[^>]*?\s+)?name=["']generator["'][^>]*content=["']([^"']+)/i)
    || html.match(/<meta\s+(?:[^>]*?\s+)?content=["']([^"']+?)["'][^>]*name=["']generator["']/i);
  if (gen) {
    const g = gen[1];
    if (/wordpress/i.test(g)) return 'WordPress';
    if (/squarespace/i.test(g)) return 'Squarespace';
    if (/wix/i.test(g)) return 'Wix';
    if (/webflow/i.test(g)) return 'Webflow';
    if (/ghost/i.test(g)) return 'Ghost';
    if (/joomla/i.test(g)) return 'Joomla';
    if (/drupal/i.test(g)) return 'Drupal';
  }
  return 'Unknown';
}
function parseCopyrightYear(html) {
  const m = html.match(/(?:©|&copy;|&#169;|copyright)\s*(?:&nbsp;|\s)*((?:19|20)\d{2})/i);
  return m ? m[1] : '';
}
function parseContactMethods(html) {
  const hasContactForm = /<form\b[^>]*>/i.test(html);
  const hasScheduling = /calendly\.com|acuityscheduling\.com|cal\.com|oncehub\.com|tidycal\.com|hubspot\.com\/meetings/i.test(html)
    || /<a\b[^>]*href=["'][^"']*(?:schedule|\/book)[^"']*["']/i.test(html);
  const hasCalendly = /calendly\.com/i.test(html);
  const hasBookingWidget = hasScheduling ||
    /simplybook\.me|booksy\.com|setmore\.com/i.test(html);
  const hasChatWidget = /tawk\.to|intercom\.io|drift\.com|crisp\.chat|tidio\.com|livechat|zendesk\.com|freshdesk\.com|chatwoot/i.test(html);
  const hasClientPortal = /taxdome\.com|canopy\.com|liscio\.me|smartvault\.com|sharefile\.com|citrix/i.test(html)
    || /<a\b[^>]*href=["'][^"']*(?:portal|client-login|secure-login)[^"']*["']/i.test(html);
  const hasOnlinePayment = /stripe\.com|paypal\.com|square\.com|helcim\.com|cpacharge\.com|affinipay\.com/i.test(html)
    || /<a\b[^>]*href=["'][^"']*(?:\/pay(?:ment)?|make-a-payment)[^"']*["']/i.test(html);
  const hasCalculatorOrTool = /(?:id|class|href)=["'][^"']*(?:calculator|estimator|quiz|assessment)[^"']*["']/i.test(html);
  const hasEmailCapture = /mailchimp\.com|convertkit\.com|constantcontact\.com/i.test(html)
    || /(?:class|href)=["'][^"']*(?:newsletter|subscribe|download)[^"']*["']/i.test(html);
  const hasClickToCall = /href=["']tel:/i.test(html);
  const hasEmail = /href=["']mailto:/i.test(html);
  return { hasContactForm, hasScheduling, hasCalendly, hasBookingWidget, hasChatWidget, hasClientPortal, hasOnlinePayment, hasCalculatorOrTool, hasEmailCapture, hasClickToCall, hasEmail };
}
function parsePageTextSnippet(html) {
  const text = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ').trim();
  return text.slice(0, 500);
}

const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const FETCH_HEADERS = {
  'user-agent': BROWSER_UA,
  'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.9',
};

// ─── JS-shell detection ───────────────────────────────────────────────────────
// Returns true when fetch() got a 200 but the body is essentially empty JS scaffolding.
// Common with GoDaddy Website Builder, CPA Site Solutions (ASP.NET), Wix headless, etc.
function isJsShell(status, html) {
  if (status !== 200 || !html) return false;
  if (html.length < 1500) return true; // anything under 1.5KB on a 200 is suspicious
  // Empty body or single empty root div (React/Vue/Angular apps)
  if (/<body[^>]*>\s*(<div[^>]*>\s*<\/div>\s*)*\s*<\/body>/i.test(html)) return true;
  // Extract visible text — if there's almost none, it's a shell
  const text = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ').trim();
  return text.length < 120 && html.length > 800;
}

// ─── Cloudflare bypass via Playwright ────────────────────────────────────────
function isCloudflareChallenge(status, html, serverHeader) {
  if (serverHeader === 'cloudflare' && (status === 403 || status === 503)) return true;
  if (!html) return false;
  if (html.includes('cf-browser-verification') || html.includes('_cf_chl_opt')) return true;
  if (html.includes('Just a moment') && html.includes('Enable JavaScript and cookies')) return true;
  if (html.includes('cloudflare-static/rocket-loader') && html.includes('Just a moment')) return true;
  return false;
}

// Semaphore: max 2 concurrent Playwright CF fetches (~300MB each = ~600MB peak)
let _cfSlots = 2;
const _cfQueue = [];
const _cfAcquire = () => new Promise(res => { if (_cfSlots > 0) { _cfSlots--; res(); } else _cfQueue.push(res); });
const _cfRelease = () => { if (_cfQueue.length > 0) _cfQueue.shift()(); else _cfSlots++; };

async function fetchHTMLWithPlaywright(url, reason = 'CF') {
  const { chromium } = await import('playwright');
  await _cfAcquire();
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const ctx = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    const page = await ctx.newPage();
    let finalStatus = 200;
    page.on('response', r => { if (r.url() === url || !finalStatus) finalStatus = r.status(); });
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
    // Wait for meaningful content: title or body text visible, up to 10s
    try {
      await page.waitForFunction(
        () => (document.title?.trim().length > 5 || document.body?.innerText?.trim().length > 100)
          && !document.body?.innerText?.includes('Just a moment'),
        { timeout: 10000, polling: 500 }
      );
    } catch {} // timeout is fine — grab whatever loaded
    const html = await page.content();
    const finalUrl = page.url();
    return { ok: true, html, finalUrl, status: finalStatus };
  } catch (e) {
    console.error(`[audit] Playwright (${reason}) failed for ${url}: ${e.message}`);
    return { ok: false, html: '', finalUrl: url, status: 0 };
  } finally {
    if (browser) try { await browser.close(); } catch {}
    _cfRelease();
  }
}

// ─── Check: HTTP + HTML ───────────────────────────────────────────────────────
async function checkHTTP(url) {
  const t0 = Date.now();
  let res;
  // Try https first, fall back to http:// if connection refused or SSL error
  const tryFetch = async (u) => fetch(u, {
    signal: AbortSignal.timeout(TIMEOUT_HTTP),
    redirect: 'follow',
    headers: FETCH_HEADERS,
  });
  try {
    res = await tryFetch(url);
  } catch (e) {
    // If https failed, try http://
    if (url.startsWith('https://')) {
      try {
        res = await tryFetch(url.replace('https://', 'http://'));
      } catch (e2) {
        return { ok: false, error: e2.message };
      }
    } else {
      return { ok: false, error: e.message };
    }
  }
  const responseMs = Date.now() - t0;
  const hdrs = {};
  for (const [k, v] of res.headers) hdrs[k.toLowerCase()] = v;

  let html = '';
  let finalUrl = res.url;
  let httpStatus = res.status;
  try { html = await res.text(); } catch {}

  // Cloudflare JS challenge or JS-rendered shell — retry with headless Chrome
  let jsRendered = false;
  if (isCloudflareChallenge(httpStatus, html, hdrs['server'])) {
    console.log(`[audit] Cloudflare challenge for ${url} — retrying with Playwright`);
    const pw = await fetchHTMLWithPlaywright(url, 'CF');
    if (pw.ok && pw.html) {
      html = pw.html;
      finalUrl = pw.finalUrl || finalUrl;
      jsRendered = true;
      // Keep original httpStatus so CSV shows 403/503
    }
  } else if (isJsShell(httpStatus, html)) {
    console.log(`[audit] JS-rendered shell detected for ${url} — fetching with Playwright`);
    const pw = await fetchHTMLWithPlaywright(url, 'JS');
    if (pw.ok && pw.html && pw.html.length > html.length) {
      html = pw.html;
      finalUrl = pw.finalUrl || finalUrl;
      jsRendered = true;
    }
  }

  const title = parseTitle(html);
  const metaDesc = parseMetaDesc(html);
  const h1s = parseH1s(html);
  const altCoverage = parseImageAltCoverage(html);
  const analytics = parseAnalytics(html);
  const ogTags = parseOGTags(html);
  const mixedContent = parseMixedContent(html, url);
  const platform = parsePlatform(html);
  const copyrightYear = parseCopyrightYear(html);
  const contactMethods = parseContactMethods(html);
  const pageTextSnippet = parsePageTextSnippet(html);

  return {
    ok: true,
    status: httpStatus,
    finalUrl,
    responseMs,
    jsRendered,
    headers: {
      hsts: hdrs['strict-transport-security'] || null,
      csp: hdrs['content-security-policy'] || null,
      xContentType: hdrs['x-content-type-options'] || null,
      xFrame: hdrs['x-frame-options'] || null,
      referrerPolicy: hdrs['referrer-policy'] || null,
      server: hdrs['server'] || null,
    },
    html: {
      title,
      titleLength: title ? title.length : 0,
      metaDesc,
      metaDescLength: metaDesc ? metaDesc.length : 0,
      h1s,
      h1Count: h1s.length,
      viewport: parseViewport(html),
      ogTags,
      hasJsonLD: parseJsonLD(html),
      altCoverage,
      hasCanonical: parseCanonical(html),
      isNoindex: parseRobotsNoindex(html),
      mixedContent,
      analytics,
      hasFavicon: parseFavicon(html),
      docSizeKB: Math.round(html.length / 1024),
      platform,
      copyrightYear,
      contactMethods,
      pageTextSnippet,
    },
  };
}

// ─── Check: PageSpeed Insights — mobile + desktop in parallel ────────────────
// With an API key: 400 req/100s quota — safe to run 5 concurrent audits
// Without a key:  25 req/100s quota — use concurrency=2 max
const PAGESPEED_BACKOFF_MS = 15000; // pause on 429 before retrying

async function fetchPageSpeedStrategy(url, strategy, apiKey) {
  const key = apiKey || PAGESPEED_API_KEY;
  const psUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=${strategy}&category=performance&category=seo&category=accessibility&category=best-practices${key ? '&key=' + key : ''}`;
  const TIMEOUTS = [40000, 55000, 70000];
  let lastError = '';
  for (let attempt = 0; attempt < TIMEOUTS.length; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, 3000 * attempt));
    let res;
    try {
      res = await fetch(psUrl, { signal: AbortSignal.timeout(TIMEOUTS[attempt]) });
    } catch (e) {
      lastError = e.name === 'TimeoutError' ? `Timed out after ${TIMEOUTS[attempt]/1000}s` : e.message;
      continue;
    }
    if (res.status === 429) {
      // Rate limited — back off and retry once
      if (attempt < TIMEOUTS.length - 1) {
        await new Promise(r => setTimeout(r, PAGESPEED_BACKOFF_MS));
        continue;
      }
      return { ok: false, error: 'PageSpeed API rate limited (429)', skipped: true };
    }
    if (!res.ok) { lastError = `PageSpeed API HTTP ${res.status}`; continue; }
    let data;
    try { data = await res.json(); } catch { lastError = 'Invalid JSON from PageSpeed API'; continue; }
    const lhr = data.lighthouseResult;
    if (!lhr) { lastError = 'PageSpeed response missing lighthouseResult'; continue; }
    return { ok: true, lhr, crux: data.loadingExperience || null, originCrux: data.originLoadingExperience || null, attempts: attempt + 1 };
  }
  return { ok: false, error: lastError || `PageSpeed ${strategy} unavailable after 3 attempts`, skipped: false };
}

// Parse CrUX field data from PSI API (loadingExperience or originLoadingExperience)
function parseCrux(cruxData) {
  if (!cruxData || !cruxData.metrics) return null;
  const m = cruxData.metrics;
  const cat = k => {
    const c = m[k]?.category;
    if (c === 'FAST') return 'GOOD';
    if (c === 'SLOW') return 'POOR';
    if (c === 'AVERAGE') return 'NEEDS IMPROVEMENT';
    return null;
  };
  const p75 = k => m[k]?.percentiles?.p75 ?? null;
  return {
    available: true,
    overallCategory: cruxData.overall_category || null,
    fcpMs: p75('FIRST_CONTENTFUL_PAINT_MS'),
    fcpRating: cat('FIRST_CONTENTFUL_PAINT_MS'),
    lcpMs: p75('LARGEST_CONTENTFUL_PAINT_MS'),
    lcpRating: cat('LARGEST_CONTENTFUL_PAINT_MS'),
    clsScore: p75('CUMULATIVE_LAYOUT_SHIFT_SCORE'),
    clsRating: cat('CUMULATIVE_LAYOUT_SHIFT_SCORE'),
    inpMs: p75('INTERACTION_TO_NEXT_PAINT'),
    inpRating: cat('INTERACTION_TO_NEXT_PAINT'),
    ttfbMs: p75('EXPERIMENTAL_TIME_TO_FIRST_BYTE'),
    ttfbRating: cat('EXPERIMENTAL_TIME_TO_FIRST_BYTE'),
    fidMs: p75('FIRST_INPUT_DELAY_MS'),
    fidRating: cat('FIRST_INPUT_DELAY_MS'),
  };
}

// Extract top resource items from a Lighthouse audit as "url | wastedKB" strings (semicolon-joined)
function extractResourceItems(audits, id, { limit = 10, byteField = 'wastedBytes', msField = null } = {}) {
  const items = audits[id]?.details?.items;
  if (!items?.length) return null;
  return items.slice(0, limit).map(item => {
    const url = item.url || item.label || item.node?.snippet || '';
    if (msField && item[msField] != null) return url ? `${url} (${Math.round(item[msField])}ms)` : `${Math.round(item[msField])}ms`;
    if (byteField && item[byteField] != null) return url ? `${url} (${Math.round(item[byteField] / 1024)}KB)` : `${Math.round(item[byteField] / 1024)}KB`;
    return url;
  }).filter(Boolean).join('; ') || null;
}

function parseLHR(lhr) {
  const cats = lhr.categories || {};
  const audits = lhr.audits || {};
  const score = (cat) => (cat?.score !== null && cat?.score !== undefined) ? Math.round(cat.score * 100) : null;
  // Strip thousands-separator commas (e.g. "1,370 ms" → "1370 ms") to prevent CSV column shift
  const parseDisplayVal = (v) => (v && typeof v === 'string') ? v.trim().replace(/(\d),(\d)/g, '$1$2') : null;

  // Savings in KB (null if audit missing or no savings)
  const savingsKB = id => {
    const bytes = audits[id]?.details?.overallSavingsBytes;
    return (bytes != null && bytes > 0) ? Math.round(bytes / 1024) : null;
  };
  const numericMs = id => audits[id]?.numericValue != null ? Math.round(audits[id].numericValue) : null;
  const numericVal = id => audits[id]?.numericValue != null ? Math.round(audits[id].numericValue) : null;

  // Diagnostics audit contains aggregate page stats
  const diag = audits['diagnostics']?.details?.items?.[0] ?? {};

  const oppAudits = Object.values(audits).filter(a => {
    if (!a.title) return false;
    const isOpportunity = a.details?.type === 'opportunity';
    const hasScore = a.score !== null && a.score !== undefined && a.score < 1;
    const notInfo = a.scoreDisplayMode !== 'informative' && a.scoreDisplayMode !== 'notApplicable';
    return (isOpportunity || (hasScore && notInfo)) && a.details?.type !== 'table';
  });
  const opportunities = oppAudits
    .sort((a, b) => {
      const savA = a.details?.overallSavingsMs || a.details?.overallSavingsBytes || 0;
      const savB = b.details?.overallSavingsMs || b.details?.overallSavingsBytes || 0;
      if (savA !== savB) return savB - savA;
      return (a.score || 1) - (b.score || 1);
    })
    .slice(0, 5)
    .map(a => ({
      title: a.title,
      savings: a.details?.overallSavingsMs
        ? Math.round(a.details.overallSavingsMs) + 'ms'
        : a.details?.overallSavingsBytes
          ? Math.round(a.details.overallSavingsBytes / 1024) + 'KB'
          : null,
      score: a.score !== null ? Math.round((a.score || 0) * 100) : null,
    }));

  // Third-party totals
  const tpItems = audits['third-party-summary']?.details?.items || [];
  const thirdPartyBlockingMs = tpItems.length ? Math.round(tpItems.reduce((t, i) => t + (i.blockingTime || 0), 0)) : null;
  const thirdPartyWeightKB = tpItems.length ? Math.round(tpItems.reduce((t, i) => t + (i.transferSize || 0), 0) / 1024) : null;
  const thirdPartyEntities = tpItems.length ? tpItems.slice(0, 10).map(i => {
    const name = i.entity || '';
    const parts = [];
    if (i.blockingTime > 0) parts.push(`${Math.round(i.blockingTime)}ms blocking`);
    if (i.transferSize > 0) parts.push(`${Math.round(i.transferSize/1024)}KB`);
    return parts.length ? `${name} (${parts.join(', ')})` : name;
  }).filter(Boolean).join('; ') : null;

  // Resource-level detail strings (semicolon-separated "url (wastedKB)" or "url (ms)")
  const renderBlockingResources = extractResourceItems(audits, 'render-blocking-resources', { byteField: 'totalBytes', msField: 'wastedMs' });
  const unusedJsResources       = extractResourceItems(audits, 'unused-javascript');
  const unusedCssResources      = extractResourceItems(audits, 'unused-css-rules');
  const unoptimizedImageResources = extractResourceItems(audits, 'uses-optimized-images');
  const modernImageResources    = extractResourceItems(audits, 'uses-webp-images');
  const responsiveImageResources = extractResourceItems(audits, 'uses-responsive-images');
  const offscreenImageResources = extractResourceItems(audits, 'offscreen-images');
  const legacyJsResources       = extractResourceItems(audits, 'legacy-javascript', { byteField: 'wastedBytes' });
  const duplicateJsResources    = extractResourceItems(audits, 'duplicated-javascript');
  const bootupTimeResources     = extractResourceItems(audits, 'bootup-time', { byteField: 'wastedBytes', msField: 'total' });
  const preconnectResources     = extractResourceItems(audits, 'uses-rel-preconnect', { byteField: 'wastedMs', msField: null });
  const fontDisplayResources    = extractResourceItems(audits, 'font-display', { byteField: 'wastedBytes' });

  // Additional failed audits (boolean pass/fail)
  const auditScore = id => audits[id]?.score != null ? Math.round(audits[id].score * 100) : null;
  const auditFailed = id => audits[id]?.score != null ? audits[id].score < 1 : null;

  // Numeric values for lab CWV (ms/score) in addition to displayValue strings
  const fcpMs = audits['first-contentful-paint']?.numericValue != null ? Math.round(audits['first-contentful-paint'].numericValue) : null;
  const lcpMs = audits['largest-contentful-paint']?.numericValue != null ? Math.round(audits['largest-contentful-paint'].numericValue) : null;
  const clsScore = audits['cumulative-layout-shift']?.numericValue != null ? Math.round(audits['cumulative-layout-shift'].numericValue * 1000) / 1000 : null;
  const tbtMs = audits['total-blocking-time']?.numericValue != null ? Math.round(audits['total-blocking-time'].numericValue) : null;
  const speedIndexMs = audits['speed-index']?.numericValue != null ? Math.round(audits['speed-index'].numericValue) : null;
  const ttiMs = audits['interactive']?.numericValue != null ? Math.round(audits['interactive'].numericValue) : null;

  return {
    // ── Scores ──────────────────────────────────────────────────────────────
    performance: score(cats['performance']),
    seo: score(cats['seo']),
    accessibility: score(cats['accessibility']),
    bestPractices: score(cats['best-practices']),

    // ── Core Web Vitals ─────────────────────────────────────────────────────
    fcp: parseDisplayVal(audits['first-contentful-paint']?.displayValue),
    lcp: parseDisplayVal(audits['largest-contentful-paint']?.displayValue),
    cls: parseDisplayVal(audits['cumulative-layout-shift']?.displayValue),
    tbt: parseDisplayVal(audits['total-blocking-time']?.displayValue),
    speedIndex: parseDisplayVal(audits['speed-index']?.displayValue),
    tti: parseDisplayVal(audits['interactive']?.displayValue),

    // ── Additional timing ───────────────────────────────────────────────────
    ttfbMs: numericMs('server-response-time'),

    // ── Page structure (from diagnostics audit) ─────────────────────────────
    totalPageWeightKB: diag.totalByteWeight != null ? Math.round(diag.totalByteWeight / 1024) : null,
    requestCount: diag.numRequests ?? null,
    numScripts: diag.numScripts ?? null,
    numStylesheets: diag.numStylesheets ?? null,
    numFonts: diag.numFonts ?? null,
    longTaskCount: diag.numTasksOver50ms ?? null,
    jsExecutionMs: numericMs('bootup-time'),
    mainThreadMs: numericMs('mainthread-work-breakdown'),
    domNodes: numericVal('dom-size'),

    // ── Unused resources ────────────────────────────────────────────────────
    unusedJsKB: savingsKB('unused-javascript'),
    unusedCssKB: savingsKB('unused-css-rules'),

    // ── Render blocking ─────────────────────────────────────────────────────
    renderBlockingCount: audits['render-blocking-resources']?.details?.items?.length ?? null,
    renderBlockingSavingsMs: audits['render-blocking-resources']?.details?.overallSavingsMs != null
      ? Math.round(audits['render-blocking-resources'].details.overallSavingsMs) : null,

    // ── Image optimisation ──────────────────────────────────────────────────
    unoptimizedImagesKB: savingsKB('uses-optimized-images'),
    modernImageFormatsKB: savingsKB('uses-webp-images'),
    responsiveImagesKB: savingsKB('uses-responsive-images'),
    offscreenImagesKB: savingsKB('offscreen-images'),

    // ── JS / CSS optimisation ───────────────────────────────────────────────
    unminifiedJsKB: savingsKB('unminified-javascript'),
    unminifiedCssKB: savingsKB('unminified-css'),
    textCompressionKB: savingsKB('uses-text-compression'),
    legacyJsKB: savingsKB('legacy-javascript'),
    duplicateJsKB: savingsKB('duplicated-javascript'),
    efficientAnimationsKB: savingsKB('efficient-animated-content'),

    // ── Third party ─────────────────────────────────────────────────────────
    thirdPartyBlockingMs,
    thirdPartyWeightKB,
    thirdPartyEntities,

    // ── Lab CWV numeric values (ms / raw score) ──────────────────────────────
    fcpMs, lcpMs, clsScore, tbtMs, speedIndexMs, ttiMs,

    // ── Resource detail strings ──────────────────────────────────────────────
    renderBlockingResources,
    unusedJsResources,
    unusedCssResources,
    unoptimizedImageResources,
    modernImageResources,
    responsiveImageResources,
    offscreenImageResources,
    legacyJsResources,
    duplicateJsResources,
    bootupTimeResources,
    preconnectResources,
    fontDisplayResources,

    // ── Additional audit scores ──────────────────────────────────────────────
    usesHttp2: auditScore('uses-http2'),
    usesHttp2Failed: auditFailed('uses-http2'),
    criticalRequestChainScore: auditScore('critical-request-chains'),
    usesPassiveListeners: auditScore('uses-passive-event-listeners'),
    noDocumentWrite: auditScore('no-document-write'),
    efficientCachePolicy: auditScore('uses-long-cache-ttl'),
    longCacheSavingsKB: savingsKB('uses-long-cache-ttl'),
    charsetDefined: auditScore('charset'),
    contentWidth: auditScore('content-width'),
    imageAlt: auditScore('image-alt'),
    linksDescriptive: auditScore('link-text'),
    robotsTxt: auditScore('robots-txt'),
    tapTargets: auditScore('tap-targets'),
    ariaValid: auditScore('aria-valid-attr'),
    colorContrast: auditScore('color-contrast'),
    documentTitle: auditScore('document-title'),
    metaDescription: auditScore('meta-description'),

    opportunities,
  };
}

async function checkPageSpeed(url, apiKey) {
  // Fire mobile + desktop simultaneously — both finish in the same time window
  // With API key: 400 req/100s, so 2 calls per audit is completely safe even at 5 concurrency
  const [mobileRes, desktopRes] = await Promise.all([
    fetchPageSpeedStrategy(url, 'mobile', apiKey),
    fetchPageSpeedStrategy(url, 'desktop', apiKey),
  ]);

  const mobileOk = mobileRes.ok;
  const desktopOk = desktopRes.ok;

  if (!mobileOk && !desktopOk) {
    return { ok: false, error: mobileRes.error || desktopRes.error, skipped: mobileRes.skipped || desktopRes.skipped };
  }

  const mobile = mobileOk ? parseLHR(mobileRes.lhr) : null;
  const desktop = desktopOk ? parseLHR(desktopRes.lhr) : null;

  // CrUX field data — prefer URL-level, fall back to origin-level
  const crux = mobileOk ? parseCrux(mobileRes.crux) : null;
  const originCrux = mobileOk ? parseCrux(mobileRes.originCrux) : null;

  // Primary metrics from mobile (Google's ranking signal), desktop as bonus
  const metrics = mobile || desktop;
  const attempts = Math.max(mobileRes.attempts || 1, desktopRes.attempts || 1);

  return {
    ok: true,
    metrics,
    mobile,
    desktop,
    crux,
    originCrux,
    opportunities: metrics?.opportunities || [],
    attempts,
  };
}

// ─── Check: SSL + HTTP redirect ───────────────────────────────────────────────
async function checkSSL(url) {
  const result = { httpsWorks: false, httpRedirects: false, redirectTarget: null };

  const httpsUrl = url.replace(/^http:\/\//i, 'https://');
  try {
    const r = await fetch(httpsUrl, {
      signal: AbortSignal.timeout(TIMEOUT_HTTP),
      redirect: 'follow',
      method: 'HEAD',
      headers: { 'user-agent': BROWSER_UA },
    });
    // 4xx from WAF/auth (403, 401, 429) means HTTPS is working — server responded
    // Only 5xx or connection failure means HTTPS is truly broken
    result.httpsWorks = r.status < 500;
  } catch {}

  const httpUrl = url.replace(/^https:\/\//i, 'http://');
  try {
    const r = await fetch(httpUrl, {
      signal: AbortSignal.timeout(TIMEOUT_HTTP),
      redirect: 'manual',
      method: 'HEAD',
      headers: { 'user-agent': BROWSER_UA },
    });
    const loc = r.headers.get('location') || '';
    if ([301, 302, 307, 308].includes(r.status) && loc.startsWith('https://')) {
      result.httpRedirects = true;
      result.redirectTarget = loc.slice(0, 120);
    }
  } catch {}

  return result;
}

// ─── Check: robots.txt + sitemap.xml ─────────────────────────────────────────
async function checkRobots(url) {
  const origin = getOrigin(url);
  if (!origin) return { robotsTxtExists: false, allDisallowed: false, sitemapInRobots: false, sitemapXmlExists: false };

  const result = { robotsTxtExists: false, allDisallowed: false, sitemapInRobots: false, sitemapXmlExists: false };

  try {
    const r = await fetch(origin + '/robots.txt', {
      signal: AbortSignal.timeout(TIMEOUT_HTTP),
      redirect: 'follow',
      headers: { 'user-agent': BROWSER_UA },
    });
    if (r.ok && r.headers.get('content-type')?.includes('text')) {
      result.robotsTxtExists = true;
      const text = await r.text();
      result.allDisallowed = /(?:^|\n)\s*Disallow:\s*\/\s*(?:\n|$)/m.test(text);
      result.sitemapInRobots = /Sitemap:/i.test(text);
    }
  } catch {}

  // Try /sitemap.xml and /sitemap_index.xml — either counts
  for (const path of ['/sitemap.xml', '/sitemap_index.xml']) {
    if (result.sitemapXmlExists) break;
    try {
      const r = await fetch(origin + path, {
        signal: AbortSignal.timeout(TIMEOUT_HTTP),
        redirect: 'follow',
        method: 'HEAD',
        headers: { 'user-agent': BROWSER_UA },
      });
      if (r.ok) result.sitemapXmlExists = true;
    } catch {}
  }

  return result;
}

// ─── Issue Generator ──────────────────────────────────────────────────────────
function generateIssues(httpData, pageSpeed, ssl, robots) {
  const issues = [];
  function add(severity, category, title, detail) {
    issues.push({ severity, category, title, detail });
  }

  if (httpData?.ok) {
    const h = httpData;
    const html = h.html;

    // Guard: if the HTML body is very small it's likely a JS shell, error page, or
    // Cloudflare challenge — skip HTML-derived checks to avoid false positives
    const htmlBodyValid = html.docSizeKB >= 2;

    // Performance — response time includes body download so only flag clear outliers
    if (h.responseMs > 5000) add('high', 'Performance', 'Very slow server response time',
      `Server took ${h.responseMs}ms to load. This includes page download time, but even so this is unusually slow. Visitors abandon pages that take more than 3 seconds, directly reducing conversions.`);
    else if (h.responseMs > 3000) add('medium', 'Performance', 'Slow server response time',
      `Server took ${h.responseMs}ms to respond. Faster servers (under 500ms TTFB) improve both user experience and Google rankings.`);

    if (htmlBodyValid && html.docSizeKB > 500) add('medium', 'Performance', `Large page size (${html.docSizeKB}KB HTML)`,
      `Page HTML alone is ${html.docSizeKB}KB. Large pages load slowly on mobile networks, losing prospects before the page finishes rendering.`);

    // SEO — only flag if we got real HTML (not a JS shell or error page)
    if (htmlBodyValid) {
      if (!html.title) add('critical', 'SEO', 'Missing title tag',
        'No title tag found in page HTML. The title is the single most important on-page SEO element — search engines use it as the primary ranking signal and display it in search results.');
      else if (html.titleLength < 20) add('medium', 'SEO', `Title tag very short (${html.titleLength} chars)`,
        `Title is only ${html.titleLength} characters. Very short titles miss opportunities to target keywords. Optimal range is 50–60 characters.`);
      else if (html.titleLength > 70) add('low', 'SEO', `Title tag too long (${html.titleLength} chars)`,
        `Title is ${html.titleLength} characters — Google truncates titles over ~60 characters in search results, hiding important keywords and reducing click-through rates.`);

      if (!html.metaDesc) add('high', 'SEO', 'Missing meta description',
        'No meta description found. Google uses this text in search results. Without one, Google auto-generates descriptions that often look unprofessional and reduce click-through rates.');
      else if (html.metaDescLength < 80) add('low', 'SEO', `Meta description too short (${html.metaDescLength} chars)`,
        `Meta description is only ${html.metaDescLength} characters. Short descriptions fail to give searchers context to click. Aim for 140–160 characters with a clear call-to-action.`);
      else if (html.metaDescLength > 165) add('low', 'SEO', `Meta description too long (${html.metaDescLength} chars)`,
        `Meta description is ${html.metaDescLength} characters — Google truncates at ~160 characters, cutting off the call-to-action.`);

      if (html.h1Count === 0) add('high', 'SEO', 'No H1 tag on page',
        'The page has no H1 heading, forcing Google to guess the page\'s primary topic. This weakens rankings for target keywords and creates poor user experience for screen readers.');
      else if (html.h1Count > 1) add('medium', 'SEO', `Multiple H1 tags (${html.h1Count} found)`,
        `The page has ${html.h1Count} H1 tags. Multiple H1s dilute SEO authority and confuse search engines about the page's main topic. Only one H1 is recommended.`);

      if (!html.hasCanonical) add('low', 'SEO', 'No canonical tag',
        'Missing canonical tag means duplicate content (www vs non-www, http vs https, trailing slash) may split SEO authority across multiple URL variations.');

      if (html.isNoindex) add('critical', 'SEO', 'Page is set to noindex',
        'The page has a noindex directive — it will NOT appear in Google search results at all. This is almost always a configuration error that costs all organic search traffic.');

      if (!html.hasJsonLD) add('low', 'SEO', 'No structured data detected',
        'No JSON-LD, Microdata, or RDFa structured data found. Structured data makes the site eligible for rich results (star ratings, FAQs, breadcrumbs) in Google Search.');

      // Mobile / UX
      if (!html.viewport) add('high', 'UX', 'No viewport meta tag — not mobile-optimized',
        'Missing viewport meta tag means the site is not mobile-optimized. Google uses mobile-first indexing, so non-mobile-friendly sites rank significantly lower. 60%+ of web traffic is on mobile.');

      // Social
      const missingOG = ['og:title', 'og:description', 'og:image'].filter(p => !html.ogTags[p]);
      if (missingOG.length === 3) add('medium', 'Social', 'No Open Graph tags for social sharing',
        'Missing all Open Graph tags means shared links on LinkedIn, Twitter, or Facebook show as bare links with no image or custom description — reducing click-through rates vs rich link previews.');
      else if (missingOG.includes('og:image')) add('low', 'Social', 'Missing og:image for social sharing',
        'No og:image tag means shared links have no thumbnail, reducing engagement when the site is shared on social media.');

      // Accessibility — only flag if many images are missing alt (not just decorative ones)
      if (html.altCoverage.total > 5 && html.altCoverage.coverage < 0.5) add('medium', 'Accessibility', `Low image alt text coverage (${Math.round(html.altCoverage.coverage * 100)}%)`,
        `${Math.round((1 - html.altCoverage.coverage) * html.altCoverage.total)} of ${html.altCoverage.total} images have no alt attribute at all. This harms accessibility for visually impaired users and prevents Google Images from indexing content.`);

      // Analytics — note this only detects HTML-visible scripts
      if (!html.analytics.hasGA && !html.analytics.hasGTM && !html.analytics.hasOther) add('low', 'Analytics', 'No analytics tracking detected in HTML',
        'No analytics platform (Google Analytics, GTM, Plausible, etc.) detected in page HTML. Note: server-side or tag-manager-proxied analytics may not be visible here. If analytics are confirmed present, disregard this item.');

      // Favicon
      if (!html.hasFavicon) add('low', 'Branding', 'No favicon configured',
        'No favicon found. Missing favicons appear as broken icons in browser tabs and bookmarks, reducing perceived professionalism for first-time visitors.');

      // Mixed content — only flag resources embedded in HTML markup (not JS data)
      if (html.mixedContent.length > 0) add('high', 'Security', `Mixed content: ${html.mixedContent.length} HTTP resource(s) on HTTPS page`,
        `The HTTPS page loads ${html.mixedContent.length} resource(s) over insecure HTTP. Browsers block or warn about mixed content, breaking functionality and showing security warnings.`);
    }

    // Security headers
    if (ssl && !ssl.httpsWorks) add('critical', 'Security', 'HTTPS not working',
      'The site\'s HTTPS version is inaccessible. Modern browsers display "Not Secure" warnings to all visitors, destroying trust and causing immediate exits.');

    if (ssl?.httpsWorks && !ssl?.httpRedirects) add('medium', 'Security', 'HTTP may not redirect to HTTPS',
      'HTTP-to-HTTPS redirect not detected via HEAD request. Visitors who type the domain without https:// may land on an insecure version. Verify this manually — some CDNs handle this transparently.');

    // HSTS: CDNs inject this for browsers but not API responses — LOW only
    if (!h.headers.hsts && ssl?.httpsWorks) add('low', 'Security', 'HSTS header not detected',
      'HTTP Strict Transport Security header not found in server response. Note: many CDNs (Cloudflare, Fastly) inject HSTS for browsers but not API requests — verify manually before flagging.');

    if (!h.headers.xContentType) add('low', 'Security', 'Missing X-Content-Type-Options header',
      'Missing security header allows MIME-type sniffing attacks. May already be set by CDN for browser requests.');

    // X-Frame-Options: only flag if CSP frame-ancestors is also absent
    const hasFrameAncestors = h.headers.csp && /frame-ancestors/i.test(h.headers.csp);
    if (!h.headers.xFrame && !hasFrameAncestors) add('low', 'Security', 'Missing clickjacking protection',
      'Neither X-Frame-Options nor CSP frame-ancestors directive detected. Without these, the site can be embedded in iframes on other domains, enabling clickjacking attacks.');

    // Robots / Crawlability
    if (robots?.allDisallowed) add('critical', 'SEO', 'robots.txt blocks all search engines',
      '"Disallow: /" in robots.txt tells Google and all search engines not to crawl any page. The site will not appear in search results. Almost certainly a configuration error.');

    if (!robots?.robotsTxtExists) add('low', 'SEO', 'No robots.txt file',
      'Missing robots.txt means search engines crawl without guidance. While not critical, it\'s a basic technical signal that the site lacks professional web configuration.');

    if (!robots?.sitemapInRobots && !robots?.sitemapXmlExists) add('low', 'SEO', 'No XML sitemap found',
      'No sitemap.xml or sitemap_index.xml detected. Sitemaps tell search engines what pages exist — without one, deep or new pages may take months to be discovered.');
  }

  // PageSpeed issues
  if (pageSpeed?.ok) {
    const ps = pageSpeed.metrics;
    if (ps.performance !== null && ps.performance !== undefined) {
      if (ps.performance < 50) add('high', 'Performance', `Poor mobile PageSpeed score (${ps.performance}/100)`,
        `Mobile PageSpeed score of ${ps.performance}/100 means the site loads very slowly on phones. Google uses Core Web Vitals as a ranking factor — low scores directly suppress search rankings and increase bounce rates.`);
      else if (ps.performance < 70) add('medium', 'Performance', `Below-average mobile PageSpeed score (${ps.performance}/100)`,
        `Mobile PageSpeed score of ${ps.performance}/100 is below Google's "Good" threshold of 90. Competitors with faster mobile sites will outrank and convert better.`);
    }
    if (ps.seo !== null && ps.seo !== undefined && ps.seo < 80) add('medium', 'SEO', `Low technical SEO audit score (${ps.seo}/100)`,
      `Technical SEO score of ${ps.seo}/100 indicates crawlability or on-page issues that are reducing search visibility.`);
    if (ps.accessibility !== null && ps.accessibility !== undefined && ps.accessibility < 70) add('medium', 'Accessibility', `Low accessibility score (${ps.accessibility}/100)`,
      `Accessibility score of ${ps.accessibility}/100 means the site is difficult to use for people with disabilities, creating legal risk (ADA/WCAG compliance) for US-based businesses.`);
  }

  return issues;
}

// ─── Summary builder ──────────────────────────────────────────────────────────
function buildSummary(url, metrics, issues) {
  const lines = [`WEBSITE AUDIT DATA FOR: ${url}`, ''];

  // Dead site — short-circuit summary
  if (metrics.siteAlive === false) {
    lines.push('SITE STATUS: NON-FUNCTIONAL');
    lines.push(`Reason: ${metrics.siteDeathReason}`);
    if (metrics.siteFlags) lines.push(`Flags: ${metrics.siteFlags}`);
    lines.push('');
    lines.push('PageSpeed, Core Web Vitals, and detailed technical audits were skipped.');
    if (issues.length) {
      lines.push('');
      lines.push('ISSUES:');
      issues.forEach(i => lines.push(`🔴 CRITICAL: [${i.category}] ${i.title}\n  → ${i.detail}`));
    }
    return lines.join('\n');
  }

  if (!metrics.pageSpeedOk && metrics.pageSpeedError) {
    lines.push(`PAGESPEED: Unavailable (${metrics.pageSpeedError})`);
    lines.push('');
  } else {
    const scoreLines = [];
    if (metrics.performance != null) scoreLines.push(`Performance: ${metrics.performance}/100`);
    if (metrics.seo != null) scoreLines.push(`SEO: ${metrics.seo}/100`);
    if (metrics.accessibility != null) scoreLines.push(`Accessibility: ${metrics.accessibility}/100`);
    if (metrics.bestPractices != null) scoreLines.push(`Best Practices: ${metrics.bestPractices}/100`);
    if (scoreLines.length) { lines.push('PAGESPEED SCORES (mobile):'); lines.push(...scoreLines); lines.push(''); }

    const vitalLines = [];
    if (metrics.fcp) vitalLines.push(`First Contentful Paint (FCP): ${metrics.fcp}`);
    if (metrics.lcp) vitalLines.push(`Largest Contentful Paint (LCP): ${metrics.lcp}`);
    if (metrics.cls) vitalLines.push(`Cumulative Layout Shift (CLS): ${metrics.cls}`);
    if (metrics.tbt) vitalLines.push(`Total Blocking Time (TBT): ${metrics.tbt}`);
    if (metrics.speedIndex) vitalLines.push(`Speed Index: ${metrics.speedIndex}`);
    if (metrics.tti) vitalLines.push(`Time to Interactive (TTI): ${metrics.tti}`);
    if (vitalLines.length) { lines.push('CORE WEB VITALS:'); lines.push(...vitalLines); lines.push(''); }
  }

  const techLines = [];
  if (metrics.responseMs != null) techLines.push(`Server response time: ${metrics.responseMs}ms`);
  if (metrics.httpsWorks != null) techLines.push(`HTTPS: ${metrics.httpsWorks ? 'Working' : 'NOT WORKING'}`);
  if (metrics.httpRedirects != null) techLines.push(`HTTP→HTTPS redirect: ${metrics.httpRedirects ? 'Yes' : 'No'}`);
  if (metrics.title !== undefined) techLines.push(`Title tag: ${metrics.title ? `"${metrics.title.slice(0, 80)}" (${metrics.titleLength} chars)` : 'MISSING'}`);
  if (metrics.metaDescLength !== undefined) techLines.push(`Meta description: ${metrics.metaDesc ? `${metrics.metaDescLength} chars` : 'MISSING'}`);
  if (metrics.h1Count !== undefined) techLines.push(`H1 tags: ${metrics.h1Count}`);
  if (metrics.viewport !== undefined) techLines.push(`Viewport/mobile meta: ${metrics.viewport ? 'Present' : 'MISSING'}`);
  if (metrics.hasCanonical !== undefined) techLines.push(`Canonical tag: ${metrics.hasCanonical ? 'Present' : 'Missing'}`);
  if (metrics.hasJsonLD !== undefined) techLines.push(`Structured data (JSON-LD): ${metrics.hasJsonLD ? 'Present' : 'Missing'}`);
  if (metrics.hasAnalytics !== undefined) techLines.push(`Analytics: ${metrics.hasAnalytics ? 'Detected' : 'NOT DETECTED'}`);
  if (metrics.hasSitemap !== undefined) techLines.push(`XML sitemap: ${metrics.hasSitemap ? 'Found' : 'Missing'}`);
  if (metrics.mixedContentCount !== undefined && metrics.mixedContentCount > 0) techLines.push(`Mixed content (HTTP on HTTPS): ${metrics.mixedContentCount} resource(s)`);
  if (metrics.docSizeKB !== undefined) techLines.push(`Page HTML size: ${metrics.docSizeKB}KB`);
  const hsts = metrics.hsts; const xct = metrics.xContentType; const xfr = metrics.xFrame;
  techLines.push(`Security headers: HSTS=${hsts ? 'Yes' : 'No'}, X-Content-Type=${xct ? 'Yes' : 'No'}, X-Frame=${xfr ? 'Yes' : 'No'}`);
  if (metrics.server) techLines.push(`Server: ${metrics.server}`);
  if (metrics.jsRendered) techLines.push(`Rendering: JavaScript-rendered (fetched with headless Chrome)`);
  if (techLines.length) { lines.push('TECHNICAL METRICS:'); lines.push(...techLines); lines.push(''); }

  if (metrics.opportunities?.length) {
    lines.push('TOP PERFORMANCE OPPORTUNITIES:');
    metrics.opportunities.forEach(o => lines.push(`- ${o.title}${o.savings ? ' (saves ~' + o.savings + ')' : ''}`));
    lines.push('');
  }

  if (issues.length) {
    const sevLabel = { critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM', low: '⚪ LOW' };
    lines.push(`ISSUES FOUND (${issues.length} total):`);
    issues.slice(0, 10).forEach(i => {
      lines.push(`${sevLabel[i.severity] || i.severity}: [${i.category}] ${i.title}`);
      lines.push(`  → ${i.detail}`);
    });
  } else {
    lines.push('No major issues detected — site appears technically healthy.');
  }

  return lines.join('\n');
}

// ─── Site Health Classifier ───────────────────────────────────────────────────
const PARKING_HOSTS = [
  'sedoparking.com','sedo.com','hugedomains.com','afternic.com','dan.com',
  'dot-services.org','dot-consulting.org','parkingcrew.net','above.com',
  'undeveloped.com','buydomains.com','domainnamessales.com','bodis.com',
  'godaddy.com','namecheap.com',
];

function classifySiteHealth(httpData) {
  if (!httpData?.ok) {
    return { alive: false, flags: ['connection-failed'], reason: httpData?.error || 'Connection failed' };
  }

  const html = httpData.html || {};
  const finalUrl = httpData.finalUrl || '';
  const status = httpData.status;
  const docSizeKB = html.docSizeKB ?? 0;
  const title = html.title || '';
  const snippet = html.pageTextSnippet || '';

  let finalHost = '';
  try { finalHost = new URL(finalUrl).hostname.toLowerCase(); } catch {}

  // 1. Redirect to known parking service
  for (const host of PARKING_HOSTS) {
    if (finalHost === host || finalHost.endsWith('.' + host)) {
      return { alive: false, flags: ['parked-redirect'], reason: `Redirects to parking service (${finalHost})` };
    }
  }

  // 2. Parked domain / for-sale page text in title or body snippet
  const combined = (title + ' ' + snippet).toLowerCase();
  if (
    /(?:domain|website).{0,15}(?:for sale|is for sale|available for purchase)|buy this domain|domain has expired|parked domain|domain parking/.test(combined)
    && docSizeKB < 30
  ) {
    return { alive: false, flags: ['parked-domain'], reason: 'Domain is parked or for sale' };
  }

  // 3. Broken server install — PHP/MySQL errors visible in page text
  if (/fatal error|mysql.*error|database connection|db connection error|php parse error|warning.*on line \d+/i.test(snippet)) {
    return { alive: false, flags: ['broken-install'], reason: 'Broken CMS / server error on page' };
  }

  // 4. Empty page — too small and no title
  if (docSizeKB <= 2 && title.length < 5) {
    return { alive: false, flags: ['empty-page'], reason: `Empty page (${docSizeKB}KB, no title)` };
  }

  // 5. Access-denied wall with no real content
  if ((status === 403 || status === 401) && docSizeKB < 5 && !title) {
    return { alive: false, flags: ['access-denied'], reason: `Access denied (HTTP ${status})` };
  }

  return { alive: true, flags: [], reason: '' };
}

// ─── Main export ──────────────────────────────────────────────────────────────
export async function auditWebsite(inputUrl, apiKey) {
  const t0 = Date.now();
  const errors = [];

  const url = normalizeUrl(inputUrl);
  if (!url) return { url: inputUrl, finalUrl: inputUrl, elapsedMs: 0, issues: [], topIssues: [], metrics: {}, summary: 'Invalid URL', errors: ['Invalid URL'] };

  // Phase 1: HTTP + SSL + Robots in parallel
  const [httpRes, sslRes, robotsRes] = await Promise.allSettled([
    checkHTTP(url), checkSSL(url), checkRobots(url),
  ]);

  const httpData = httpRes.status === 'fulfilled' ? httpRes.value : null;
  const ssl = sslRes.status === 'fulfilled' ? sslRes.value : null;
  const robots = robotsRes.status === 'fulfilled' ? robotsRes.value : null;

  if (httpRes.status === 'rejected') errors.push('HTTP check: ' + (httpRes.reason?.message || String(httpRes.reason)));
  if (sslRes.status === 'rejected') errors.push('SSL check: ' + (sslRes.reason?.message || String(sslRes.reason)));
  if (robotsRes.status === 'rejected') errors.push('Robots check: ' + (robotsRes.reason?.message || String(robotsRes.reason)));

  // Phase 2: Classify site health (fast, no I/O)
  const health = classifySiteHealth(httpData);

  const finalUrl = httpData?.finalUrl || url;
  const html = httpData?.html || {};
  const analytics = html.analytics || {};

  let originalDomain = '';
  let finalDomain = '';
  try { originalDomain = new URL(url).hostname; } catch {}
  try { finalDomain = new URL(finalUrl).hostname; } catch {}
  const domainRedirected = !!finalDomain && originalDomain !== finalDomain;

  // Phase 3: PageSpeed — skip entirely for dead/non-functional sites (saves 20-30s)
  let pageSpeed = null;
  let pageSpeedSkipped = false;
  if (health.alive) {
    const psRes = await checkPageSpeed(url, apiKey).catch(e => ({ ok: false, error: e.message }));
    pageSpeed = psRes;
    if (!psRes.ok) errors.push('PageSpeed check: ' + (psRes.error || 'unavailable'));
  } else {
    pageSpeedSkipped = true;
  }

  // Flatten metrics for easy access
  const metrics = {
    // Site health classification
    siteAlive: health.alive,
    siteFlags: health.flags.join(', '),
    siteDeathReason: health.reason,
    originalDomain,
    finalDomain,
    domainRedirected,

    responseMs: httpData?.responseMs,
    status: httpData?.status,
    finalUrl,
    httpsWorks: ssl?.httpsWorks,
    httpRedirects: ssl?.httpRedirects,
    title: html.title,
    titleLength: html.titleLength,
    metaDesc: html.metaDesc,
    metaDescLength: html.metaDescLength,
    h1Count: html.h1Count,
    viewport: html.viewport,
    hasCanonical: html.hasCanonical,
    isNoindex: html.isNoindex,
    hasJsonLD: html.hasJsonLD,
    hasFavicon: html.hasFavicon,
    docSizeKB: html.docSizeKB,
    altCoverage: html.altCoverage?.coverage,
    hasAnalytics: analytics.hasGA || analytics.hasGTM || analytics.hasOther || undefined,
    hasSitemap: robots?.sitemapXmlExists || robots?.sitemapInRobots,
    platform: html.platform || 'Unknown',
    copyrightYear: html.copyrightYear || '',
    contactMethods: html.contactMethods || {},
    hasScheduling: html.contactMethods?.hasScheduling || false,
    hasChatWidget: html.contactMethods?.hasChatWidget || false,
    hasClientPortal: html.contactMethods?.hasClientPortal || false,
    hasOnlinePayment: html.contactMethods?.hasOnlinePayment || false,
    hasCalculatorOrTool: html.contactMethods?.hasCalculatorOrTool || false,
    hasEmailCapture: html.contactMethods?.hasEmailCapture || false,
    pageTextSnippet: html.pageTextSnippet || '',
    jsRendered: httpData?.jsRendered || false,
    mixedContentCount: html.mixedContent?.length,
    hsts: httpData?.headers?.hsts,
    csp: httpData?.headers?.csp,
    xContentType: httpData?.headers?.xContentType,
    xFrame: httpData?.headers?.xFrame,
    server: httpData?.headers?.server,
    // HTML extended
    firstH1: html.h1s?.[0] || '',
    ogTitle: html.ogTags?.['og:title'] || '',
    ogDescription: html.ogTags?.['og:description'] || '',
    ogImage: html.ogTags?.['og:image'] || '',

    // PageSpeed — always present; null means unavailable, not zero
    performance: pageSpeed?.ok ? pageSpeed.metrics.performance : null,
    seo: pageSpeed?.ok ? pageSpeed.metrics.seo : null,
    accessibility: pageSpeed?.ok ? pageSpeed.metrics.accessibility : null,
    bestPractices: pageSpeed?.ok ? pageSpeed.metrics.bestPractices : null,
    fcp: pageSpeed?.ok ? pageSpeed.metrics.fcp : null,
    lcp: pageSpeed?.ok ? pageSpeed.metrics.lcp : null,
    cls: pageSpeed?.ok ? pageSpeed.metrics.cls : null,
    tbt: pageSpeed?.ok ? pageSpeed.metrics.tbt : null,
    speedIndex: pageSpeed?.ok ? pageSpeed.metrics.speedIndex : null,
    tti: pageSpeed?.ok ? pageSpeed.metrics.tti : null,
    ttfbMs: pageSpeed?.ok ? pageSpeed.metrics.ttfbMs : null,
    totalPageWeightKB: pageSpeed?.ok ? pageSpeed.metrics.totalPageWeightKB : null,
    requestCount: pageSpeed?.ok ? pageSpeed.metrics.requestCount : null,
    numScripts: pageSpeed?.ok ? pageSpeed.metrics.numScripts : null,
    numStylesheets: pageSpeed?.ok ? pageSpeed.metrics.numStylesheets : null,
    numFonts: pageSpeed?.ok ? pageSpeed.metrics.numFonts : null,
    longTaskCount: pageSpeed?.ok ? pageSpeed.metrics.longTaskCount : null,
    jsExecutionMs: pageSpeed?.ok ? pageSpeed.metrics.jsExecutionMs : null,
    mainThreadMs: pageSpeed?.ok ? pageSpeed.metrics.mainThreadMs : null,
    domNodes: pageSpeed?.ok ? pageSpeed.metrics.domNodes : null,
    unusedJsKB: pageSpeed?.ok ? pageSpeed.metrics.unusedJsKB : null,
    unusedCssKB: pageSpeed?.ok ? pageSpeed.metrics.unusedCssKB : null,
    renderBlockingCount: pageSpeed?.ok ? pageSpeed.metrics.renderBlockingCount : null,
    renderBlockingSavingsMs: pageSpeed?.ok ? pageSpeed.metrics.renderBlockingSavingsMs : null,
    unoptimizedImagesKB: pageSpeed?.ok ? pageSpeed.metrics.unoptimizedImagesKB : null,
    modernImageFormatsKB: pageSpeed?.ok ? pageSpeed.metrics.modernImageFormatsKB : null,
    responsiveImagesKB: pageSpeed?.ok ? pageSpeed.metrics.responsiveImagesKB : null,
    offscreenImagesKB: pageSpeed?.ok ? pageSpeed.metrics.offscreenImagesKB : null,
    unminifiedJsKB: pageSpeed?.ok ? pageSpeed.metrics.unminifiedJsKB : null,
    unminifiedCssKB: pageSpeed?.ok ? pageSpeed.metrics.unminifiedCssKB : null,
    textCompressionKB: pageSpeed?.ok ? pageSpeed.metrics.textCompressionKB : null,
    legacyJsKB: pageSpeed?.ok ? pageSpeed.metrics.legacyJsKB : null,
    duplicateJsKB: pageSpeed?.ok ? pageSpeed.metrics.duplicateJsKB : null,
    efficientAnimationsKB: pageSpeed?.ok ? pageSpeed.metrics.efficientAnimationsKB : null,
    thirdPartyBlockingMs: pageSpeed?.ok ? pageSpeed.metrics.thirdPartyBlockingMs : null,
    thirdPartyWeightKB: pageSpeed?.ok ? pageSpeed.metrics.thirdPartyWeightKB : null,
    thirdPartyEntities: pageSpeed?.ok ? pageSpeed.metrics.thirdPartyEntities : null,
    opportunities: pageSpeed?.ok ? (pageSpeed.opportunities || []) : [],
    pageSpeedOk: pageSpeed?.ok || false,
    pageSpeedError: pageSpeedSkipped ? 'Skipped — site non-functional' : (!pageSpeed?.ok ? (pageSpeed?.error || 'PageSpeed data unavailable') : null),
    pageSpeedAttempts: pageSpeed?.attempts || 0,

    // ── Lab CWV numeric (ms/raw) ─────────────────────────────────────────────
    fcpMs: pageSpeed?.ok ? pageSpeed.metrics.fcpMs : null,
    lcpMs: pageSpeed?.ok ? pageSpeed.metrics.lcpMs : null,
    clsScore: pageSpeed?.ok ? pageSpeed.metrics.clsScore : null,
    tbtMs: pageSpeed?.ok ? pageSpeed.metrics.tbtMs : null,
    speedIndexMs: pageSpeed?.ok ? pageSpeed.metrics.speedIndexMs : null,
    ttiMs: pageSpeed?.ok ? pageSpeed.metrics.ttiMs : null,

    // ── CrUX URL-level field data ────────────────────────────────────────────
    cruxAvailable: pageSpeed?.crux?.available || false,
    cruxOverall: pageSpeed?.crux?.overallCategory || null,
    cruxFCPMs: pageSpeed?.crux?.fcpMs ?? null,
    cruxFCPRating: pageSpeed?.crux?.fcpRating || null,
    cruxLCPMs: pageSpeed?.crux?.lcpMs ?? null,
    cruxLCPRating: pageSpeed?.crux?.lcpRating || null,
    cruxCLSScore: pageSpeed?.crux?.clsScore ?? null,
    cruxCLSRating: pageSpeed?.crux?.clsRating || null,
    cruxINPMs: pageSpeed?.crux?.inpMs ?? null,
    cruxINPRating: pageSpeed?.crux?.inpRating || null,
    cruxTTFBMs: pageSpeed?.crux?.ttfbMs ?? null,
    cruxTTFBRating: pageSpeed?.crux?.ttfbRating || null,
    cruxFIDMs: pageSpeed?.crux?.fidMs ?? null,
    cruxFIDRating: pageSpeed?.crux?.fidRating || null,

    // ── CrUX Origin-level field data ─────────────────────────────────────────
    originCruxAvailable: pageSpeed?.originCrux?.available || false,
    originCruxOverall: pageSpeed?.originCrux?.overallCategory || null,
    originCruxFCPMs: pageSpeed?.originCrux?.fcpMs ?? null,
    originCruxFCPRating: pageSpeed?.originCrux?.fcpRating || null,
    originCruxLCPMs: pageSpeed?.originCrux?.lcpMs ?? null,
    originCruxLCPRating: pageSpeed?.originCrux?.lcpRating || null,
    originCruxCLSScore: pageSpeed?.originCrux?.clsScore ?? null,
    originCruxCLSRating: pageSpeed?.originCrux?.clsRating || null,
    originCruxINPMs: pageSpeed?.originCrux?.inpMs ?? null,
    originCruxINPRating: pageSpeed?.originCrux?.inpRating || null,
    originCruxTTFBMs: pageSpeed?.originCrux?.ttfbMs ?? null,
    originCruxTTFBRating: pageSpeed?.originCrux?.ttfbRating || null,
    originCruxFIDMs: pageSpeed?.originCrux?.fidMs ?? null,
    originCruxFIDRating: pageSpeed?.originCrux?.fidRating || null,

    // ── Resource detail strings ──────────────────────────────────────────────
    renderBlockingResources: pageSpeed?.ok ? pageSpeed.metrics.renderBlockingResources : null,
    unusedJsResources: pageSpeed?.ok ? pageSpeed.metrics.unusedJsResources : null,
    unusedCssResources: pageSpeed?.ok ? pageSpeed.metrics.unusedCssResources : null,
    unoptimizedImageResources: pageSpeed?.ok ? pageSpeed.metrics.unoptimizedImageResources : null,
    modernImageResources: pageSpeed?.ok ? pageSpeed.metrics.modernImageResources : null,
    responsiveImageResources: pageSpeed?.ok ? pageSpeed.metrics.responsiveImageResources : null,
    offscreenImageResources: pageSpeed?.ok ? pageSpeed.metrics.offscreenImageResources : null,
    legacyJsResources: pageSpeed?.ok ? pageSpeed.metrics.legacyJsResources : null,
    duplicateJsResources: pageSpeed?.ok ? pageSpeed.metrics.duplicateJsResources : null,
    bootupTimeResources: pageSpeed?.ok ? pageSpeed.metrics.bootupTimeResources : null,
    preconnectResources: pageSpeed?.ok ? pageSpeed.metrics.preconnectResources : null,
    fontDisplayResources: pageSpeed?.ok ? pageSpeed.metrics.fontDisplayResources : null,

    // ── Additional audit scores ──────────────────────────────────────────────
    usesHttp2: pageSpeed?.ok ? pageSpeed.metrics.usesHttp2 : null,
    usesHttp2Failed: pageSpeed?.ok ? pageSpeed.metrics.usesHttp2Failed : null,
    criticalRequestChainScore: pageSpeed?.ok ? pageSpeed.metrics.criticalRequestChainScore : null,
    usesPassiveListeners: pageSpeed?.ok ? pageSpeed.metrics.usesPassiveListeners : null,
    noDocumentWrite: pageSpeed?.ok ? pageSpeed.metrics.noDocumentWrite : null,
    efficientCachePolicy: pageSpeed?.ok ? pageSpeed.metrics.efficientCachePolicy : null,
    longCacheSavingsKB: pageSpeed?.ok ? pageSpeed.metrics.longCacheSavingsKB : null,
    charsetDefined: pageSpeed?.ok ? pageSpeed.metrics.charsetDefined : null,
    contentWidth: pageSpeed?.ok ? pageSpeed.metrics.contentWidth : null,
    imageAlt: pageSpeed?.ok ? pageSpeed.metrics.imageAlt : null,
    linksDescriptive: pageSpeed?.ok ? pageSpeed.metrics.linksDescriptive : null,
    robotsTxt: pageSpeed?.ok ? pageSpeed.metrics.robotsTxt : null,
    tapTargets: pageSpeed?.ok ? pageSpeed.metrics.tapTargets : null,
    ariaValid: pageSpeed?.ok ? pageSpeed.metrics.ariaValid : null,
    colorContrast: pageSpeed?.ok ? pageSpeed.metrics.colorContrast : null,
    documentTitle: pageSpeed?.ok ? pageSpeed.metrics.documentTitle : null,
    metaDescription: pageSpeed?.ok ? pageSpeed.metrics.metaDescription : null,
  };

  // Dead sites get one critical issue; live sites get the full issue list
  const issues = health.alive
    ? generateIssues(httpData, pageSpeed, ssl, robots)
    : [{ severity: 'critical', category: 'Site Health', title: 'Site is non-functional', detail: health.reason }];

  // Sort: critical → high → medium → low
  const sevOrd = { critical: 0, high: 1, medium: 2, low: 3 };
  issues.sort((a, b) => sevOrd[a.severity] - sevOrd[b.severity]);

  const topIssues = issues.slice(0, 3);
  const summary = buildSummary(url, metrics, issues);

  // Expose full desktop PageSpeed metrics for CSV export
  const desktopData = pageSpeed?.ok && pageSpeed.desktop ? pageSpeed.desktop : null;

  return {
    url: inputUrl,
    finalUrl,
    elapsedMs: Date.now() - t0,
    issues,
    topIssues,
    metrics,
    desktop: desktopData,
    crux: pageSpeed?.crux || null,
    originCrux: pageSpeed?.originCrux || null,
    summary,
    errors,
  };
}
