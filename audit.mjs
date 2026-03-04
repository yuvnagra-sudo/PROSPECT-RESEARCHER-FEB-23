// audit.mjs — Website audit pipeline for Prospect Researcher
// Uses only Node 18+ built-ins (fetch, AbortSignal.timeout). No extra deps.

const TIMEOUT_HTTP = 12000;
const TIMEOUT_PAGESPEED = 60000;
const PAGESPEED_API_KEY = process.env.PAGESPEED_API_KEY || '';

// Adaptive PageSpeed semaphore: 2 concurrent with API key, 1 without; 1s cooldown per slot
const PS_MAX = PAGESPEED_API_KEY ? 2 : 1;
let _psActive = 0;
const _psQueue = [];
function checkPageSpeedQueued(url) {
  return new Promise((resolve, reject) => {
    _psQueue.push({ url, resolve, reject });
    _psDrain();
  });
}
function _psDrain() {
  while (_psActive < PS_MAX && _psQueue.length) {
    const { url, resolve, reject } = _psQueue.shift();
    _psActive++;
    checkPageSpeed(url).then(resolve, reject).finally(() => {
      setTimeout(() => { _psActive--; _psDrain(); }, 1000);
    });
  }
}

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

// ─── HTML parsers (regex only, no cheerio) ───────────────────────────────────
function parseTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim() : null;
}
function parseMetaDesc(html) {
  const m = html.match(/<meta\s+(?:[^>]*?\s+)?name=["']description["'][^>]*content=["']([^"']*)/i)
    || html.match(/<meta\s+(?:[^>]*?\s+)?content=["']([^"']*?)["'][^>]*name=["']description["']/i);
  return m ? m[1].trim() : null;
}
function parseH1s(html) {
  return [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)]
    .map(m => m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim());
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
  return /<script[^>]+type=["']application\/ld\+json["'][^>]*>/i.test(html);
}
function parseImageAltCoverage(html) {
  const allImgs = [...html.matchAll(/<img\b[^>]*>/gi)];
  if (!allImgs.length) return { total: 0, withAlt: 0, coverage: 1 };
  const withAlt = allImgs.filter(m => /\balt\s*=\s*["'][^"']+["']/i.test(m[0])).length;
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
  const refs = [];
  const pats = [
    /(?:src|href)=["'](http:\/\/[^"'\s>]{4,})/gi,
    /url\(["']?(http:\/\/[^"'\s)]{4,})/gi,
  ];
  for (const pat of pats) {
    let m;
    while ((m = pat.exec(html)) !== null) {
      if (!m[1].startsWith('http://localhost')) refs.push(m[1].slice(0, 100));
    }
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

// ─── Check: HTTP + HTML ───────────────────────────────────────────────────────
async function checkHTTP(url) {
  const t0 = Date.now();
  let res;
  try {
    res = await fetch(url, {
      signal: AbortSignal.timeout(TIMEOUT_HTTP),
      redirect: 'follow',
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; ProspectResearcher/1.0; +https://github.com)' },
    });
  } catch (e) {
    return { ok: false, error: e.message };
  }
  const responseMs = Date.now() - t0;
  const hdrs = {};
  for (const [k, v] of res.headers) hdrs[k.toLowerCase()] = v;

  let html = '';
  try { html = await res.text(); } catch {}

  const title = parseTitle(html);
  const metaDesc = parseMetaDesc(html);
  const h1s = parseH1s(html);
  const altCoverage = parseImageAltCoverage(html);
  const analytics = parseAnalytics(html);
  const ogTags = parseOGTags(html);
  const mixedContent = parseMixedContent(html, url);

  return {
    ok: true,
    status: res.status,
    finalUrl: res.url,
    responseMs,
    rawHtml: html,
    rawHeaders: hdrs,
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
    },
  };
}

// ─── Check: PageSpeed Insights (free, no key) ────────────────────────────────
async function checkPageSpeed(url) {
  const psUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=mobile&category=performance&category=seo&category=accessibility&category=best-practices${PAGESPEED_API_KEY ? '&key=' + PAGESPEED_API_KEY : ''}`;
  let res;
  for(let attempt=0;attempt<2;attempt++){
    try{res=await fetch(psUrl,{signal:AbortSignal.timeout(TIMEOUT_PAGESPEED)});}
    catch(e){return{ok:false,error:e.message};}
    if(res.status===429||res.status===503){
      if(attempt===0){await new Promise(r=>setTimeout(r,4000));continue;}
      return{ok:false,error:`PageSpeed API ${res.status} (rate limited)`};
    }
    break;
  }
  if(!res.ok)return{ok:false,error:`PageSpeed API ${res.status}`};
  let data;
  try { data = await res.json(); } catch { return { ok: false, error: 'Invalid JSON from PageSpeed' }; }

  const cats = data.lighthouseResult?.categories || {};
  const audits = data.lighthouseResult?.audits || {};
  const score = (cat) => (cat?.score !== null && cat?.score !== undefined) ? Math.round(cat.score * 100) : null;

  const metrics = {
    performance: score(cats['performance']),
    seo: score(cats['seo']),
    accessibility: score(cats['accessibility']),
    bestPractices: score(cats['best-practices']),
    fcp: audits['first-contentful-paint']?.displayValue || null,
    lcp: audits['largest-contentful-paint']?.displayValue || null,
    cls: audits['cumulative-layout-shift']?.displayValue || null,
    tbt: audits['total-blocking-time']?.displayValue || null,
  };

  const opportunities = Object.values(audits)
    .filter(a => a.details?.type === 'opportunity' && (a.details?.overallSavingsMs || 0) > 0)
    .sort((a, b) => (b.details?.overallSavingsMs || 0) - (a.details?.overallSavingsMs || 0))
    .slice(0, 3)
    .map(a => ({
      title: a.title,
      savings: a.details?.overallSavingsMs ? Math.round(a.details.overallSavingsMs) + 'ms' : null,
    }));

  return { ok: true, metrics, opportunities };
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
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; ProspectResearcher/1.0)' },
    });
    result.httpsWorks = r.status < 400;
  } catch {}

  const httpUrl = url.replace(/^https:\/\//i, 'http://');
  try {
    const r = await fetch(httpUrl, {
      signal: AbortSignal.timeout(TIMEOUT_HTTP),
      redirect: 'manual',
      method: 'HEAD',
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; ProspectResearcher/1.0)' },
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
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; ProspectResearcher/1.0)' },
    });
    if (r.ok && r.headers.get('content-type')?.includes('text')) {
      result.robotsTxtExists = true;
      const text = await r.text();
      result.allDisallowed = /(?:^|\n)\s*Disallow:\s*\/\s*(?:\n|$)/m.test(text);
      result.sitemapInRobots = /Sitemap:/i.test(text);
    }
  } catch {}

  try {
    const r = await fetch(origin + '/sitemap.xml', {
      signal: AbortSignal.timeout(TIMEOUT_HTTP),
      redirect: 'follow',
      method: 'HEAD',
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; ProspectResearcher/1.0)' },
    });
    result.sitemapXmlExists = r.ok;
  } catch {}

  return result;
}

// ─── Tech Stack Detection ─────────────────────────────────────────────────────
function detectTechStack(html, headers) {
  const h = headers || {};
  let platform = 'Custom / Unknown';
  if (/wp-content\/|wp-includes\/|wp-json/i.test(html) || /meta[^>]+generator[^>]+WordPress/i.test(html)) platform = 'WordPress';
  else if (/wixsite\.com|_wix_browser_sess/i.test(html) || Object.keys(h).some(k => k.startsWith('x-wix-'))) platform = 'Wix';
  else if (/static1\.squarespace\.com|squarespace-cdn\.com/i.test(html) || /meta[^>]+generator[^>]+Squarespace/i.test(html)) platform = 'Squarespace';
  else if (/cdn\.shopify\.com|Shopify\.theme|myshopify\.com/i.test(html)) platform = 'Shopify';
  else if (/webflow\.io|assets-global\.website-files\.com|data-wf-site/i.test(html)) platform = 'Webflow';
  else if (/Drupal\.settings|\/sites\/default\/files\//i.test(html) || /meta[^>]+generator[^>]+Drupal/i.test(html)) platform = 'Drupal';
  else if (/\/media\/jui\//i.test(html) || /meta[^>]+generator[^>]+Joomla/i.test(html)) platform = 'Joomla';
  else if (/godaddysites\.com|img1\.wsimg\.com/i.test(html)) platform = 'GoDaddy Website Builder';

  const booking = [];
  if (/calendly\.com/i.test(html)) booking.push('Calendly');
  if (/acuityscheduling\.com/i.test(html)) booking.push('Acuity Scheduling');
  if (/simplybook\.me/i.test(html)) booking.push('SimplyBook');
  if (/squareup\.com\/appointments/i.test(html)) booking.push('Square Appointments');
  if (/mindbodyonline\.com/i.test(html)) booking.push('Mindbody');
  if (/janeapp\.com/i.test(html)) booking.push('Jane App');

  const chat = [];
  if (/tawk\.to/i.test(html)) chat.push('Tawk.to');
  if (/widget\.intercom\.io|intercom\.io\/widget/i.test(html)) chat.push('Intercom');
  if (/js\.driftt\.com|drift\.com\/widget/i.test(html)) chat.push('Drift');
  if (/livechatinc\.com/i.test(html)) chat.push('LiveChat');
  if (/zopim\.|zendesk\.com\/embeddable/i.test(html)) chat.push('Zendesk');
  if (/crisp\.chat/i.test(html)) chat.push('Crisp');
  if (/js\.hs-scripts\.com/i.test(html)) chat.push('HubSpot Chat');

  const payments = [];
  if (/js\.stripe\.com/i.test(html)) payments.push('Stripe');
  if (/squareup\.com\/js/i.test(html)) payments.push('Square');
  if (/paypal\.com\/sdk/i.test(html)) payments.push('PayPal');
  if (/braintree-api\.com|braintreegateway\.com/i.test(html)) payments.push('Braintree');

  const email = [];
  if (/js\.hsforms\.net|js\.hs-scripts\.com/i.test(html)) email.push('HubSpot');
  if (/mailchimp\.com|list-manage\.com/i.test(html)) email.push('Mailchimp');
  if (/activehosted\.com/i.test(html)) email.push('ActiveCampaign');
  if (/klaviyo\.com/i.test(html)) email.push('Klaviyo');
  if (/constantcontact\.com/i.test(html)) email.push('Constant Contact');

  const analytics = [];
  if (/hotjar\.com/i.test(html)) analytics.push('Hotjar');
  if (/clarity\.ms/i.test(html)) analytics.push('Microsoft Clarity');
  if (/fbq\(|facebook\.net\/en_US\/fbevents/i.test(html)) analytics.push('Facebook Pixel');
  if (/snap\.licdn\.com/i.test(html)) analytics.push('LinkedIn Insight');
  if (/googletagmanager\.com/i.test(html)) analytics.push('Google Tag Manager');

  let cdn = null;
  const srv = (h['server'] || '').toLowerCase();
  if (h['cf-ray'] || srv.includes('cloudflare')) cdn = 'Cloudflare';
  else if ((h['x-served-by'] || '').toLowerCase().includes('fastly') || srv.includes('fastly')) cdn = 'Fastly';
  else if (h['x-amz-cf-id'] || h['x-amz-cf-pop'] || /cloudfront\.net/i.test(html)) cdn = 'AWS CloudFront';
  else if (srv.includes('akamai') || h['x-check-cacheable'] || h['akamai-x-cache']) cdn = 'Akamai';

  return { platform, booking, chat, payments, email, analytics, cdn };
}

// ─── Conversion Path Analysis ─────────────────────────────────────────────────
function checkConversionPaths(html) {
  const formMatches = html.match(/<form[\s>]/gi) || [];
  const formCount = formMatches.length;

  const telMatch = html.match(/href=["']tel:([^"']+)["']/i);
  const telNumber = telMatch ? telMatch[1] : null;

  const ctaPattern = /\b(book|schedule|contact\s+us|call\s+us|get\s+quote|free\s+consultation|request|appointment)\b/i;
  const hasCtaLinks = ctaPattern.test(html);

  const first30 = html.slice(0, Math.floor(html.length * 0.3));
  const phonePattern = /(\+1[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}/;
  const phoneMatch = first30.match(phonePattern);
  const phoneAboveFold = phoneMatch ? phoneMatch[0].trim() : null;

  return { formCount, telNumber, hasCtaLinks, phoneAboveFold };
}

// ─── Business Context Inference (for GBP search) ─────────────────────────────
function inferBusinessContext(html, finalUrl) {
  const h1Match = html.match(/<h1[^>]*>([^<]{3,80})<\/h1>/i);
  const h1Text = h1Match ? h1Match[1].replace(/<[^>]+>/g, '').trim() : null;

  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const titleFull = titleMatch ? titleMatch[1].trim() : null;
  const titleShort = titleFull ? titleFull.split(/[|\-–—]/)[0].trim() : null;

  const keyword = h1Text || titleShort || '';

  let city = '';
  const inCityMatch = ((titleFull || '') + ' ' + (h1Text || '')).match(/\bin\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/);
  if (inCityMatch) city = inCityMatch[1];
  if (!city) { const ld = html.match(/"addressLocality"\s*:\s*"([^"]+)"/); if (ld) city = ld[1]; }

  let domain = '';
  try { domain = new URL(finalUrl).hostname.replace(/^www\./, '').split('.')[0]; } catch {}
  const companyName = titleShort || domain || keyword;

  return { companyName: companyName.slice(0, 80), city: city.slice(0, 40), keyword: keyword.slice(0, 80) };
}

// ─── Google Business Profile Lookup ──────────────────────────────────────────
async function checkGoogleBusinessProfile(companyName, city, keyword, apiKey) {
  if (!apiKey) return { available: false, reason: 'no_api_key' };

  const BASE = 'https://places.googleapis.com/v1/places:searchText';
  const MASK = 'places.displayName,places.formattedAddress,places.rating,places.userRatingCount,places.types,places.websiteUri,places.googleMapsUri,places.photos';

  async function searchPlaces(textQuery, maxResultCount = 1) {
    const body = { textQuery };
    if (maxResultCount > 1) body.maxResultCount = maxResultCount;
    const r = await fetch(BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': apiKey, 'X-Goog-FieldMask': MASK },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    const json = await r.json();
    if (!r.ok) throw new Error(`Places API ${r.status}: ${json.error?.message||json.error?.status||r.statusText}`);
    return json.places || [];
  }

  const issues = [];
  let business = null;
  let competitors = [];

  try {
    const searchQ = city ? `${companyName} ${city}` : companyName;
    const bizResults = await searchPlaces(searchQ, 3);
    const nameLower = companyName.toLowerCase();
    const match = bizResults.find(p => {
      const pn = (p.displayName?.text || '').toLowerCase();
      return pn.includes(nameLower.split(' ')[0]) || nameLower.includes(pn.split(' ')[0]);
    });

    if (match) {
      business = {
        name: match.displayName?.text,
        address: match.formattedAddress,
        rating: match.rating,
        reviewCount: match.userRatingCount,
        types: match.types,
        website: match.websiteUri,
        mapsUrl: match.googleMapsUri,
        photoCount: match.photos?.length || 0,
      };
      if (!business.reviewCount || business.reviewCount < 10)
        issues.push({ severity: 'medium', category: 'Local SEO', title: 'Low Google review count',
          detail: `Only ${business.reviewCount || 0} Google reviews. Businesses with 10+ reviews rank higher in local map pack results.` });
      if (!business.rating)
        issues.push({ severity: 'medium', category: 'Local SEO', title: 'No Google star rating',
          detail: 'No star rating on Google Business Profile. This may indicate an unclaimed listing or very few reviews.' });
      if (business.photoCount < 3)
        issues.push({ severity: 'low', category: 'Local SEO', title: 'Few Google Business Profile photos',
          detail: `Only ${business.photoCount} photo(s) on GBP. Listings with more photos get more clicks in Google Maps.` });
    } else {
      issues.push({ severity: 'high', category: 'Local SEO', title: 'Business not found on Google Maps',
        detail: 'Could not find this business in Google Places. An unclaimed or missing GBP listing means the business is invisible in local search and Google Maps.' });
    }

    const compQ = city ? `${keyword || companyName} ${city}` : (keyword || companyName);
    const compResults = await searchPlaces(compQ, 5);
    const bizHostname = business?.website ? (() => { try { return new URL(business.website).hostname; } catch { return ''; } })() : '';
    competitors = compResults
      .filter(p => {
        const pn = (p.displayName?.text || '').toLowerCase();
        const ps = (p.websiteUri || '').toLowerCase();
        return !pn.includes(nameLower.split(' ')[0]) && (!bizHostname || !ps.includes(bizHostname));
      })
      .slice(0, 3)
      .map(p => ({ name: p.displayName?.text, rating: p.rating, reviewCount: p.userRatingCount, website: p.websiteUri, photoCount: p.photos?.length || 0 }));

    if (business && competitors.length > 0) {
      const top = competitors[0];
      if (top.reviewCount && (business.reviewCount || 0) > 0 && top.reviewCount >= 3 * business.reviewCount)
        issues.push({ severity: 'high', category: 'Local SEO', title: `Competitor "${top.name}" has ${top.reviewCount}x more reviews`,
          detail: `${top.name} has ${top.reviewCount} reviews vs your ${business.reviewCount}. Review count is a primary local pack ranking factor.` });
      else if (top.reviewCount && !business.reviewCount)
        issues.push({ severity: 'high', category: 'Local SEO', title: 'Competitors have reviews; this business does not',
          detail: `Top competitor "${top.name}" has ${top.reviewCount} reviews. Getting even 10 reviews can dramatically improve local pack visibility.` });
      if (top.rating && business.rating && top.rating - business.rating >= 0.5)
        issues.push({ severity: 'medium', category: 'Local SEO', title: `Competitor has higher Google rating`,
          detail: `"${top.name}" has ${top.rating}★ vs your ${business.rating}★. Higher ratings improve click-through rates in local search.` });
    }
  } catch (e) {
    return { available: false, reason: e.message };
  }

  return { available: true, business, competitors, issues };
}

// ─── Tech/Conversion Issue Generator ─────────────────────────────────────────
function generateTechIssues(techStack, conversion, html) {
  const issues = [];
  if (!techStack || !conversion) return issues;
  function add(severity, category, title, detail) { issues.push({ severity, category, title, detail }); }

  if (techStack.platform === 'WordPress')
    add('low', 'Technology', 'Built on WordPress — verify plugins and themes are current',
      'WordPress powers 40% of the web but is the most targeted CMS for security vulnerabilities. Outdated plugins are the #1 source of WordPress hacks.');

  const serviceWords = /\b(consultation|appointment|schedule|services|therapy|coaching|clinic|studio|salon|spa|treatment|session|booking)\b/i;
  if (techStack.booking.length === 0 && serviceWords.test(html))
    add('medium', 'Conversion', 'No online booking system detected',
      'The site appears service-based but has no online booking tool (Calendly, Acuity, etc.). Requiring prospects to call or email to book creates friction that loses leads.');

  if (techStack.chat.length === 0)
    add('low', 'Conversion', 'No live chat or messaging widget detected',
      'No chat widget found. Live chat can increase conversion rates by 20–40% by answering questions in real time when visitors are ready to buy.');

  if (conversion.formCount === 0)
    add('high', 'Conversion', 'No contact form found on homepage',
      'No HTML form elements detected. Without a contact form, leads have no easy way to reach out — they must navigate elsewhere or leave.');

  if (!conversion.phoneAboveFold)
    add('medium', 'Conversion', 'No visible phone number above the fold',
      'No phone number found in the first third of the page. Service businesses convert significantly better when a phone number is immediately visible without scrolling.');

  if (!conversion.hasCtaLinks)
    add('high', 'Conversion', 'No clear calls to action detected',
      'No button or link text containing action words (Book, Schedule, Contact, Get Quote, etc.) was found. Without clear CTAs, visitors do not know what step to take next.');

  return issues;
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

    // Performance
    if (h.responseMs > 3000) add('high', 'Performance', 'Slow server response time',
      `Server took ${h.responseMs}ms to respond. Visitors abandon pages that take more than 3 seconds to load, directly reducing conversions and lead capture.`);
    else if (h.responseMs > 1500) add('medium', 'Performance', 'Above-average server response time',
      `Server response is ${h.responseMs}ms. Faster servers (under 500ms) improve both user experience and Google rankings.`);

    if (html.docSizeKB > 500) add('medium', 'Performance', `Large page size (${html.docSizeKB}KB HTML)`,
      `Page HTML alone is ${html.docSizeKB}KB. Large pages load slowly on mobile networks, losing prospects before the page finishes rendering.`);

    // SEO
    if (!html.title) add('critical', 'SEO', 'Missing title tag',
      'No title tag found. The title is the single most important on-page SEO element — search engines use it as the primary ranking signal and display it in search results. Missing it means Google auto-generates a title, often resulting in low click-through rates.');
    else if (html.titleLength < 30) add('medium', 'SEO', `Title tag too short (${html.titleLength} chars)`,
      `Title is only ${html.titleLength} characters. Short titles miss opportunities to target keywords. Optimal range is 50–60 characters.`);
    else if (html.titleLength > 70) add('low', 'SEO', `Title tag too long (${html.titleLength} chars)`,
      `Title is ${html.titleLength} characters — Google truncates titles over ~60 characters in search results, hiding important keywords and reducing click-through rates.`);

    if (!html.metaDesc) add('high', 'SEO', 'Missing meta description',
      'No meta description found. Google uses this text in search results. Without one, Google auto-generates descriptions that often look unprofessional and reduce click-through rates by 5–10%.');
    else if (html.metaDescLength < 80) add('low', 'SEO', `Meta description too short (${html.metaDescLength} chars)`,
      `Meta description is only ${html.metaDescLength} characters. Short descriptions fail to give searchers context to click. Aim for 140–160 characters with a clear call-to-action.`);
    else if (html.metaDescLength > 165) add('low', 'SEO', `Meta description too long (${html.metaDescLength} chars)`,
      `Meta description is ${html.metaDescLength} characters — Google truncates at ~160 characters, cutting off the call-to-action.`);

    if (html.h1Count === 0) add('high', 'SEO', 'No H1 tag on page',
      'The page has no H1 heading, forcing Google to guess the page\'s primary topic. This weakens rankings for target keywords and creates poor user experience for screen readers.');
    else if (html.h1Count > 1) add('medium', 'SEO', `Multiple H1 tags (${html.h1Count} found)`,
      `The page has ${html.h1Count} H1 tags. Multiple H1s dilute SEO authority and confuse search engines about the page's main topic. Only one H1 is recommended.`);

    if (!html.hasCanonical) add('low', 'SEO', 'No canonical tag',
      'Missing canonical tag means duplicate content (www vs non-www, http vs https, trailing slash) splits SEO authority across multiple URL variations, weakening rankings.');

    if (html.isNoindex) add('critical', 'SEO', 'Page is set to noindex',
      'The page has a noindex directive — it will NOT appear in Google search results at all. This is almost always a configuration error that costs all organic search traffic.');

    if (!html.hasJsonLD) add('low', 'SEO', 'No structured data (JSON-LD)',
      'Missing structured data makes the site ineligible for rich results (star ratings, FAQs, breadcrumbs) in Google Search, reducing click-through rates vs competitors with them.');

    // Mobile / UX
    if (!html.viewport) add('high', 'UX', 'No viewport meta tag — not mobile-optimized',
      'Missing viewport meta tag means the site is not mobile-optimized. Google uses mobile-first indexing, so non-mobile-friendly sites rank significantly lower. 60%+ of web traffic is on mobile.');

    // Social
    const missingOG = ['og:title', 'og:description', 'og:image'].filter(p => !html.ogTags[p]);
    if (missingOG.length === 3) add('medium', 'Social', 'No Open Graph tags for social sharing',
      'Missing all Open Graph tags means shared links on LinkedIn, Twitter, or Facebook show as bare links with no image or custom description — reducing click-through rates by 3x vs rich link previews.');
    else if (missingOG.includes('og:image')) add('low', 'Social', 'Missing og:image for social sharing',
      'No og:image tag means shared links have no thumbnail, reducing engagement when the site is shared on social media.');

    // Security
    if (ssl && !ssl.httpsWorks) add('critical', 'Security', 'HTTPS not working',
      'The site\'s HTTPS version is inaccessible. Modern browsers display "Not Secure" warnings to all visitors, destroying trust and causing immediate exits. Google also penalizes non-HTTPS sites in rankings.');

    if (ssl?.httpsWorks && !ssl?.httpRedirects) add('high', 'Security', 'HTTP does not redirect to HTTPS',
      'Visitors who type the domain without https:// land on an insecure HTTP version. This exposes user data, triggers browser security warnings, and splits SEO authority between http and https versions.');

    if (!h.headers.hsts && ssl?.httpsWorks) add('medium', 'Security', 'Missing HSTS header',
      'No HTTP Strict Transport Security header means browsers won\'t enforce HTTPS connections, leaving users vulnerable to SSL stripping attacks on public networks.');

    if (!h.headers.xContentType) add('low', 'Security', 'Missing X-Content-Type-Options header',
      'Missing security header allows MIME-type sniffing attacks. Also signals the server configuration hasn\'t been security-hardened, which sophisticated buyers notice.');

    if (!h.headers.xFrame) add('low', 'Security', 'Missing X-Frame-Options header',
      'Without X-Frame-Options, the site can be embedded in iframes on other domains, enabling clickjacking attacks where users are tricked into taking unintended actions.');

    if (html.mixedContent.length > 0) add('high', 'Security', `Mixed content: ${html.mixedContent.length} HTTP resource(s) on HTTPS page`,
      `The HTTPS page loads ${html.mixedContent.length} resource(s) over insecure HTTP. Browsers block or warn about mixed content, breaking functionality and showing security warnings that reduce visitor trust.`);

    // Accessibility
    if (html.altCoverage.total > 3 && html.altCoverage.coverage < 0.5) add('medium', 'Accessibility', `Low image alt text coverage (${Math.round(html.altCoverage.coverage * 100)}%)`,
      `Only ${Math.round(html.altCoverage.coverage * 100)}% of ${html.altCoverage.total} images have descriptive alt text. This harms accessibility for visually impaired users, risks ADA compliance issues, and prevents Google Images from indexing content.`);

    // Analytics
    if (!html.analytics.hasGA && !html.analytics.hasGTM && !html.analytics.hasOther) add('medium', 'Analytics', 'No analytics tracking detected',
      'No analytics platform detected (Google Analytics, GTM, etc.). The business is making marketing decisions without data on visitor behavior, traffic sources, or conversion rates.');

    // Robots / Crawlability
    if (robots?.allDisallowed) add('critical', 'SEO', 'robots.txt blocks all search engines',
      '"Disallow: /" in robots.txt tells Google and all search engines not to crawl any page. The site will not appear in search results. Almost certainly a configuration error that costs all organic traffic.');

    if (!robots?.robotsTxtExists) add('low', 'SEO', 'No robots.txt file',
      'Missing robots.txt means search engines crawl without guidance. While not critical, it\'s a basic technical signal that the site lacks professional web configuration.');

    if (!robots?.sitemapInRobots && !robots?.sitemapXmlExists) add('low', 'SEO', 'No XML sitemap found',
      'No sitemap.xml detected. Sitemaps tell search engines what pages exist. Without one, deep or new pages may take months to be discovered and indexed.');

    // Favicon
    if (!html.hasFavicon) add('low', 'Branding', 'No favicon configured',
      'No favicon found. Missing favicons appear as broken icons in browser tabs and bookmarks, reducing perceived professionalism for first-time visitors.');
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

  const scoreLines = [];
  if (metrics.performance != null) scoreLines.push(`Performance: ${metrics.performance}/100`);
  if (metrics.seo != null) scoreLines.push(`SEO: ${metrics.seo}/100`);
  if (metrics.accessibility != null) scoreLines.push(`Accessibility: ${metrics.accessibility}/100`);
  if (metrics.bestPractices != null) scoreLines.push(`Best Practices: ${metrics.bestPractices}/100`);
  if (scoreLines.length) { lines.push('PAGESPEED SCORES (mobile):'); lines.push(...scoreLines); lines.push(''); }

  const vitalLines = [];
  if (metrics.fcp) vitalLines.push(`FCP: ${metrics.fcp}`);
  if (metrics.lcp) vitalLines.push(`LCP: ${metrics.lcp}`);
  if (metrics.cls) vitalLines.push(`CLS: ${metrics.cls}`);
  if (metrics.tbt) vitalLines.push(`TBT: ${metrics.tbt}`);
  if (vitalLines.length) { lines.push('CORE WEB VITALS:'); lines.push(...vitalLines); lines.push(''); }

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

  const ts = metrics.techStack;
  if (ts) {
    lines.push('');
    lines.push('TECH STACK:');
    lines.push(`Platform: ${ts.platform}`);
    if (ts.booking.length) lines.push(`Booking: ${ts.booking.join(', ')}`);
    if (ts.chat.length) lines.push(`Chat: ${ts.chat.join(', ')}`);
    if (ts.payments.length) lines.push(`Payments: ${ts.payments.join(', ')}`);
    if (ts.email.length) lines.push(`Email/CRM: ${ts.email.join(', ')}`);
    if (ts.analytics.length) lines.push(`Analytics: ${ts.analytics.join(', ')}`);
    if (ts.cdn) lines.push(`CDN: ${ts.cdn}`);
  }

  const cv = metrics.conversion;
  if (cv) {
    lines.push('');
    lines.push('CONVERSION PATHS:');
    lines.push(`Contact forms: ${cv.formCount}`);
    if (cv.telNumber) lines.push(`Click-to-call: ${cv.telNumber}`);
    if (cv.phoneAboveFold) lines.push(`Phone visible above fold: ${cv.phoneAboveFold}`);
    lines.push(`CTA buttons/links: ${cv.hasCtaLinks ? 'Yes' : 'None detected'}`);
  }

  const gbp = metrics.gbp;
  if (gbp?.available && gbp.business) {
    lines.push('');
    lines.push('GOOGLE BUSINESS PROFILE:');
    lines.push(`Business: ${gbp.business.name}`);
    if (gbp.business.rating) lines.push(`Rating: ${gbp.business.rating}★ (${gbp.business.reviewCount || 0} reviews)`);
    else lines.push(`Reviews: ${gbp.business.reviewCount || 0}`);
    lines.push(`Photos: ${gbp.business.photoCount}`);
    if (gbp.business.address) lines.push(`Address: ${gbp.business.address}`);
    if (gbp.competitors?.length) {
      lines.push('');
      lines.push('LOCAL COMPETITORS:');
      gbp.competitors.forEach((c, i) => lines.push(`${i + 1}. ${c.name} — ${c.rating ? c.rating + '★' : 'no rating'} (${c.reviewCount || 0} reviews)`));
    }
  }

  return lines.join('\n');
}

// ─── Main export ──────────────────────────────────────────────────────────────
export async function auditWebsite(inputUrl, { placesApiKey, companyName: hintName } = {}) {
  const t0 = Date.now();
  const errors = [];

  const url = normalizeUrl(inputUrl);
  if (!url) return { url: inputUrl, finalUrl: inputUrl, elapsedMs: 0, issues: [], topIssues: [], metrics: {}, summary: 'Invalid URL', errors: ['Invalid URL'] };

  // GBP chains off the HTTP promise so HTML is available for keyword inference
  const httpPromise = checkHTTP(url);
  const effectivePlacesKey = placesApiKey || process.env.GOOGLE_PLACES_API_KEY || '';
  const gbpPromise = effectivePlacesKey
    ? httpPromise.then(httpData => {
        if (!httpData?.ok) return { available: false, reason: 'http_failed' };
        const ctx = inferBusinessContext(httpData.rawHtml, httpData.finalUrl || url);
        const name = hintName || ctx.companyName;
        return checkGoogleBusinessProfile(name, ctx.city, ctx.keyword, effectivePlacesKey);
      }).catch(e => ({ available: false, reason: e.message }))
    : Promise.resolve({ available: false, reason: 'no_api_key' });

  // Run all checks in parallel (GBP starts as soon as HTTP resolves)
  const [httpRes, pageSpeedRes, sslRes, robotsRes, gbpRes] = await Promise.allSettled([
    httpPromise,
    checkPageSpeedQueued(url),
    checkSSL(url),
    checkRobots(url),
    gbpPromise,
  ]);

  const httpData = httpRes.status === 'fulfilled' ? httpRes.value : null;
  const pageSpeed = pageSpeedRes.status === 'fulfilled' ? pageSpeedRes.value : null;
  const ssl = sslRes.status === 'fulfilled' ? sslRes.value : null;
  const robots = robotsRes.status === 'fulfilled' ? robotsRes.value : null;
  const gbp = gbpRes.status === 'fulfilled' ? gbpRes.value : null;

  if (httpRes.status === 'rejected') errors.push('HTTP check: ' + (httpRes.reason?.message || String(httpRes.reason)));
  if (pageSpeedRes.status === 'rejected') errors.push('PageSpeed check: ' + (pageSpeedRes.reason?.message || String(pageSpeedRes.reason)));
  if (sslRes.status === 'rejected') errors.push('SSL check: ' + (sslRes.reason?.message || String(sslRes.reason)));
  if (robotsRes.status === 'rejected') errors.push('Robots check: ' + (robotsRes.reason?.message || String(robotsRes.reason)));

  const finalUrl = httpData?.finalUrl || url;
  const html = httpData?.html || {};
  const analytics = html.analytics || {};

  // Tech stack and conversion analysis (synchronous, uses already-fetched HTML)
  const techStack = httpData?.ok ? detectTechStack(httpData.rawHtml, httpData.rawHeaders) : null;
  const conversion = httpData?.ok ? checkConversionPaths(httpData.rawHtml) : null;

  // Flatten metrics for easy access
  const metrics = {
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
    mixedContentCount: html.mixedContent?.length,
    hsts: httpData?.headers?.hsts,
    csp: httpData?.headers?.csp,
    xContentType: httpData?.headers?.xContentType,
    xFrame: httpData?.headers?.xFrame,
    server: httpData?.headers?.server,
    // PageSpeed
    performance: pageSpeed?.ok ? pageSpeed.metrics.performance : null,
    seo: pageSpeed?.ok ? pageSpeed.metrics.seo : null,
    accessibility: pageSpeed?.ok ? pageSpeed.metrics.accessibility : null,
    bestPractices: pageSpeed?.ok ? pageSpeed.metrics.bestPractices : null,
    fcp: pageSpeed?.ok ? pageSpeed.metrics.fcp : null,
    lcp: pageSpeed?.ok ? pageSpeed.metrics.lcp : null,
    cls: pageSpeed?.ok ? pageSpeed.metrics.cls : null,
    tbt: pageSpeed?.ok ? pageSpeed.metrics.tbt : null,
    opportunities: pageSpeed?.ok ? (pageSpeed.opportunities || []) : [],
    pageSpeedError: (!pageSpeed || pageSpeed.ok) ? null : pageSpeed.error,
    // New fields
    techStack,
    conversion,
    gbp,
  };

  const issues = generateIssues(httpData, pageSpeed, ssl, robots);

  // Tech/conversion issues
  const techIssues = generateTechIssues(techStack, conversion, httpData?.rawHtml || '');
  issues.push(...techIssues);

  // GBP issues
  if (gbp?.issues?.length) issues.push(...gbp.issues);

  // Sort: critical → high → medium → low
  const sevOrd = { critical: 0, high: 1, medium: 2, low: 3 };
  issues.sort((a, b) => sevOrd[a.severity] - sevOrd[b.severity]);

  const topIssues = issues.slice(0, 3);
  const summary = buildSummary(url, metrics, issues);

  return {
    url: inputUrl,
    finalUrl,
    elapsedMs: Date.now() - t0,
    issues,
    topIssues,
    metrics,
    summary,
    errors,
  };
}
