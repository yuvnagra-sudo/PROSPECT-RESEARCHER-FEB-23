// screenshot.mjs — Playwright homepage screenshot capture
// Capped at MAX_SLOTS concurrent browser instances regardless of caller concurrency.

import { chromium } from 'playwright';
import { mkdirSync, existsSync } from 'fs';
import { writeFile } from 'fs/promises';
import { join, resolve } from 'path';

const SCREENSHOT_DIR = resolve(process.cwd(), 'screenshots');
if (!existsSync(SCREENSHOT_DIR)) mkdirSync(SCREENSHOT_DIR, { recursive: true });

const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const VIEWPORT   = { width: 1280, height: 900 };
const TIMEOUT_MS = 20000;
const MAX_SLOTS  = 5;

// ─── Semaphore ────────────────────────────────────────────────────────────────
let slots = MAX_SLOTS;
const queue = [];
function acquire() {
  return new Promise(res => {
    if (slots > 0) { slots--; res(); }
    else queue.push(res);
  });
}
function release() {
  if (queue.length > 0) queue.shift()();
  else slots++;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function slugifyDomain(url) {
  try {
    const host = new URL(/^https?:\/\//i.test(url) ? url : 'https://' + url).hostname;
    return host.replace(/^www\./i, '').replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  } catch {
    return url.replace(/[^a-z0-9]+/g, '-').toLowerCase().slice(0, 80);
  }
}

function normalizeUrl(url) {
  if (!url) return '';
  return /^https?:\/\//i.test(url) ? url : 'https://' + url;
}

// ─── Main export ──────────────────────────────────────────────────────────────
export async function takeScreenshot(rawUrl) {
  const url = normalizeUrl(rawUrl);
  if (!url) return { status: 'screenshot_failed', path: '' };

  await acquire();
  let browser;
  try {
    const filename = slugifyDomain(url) + '.png';
    const filepath = join(SCREENSHOT_DIR, filename);

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
      userAgent: USER_AGENT,
      viewport: VIEWPORT,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    const page = await context.newPage();

    let buf = null;

    // Strategy 1: domcontentloaded + 3s wait (most reliable across all sites)
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MS });
      await page.waitForTimeout(3000);
      buf = await page.screenshot({ clip: { x: 0, y: 0, width: 1280, height: 900 } });
    } catch (e1) {
      // Strategy 2: load event (works for simpler/faster sites)
      try {
        await page.goto(url, { waitUntil: 'load', timeout: TIMEOUT_MS });
        buf = await page.screenshot({ clip: { x: 0, y: 0, width: 1280, height: 900 } });
      } catch (e2) {
        // Strategy 3: http:// fallback (some sites reject https in headless browsers)
        if (url.startsWith('https://')) {
          const httpUrl = url.replace('https://', 'http://');
          try {
            await page.goto(httpUrl, { waitUntil: 'domcontentloaded', timeout: TIMEOUT_MS });
            await page.waitForTimeout(3000);
            buf = await page.screenshot({ clip: { x: 0, y: 0, width: 1280, height: 900 } });
          } catch {}
        }
      }
    }

    if (!buf) {
      console.error(`[screenshot] All strategies failed for ${url}`);
      return { status: 'screenshot_failed', path: '' };
    }

    await writeFile(filepath, buf);
    return { status: 'success', path: 'screenshots/' + filename };

  } catch (e) {
    console.error(`[screenshot] Failed for ${url}: ${e.message}`);
    return { status: 'screenshot_failed', path: '' };
  } finally {
    if (browser) try { await browser.close(); } catch {}
    release();
  }
}
