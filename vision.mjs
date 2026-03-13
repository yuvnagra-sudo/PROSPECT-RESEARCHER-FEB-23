// vision.mjs — Gemini Vision analysis for website screenshots
import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { resolve } from 'path';

/**
 * Analyze a website screenshot using Gemini Vision.
 * @param {string} screenshotPath - Relative path like "screenshots/domain.png"
 * @param {string} apiKey - Gemini API key
 * @returns {Promise<string>} Analysis text, or empty string on failure
 */
export async function callGeminiVision(screenshotPath, apiKey) {
  const absPath = resolve(process.cwd(), screenshotPath);
  if (!existsSync(absPath)) return '';
  let imgBuf;
  try { imgBuf = await readFile(absPath); } catch { return ''; }
  const b64 = imgBuf.toString('base64');

  const model = 'gemini-3-flash-preview';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const body = {
    contents: [{ parts: [
      { text: `You are a professional web design and conversion rate expert. Analyze this website screenshot and provide:

1. First impression and visual quality (professional/amateur, modern/dated)
2. Above-the-fold content — is the value proposition clear?
3. Calls to action — visible and compelling?
4. Layout and whitespace — clean or cluttered?
5. Mobile-friendliness indicators visible in the design
6. Trust signals present (logos, testimonials, certifications, social proof)
7. Top 3 specific improvement recommendations to convert more B2B leads
8. Overall visual score out of 10

Be direct and specific. Output plain text, no markdown headers.` },
      { inlineData: { mimeType: 'image/png', data: b64 } }
    ] }],
    generationConfig: { maxOutputTokens: 1200, thinkingConfig: { thinkingLevel: 'none' } }
  };

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 60000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: ac.signal
    });
    clearTimeout(timer);
    if (!res.ok) return '';
    const data = await res.json();
    const parts = data.candidates?.[0]?.content?.parts || [];
    return parts.filter(p => typeof p.text === 'string' && !p.thought).map(p => p.text).join('\n').trim();
  } catch { clearTimeout(timer); return ''; }
}
