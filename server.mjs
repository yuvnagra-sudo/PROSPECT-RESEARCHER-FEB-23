#!/usr/bin/env node
import { createServer } from 'http';
import { readFileSync, existsSync, mkdirSync } from 'fs';
import { resolve, join } from 'path';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import Database from 'better-sqlite3';

// .env loader
try { const ep=resolve(process.cwd(),'.env'); if(existsSync(ep)) readFileSync(ep,'utf8').split('\n').forEach(l=>{const m=l.match(/^\s*([^#=]+?)\s*=\s*(.*?)\s*$/);if(m&&!process.env[m[1]])process.env[m[1]]=m[2].replace(/^["']|["']$/g,'');}); } catch{}

const JWT_SECRET = process.env.JWT_SECRET || randomBytes(32).toString('hex');

// ─── Database ───
const DD=resolve(process.cwd(),'.data'); if(!existsSync(DD))mkdirSync(DD,{recursive:true});
const db=new Database(join(DD,'prospect_research.db')); db.pragma('journal_mode=WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,name TEXT,created_at TEXT DEFAULT(datetime('now')));
CREATE TABLE IF NOT EXISTS user_keys(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,key_name TEXT NOT NULL,key_value TEXT NOT NULL,FOREIGN KEY(user_id)REFERENCES users(id),UNIQUE(user_id,key_name));
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL DEFAULT 0,name TEXT,provider TEXT,template_id TEXT,system_prompt TEXT,use_web_search INT DEFAULT 1,col_map TEXT,total_rows INT,succeeded INT DEFAULT 0,failed INT DEFAULT 0,status TEXT DEFAULT 'queued',total_in INT DEFAULT 0,total_out INT DEFAULT 0,total_cr INT DEFAULT 0,total_cw INT DEFAULT 0,cost REAL DEFAULT 0,elapsed REAL DEFAULT 0,created_at TEXT DEFAULT(datetime('now')),updated_at TEXT DEFAULT(datetime('now')),FOREIGN KEY(user_id)REFERENCES users(id));
CREATE TABLE IF NOT EXISTS rows(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id INT,idx INT,company TEXT,prompt TEXT,status TEXT DEFAULT 'pending',research TEXT,error TEXT,input_tokens INT DEFAULT 0,output_tokens INT DEFAULT 0,cache_read INT DEFAULT 0,cache_write INT DEFAULT 0,FOREIGN KEY(job_id)REFERENCES jobs(id),UNIQUE(job_id,idx));
CREATE INDEX IF NOT EXISTS idx_rj ON rows(job_id,idx);
CREATE INDEX IF NOT EXISTS idx_rs ON rows(job_id,status);
CREATE INDEX IF NOT EXISTS idx_ju ON jobs(user_id);`);
try{db.exec(`ALTER TABLE jobs ADD COLUMN user_id INTEGER DEFAULT 0`);}catch{}
try{db.exec(`ALTER TABLE jobs ADD COLUMN sections_json TEXT`);}catch{}
try{db.exec(`ALTER TABLE rows ADD COLUMN quality INT DEFAULT 0`);}catch{}

// ─── Auth helpers ───
function hashPw(pw){const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(pw,salt,64).toString('hex');}
function verifyPw(pw,stored){const[salt,hash]=stored.split(':');return timingSafeEqual(scryptSync(pw,salt,64),Buffer.from(hash,'hex'));}
function base64url(buf){return(typeof buf==='string'?Buffer.from(buf):buf).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');}
function jwtSign(payload){const h=base64url(JSON.stringify({alg:'HS256',typ:'JWT'}));const b=base64url(JSON.stringify({...payload,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+604800}));return h+'.'+b+'.'+base64url(createHmac('sha256',JWT_SECRET).update(h+'.'+b).digest());}
function jwtVerify(token){try{const[h,b,s]=token.split('.');if(s!==base64url(createHmac('sha256',JWT_SECRET).update(h+'.'+b).digest()))return null;const p=JSON.parse(Buffer.from(b,'base64url').toString());return p.exp&&p.exp<Math.floor(Date.now()/1000)?null:p;}catch{return null;}}
function getUser(req){const a=req.headers.authorization;return a?.startsWith('Bearer ')?jwtVerify(a.slice(7)):null;}

// ─── Prepared statements ───
const S={
  createUser:db.prepare(`INSERT INTO users(email,password_hash,name)VALUES(?,?,?)`),
  getUserByEmail:db.prepare(`SELECT*FROM users WHERE email=?`),
  getUserById:db.prepare(`SELECT id,email,name,created_at FROM users WHERE id=?`),
  setUserKey:db.prepare(`INSERT OR REPLACE INTO user_keys(user_id,key_name,key_value)VALUES(?,?,?)`),
  getUserKey:db.prepare(`SELECT key_value FROM user_keys WHERE user_id=? AND key_name=?`),
  delUserKey:db.prepare(`DELETE FROM user_keys WHERE user_id=? AND key_name=?`),
  getUserKeys:db.prepare(`SELECT key_name FROM user_keys WHERE user_id=?`),
  iJ:db.prepare(`INSERT INTO jobs(user_id,name,provider,template_id,system_prompt,use_web_search,col_map,total_rows,sections_json)VALUES(?,?,?,?,?,?,?,?,?)`),
  uJ:db.prepare(`UPDATE jobs SET succeeded=?,failed=?,status=?,total_in=?,total_out=?,total_cr=?,total_cw=?,cost=?,elapsed=?,updated_at=datetime('now')WHERE id=?`),
  gJ:db.prepare(`SELECT*FROM jobs WHERE id=?`),
  lJ:db.prepare(`SELECT id,name,provider,template_id,total_rows,succeeded,failed,status,cost,elapsed,created_at FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 50`),
  dJ:db.prepare(`DELETE FROM jobs WHERE id=? AND user_id=?`),
  iR:db.prepare(`INSERT INTO rows(job_id,idx,company,prompt)VALUES(?,?,?,?)`),
  uR:db.prepare(`UPDATE rows SET status=?,research=?,error=?,input_tokens=?,output_tokens=?,cache_read=?,cache_write=? WHERE job_id=? AND idx=?`),
  gR:db.prepare(`SELECT*FROM rows WHERE job_id=? ORDER BY idx`),
  gP:db.prepare(`SELECT*FROM rows WHERE job_id=? AND status='pending' ORDER BY idx`),
  gC:db.prepare(`SELECT*FROM rows WHERE job_id=? AND status IN('success','error')ORDER BY idx`),
  dR:db.prepare(`DELETE FROM rows WHERE job_id=?`),
};
function userKey(uid,keyName){const r=S.getUserKey.get(uid,keyName);return r?.key_value||'';}

// ─── Providers ───
const PROVDEFS={
  gemini:{name:'Gemini 2.5 Flash',model:'gemini-2.5-flash',inputCost:0.15,outputCost:0.60,format:'gemini-native',webSearch:true,webCostPerCall:0.035,envName:'GEMINI_API_KEY'},
  claude:{name:'Claude Sonnet 4',model:'claude-sonnet-4-20250514',apiUrl:'https://api.anthropic.com/v1/messages',inputCost:3,outputCost:15,format:'anthropic',webSearch:true,webCostPerCall:0.015,cacheReadCost:0.30,cacheWriteCost:3.75,envName:'ANTHROPIC_API_KEY'},
  haiku:{name:'Claude Haiku 4.5',model:'claude-haiku-4-5-20251001',apiUrl:'https://api.anthropic.com/v1/messages',inputCost:1,outputCost:5,format:'anthropic',webSearch:true,webCostPerCall:0.005,cacheReadCost:0.10,cacheWriteCost:1.25,envName:'ANTHROPIC_API_KEY'},
  gpt5:{name:'GPT-5',model:'gpt-5',apiUrl:'https://api.openai.com/v1/chat/completions',inputCost:1.25,outputCost:10,format:'openai',webSearch:true,webTool:'openai',webCostPerCall:0.018,envName:'OPENAI_API_KEY'},
  openai:{name:'GPT-4o Mini',model:'gpt-4o-mini',apiUrl:'https://api.openai.com/v1/chat/completions',inputCost:0.15,outputCost:0.60,format:'openai',webSearch:false,webCostPerCall:0,envName:'OPENAI_API_KEY'},
  deepseek:{name:'DeepSeek V3',model:'deepseek-chat',apiUrl:'https://api.deepseek.com/v1/chat/completions',inputCost:0.56,outputCost:1.68,format:'openai',webSearch:false,webCostPerCall:0,envName:'DEEPSEEK_API_KEY'},
};
function provSt(uid){const a={};const uk=S.getUserKeys.all(uid).map(r=>r.key_name);for(const[id,p]of Object.entries(PROVDEFS))a[id]={name:p.name,hasKey:uk.includes(p.envName),inputCost:p.inputCost,outputCost:p.outputCost,webSearch:p.webSearch,webCostPerCall:p.webCostPerCall||0};return a;}

// ─── Templates ───
const TEMPLATES={
'b2b-outreach':{name:'B2B Sales Outreach',icon:'\u{1F4E7}',desc:'Pain points, triggers, and personalization hooks for cold email',
sections:[
  {key:'company_snapshot',label:'Company Snapshot'},
  {key:'recent_triggers',label:'Recent Triggers'},
  {key:'pain_points',label:'Pain Points'},
  {key:'personalization_hooks',label:'Personalization Hooks'},
  {key:'outreach_angle',label:'Outreach Angle'}
],
prompt:`You are an expert B2B sales researcher. For each prospect, provide:
1. **Company Snapshot** (2-3 sentences) - What they do, who they serve, approximate size
2. **Recent Triggers** - Funding, launches, leadership changes, expansions, hiring surges from last 6 months
3. **Pain Points** (2-3) - Specific operational challenges. Be specific: not "need better marketing" but "scaling from 20-50 employees typically breaks onboarding"
4. **Personalization Hooks** (2-3) - Concrete things to reference in a cold email opener. Include source (LinkedIn post, press release, job listing)
5. **Outreach Angle** - One recommended angle: specific pain + how to frame solution. Write a sample opening line.
Be specific and actionable. Generic research is useless for cold email.`},
'vc-research':{name:'VC / PE Due Diligence',icon:'\u{1F4B0}',desc:'Investment thesis, check sizes, stages, constraints, 2025 portfolio',
sections:[
  {key:'investment_niche',label:'Investment Niche'},
  {key:'check_size_stages',label:'Check Size & Stages'},
  {key:'investment_constraints',label:'Investment Constraints'},
  {key:'portfolio_activity',label:'Portfolio Activity'},
  {key:'contact_process',label:'Contact & Process'},
  {key:'confidence_score',label:'Confidence Score'}
],
prompt:`You are a capital raising research assistant. Research this company and determine:
Is this company investing into startup companies (VC, PE, Angel Group, Accelerator)? If NOT, return only "Not an Investor" and stop.
If they ARE an investor:
1. **Investment Niche** - Thesis, sectors, focus areas
2. **Check Size & Stages** - Average check range, stages (pre-seed through growth)
3. **Investment Constraints** - Geography, founder demographics, industry exclusions, minimum revenue
4. **2025 Portfolio Activity** - List: date, company name, round type, brief description
5. **Contact & Process** - How to reach them, cold inbound, application process
CONFIDENCE SCORE:
- Investment Niche: [Low/Medium/High]
- Data Richness: [Low/Medium/High]
- Investor Type: [VC/PE/Angel/Accelerator/Family Office/CVC/Not an Investor]`},
'real-estate':{name:'Real Estate Agent Prospecting',icon:'\u{1F3E0}',desc:'Transaction volume, online presence gaps, marketing pain points',
sections:[
  {key:'agent_profile',label:'Agent Profile'},
  {key:'market_activity',label:'Market Activity'},
  {key:'online_presence_audit',label:'Online Presence Audit'},
  {key:'pain_points',label:'Pain Points'},
  {key:'personalization_hook',label:'Personalization Hook'},
  {key:'outreach_recommendation',label:'Outreach Recommendation'}
],
prompt:`You are a real estate industry researcher for a marketing agency. For each agent/brokerage:
1. **Agent Profile** - Name, brokerage, years active, designations
2. **Market Activity** - Recent listings, volume, price range, primary areas
3. **Online Presence Audit** - Website quality (1-10), social activity, review count/rating, video/blog
4. **Pain Points** (top 2-3): Lead gen beyond referrals, feast-or-famine deal flow, poor online presence vs competitors, time on admin vs selling, difficulty standing out, expired listings
5. **Personalization Hook** - One specific recent thing to reference
6. **Outreach Recommendation** - Best angle for a marketing agency`},
'local-business':{name:'Local Business Outreach',icon:'\u{1F3EA}',desc:'Online presence audit, competitor gaps, quick-win opportunities',
sections:[
  {key:'business_overview',label:'Business Overview'},
  {key:'online_presence_audit',label:'Online Presence Audit'},
  {key:'competitive_landscape',label:'Competitive Landscape'},
  {key:'gap_analysis',label:'Gap Analysis'},
  {key:'quick_win',label:'Quick Win'},
  {key:'outreach_hook',label:'Outreach Hook'}
],
prompt:`You are a local business marketing researcher. For each business:
1. **Business Overview** - What they do, years in business, locations, size
2. **Online Presence Audit**: Google Business (claimed? rating? reviews? response rate?), Website (exists? mobile? booking/ordering?), Social (platforms? frequency? engagement?), SEO (rank for "[service] near me"?)
3. **Competitive Landscape** - 2-3 direct local competitors, who is winning online and why
4. **Gap Analysis** (top 3): Missing GBP, low reviews vs competitors, no/outdated website, no online ordering, inactive social, not running ads, poor local SEO, unresponded negative reviews
5. **Quick Win** - Single most impactful 30-day action
6. **Outreach Hook** - Specific non-generic opener (reference a real review, competitor advantage, seasonal opportunity)`},
'saas-competitor':{name:'SaaS Competitor Analysis',icon:'\u2694\uFE0F',desc:'Pricing, positioning, strengths, vulnerabilities',
sections:[
  {key:'product_overview',label:'Product Overview'},
  {key:'pricing_packaging',label:'Pricing & Packaging'},
  {key:'market_position',label:'Market Position'},
  {key:'tech_stack_integrations',label:'Tech Stack & Integrations'},
  {key:'recent_moves',label:'Recent Moves'},
  {key:'strengths_vulnerabilities',label:'Strengths & Vulnerabilities'},
  {key:'sales_approach',label:'Sales Approach'}
],
prompt:`You are a SaaS competitive intelligence analyst. For each company:
1. **Product Overview** - Core product, target market, founding year, funding, total raised
2. **Pricing & Packaging** - Tiers, free plan, per-seat vs usage, published or "contact sales"
3. **Market Position** - Est. ARR/employee count, differentiators, G2/Capterra rating, notable customers
4. **Tech Stack & Integrations** - Key integrations, API, platform
5. **Recent Moves** (12 months) - Launches, acquisitions, partnerships, leadership, layoffs
6. **Strengths & Vulnerabilities** - Top 3 each from reviews/positioning, exploitable gaps
7. **Sales Approach** - PLG/sales-led/partner, content strategy, ad presence`},
'recruiting':{name:'Recruiting & Hiring Intel',icon:'\u{1F465}',desc:'Hiring velocity, hard-to-fill roles, culture, staffing pain points',
sections:[
  {key:'company_overview',label:'Company Overview'},
  {key:'hiring_velocity',label:'Hiring Velocity'},
  {key:'key_open_roles',label:'Key Open Roles'},
  {key:'culture_employer_brand',label:'Culture & Employer Brand'},
  {key:'hiring_pain_points',label:'Hiring Pain Points'},
  {key:'outreach_recommendation',label:'Outreach Recommendation'}
],
prompt:`You are a recruiting industry researcher. For each company:
1. **Company Overview** - What they do, size, growth stage, HQ, recent milestones
2. **Hiring Velocity** - Open roles count, top-hiring departments, trend vs 3-6 months ago
3. **Key Open Roles** - Most critical positions, long-open or reposted ones
4. **Culture & Employer Brand** - Glassdoor rating, review themes, remote policy, perks/concerns
5. **Hiring Pain Points** (top 2-3): Scaling post-funding, high turnover, competing for talent, niche roles, leadership building, geographic limits
6. **Outreach Recommendation** - Best angle for recruiter/staffing firm, sample opening line`},
'website-audit':{name:'Website Services Prospecting',icon:'\u{1F310}',desc:'Website audit, technical issues, and pain points for web agency outreach',
sections:[
  {key:'company_snapshot',label:'Company Snapshot'},
  {key:'website_audit',label:'Website Audit'},
  {key:'issue_1',label:'Issue 1'},
  {key:'issue_2',label:'Issue 2'},
  {key:'issue_3',label:'Issue 3'},
  {key:'pain_points',label:'Pain Points'}
],
prompt:`You are an expert B2B sales researcher selling website services (design, development, SEO, security, performance optimization). For each prospect, provide:
1. **Company Snapshot** (2-3 sentences) - What they do, who they serve, approximate size
2. **Website Audit** - Visit their website and provide a technical surface-level analysis covering SEO health (meta tags, headings, structured data), security indicators (HTTPS, mixed content), and performance observations (page weight, render speed, mobile responsiveness). Be specific with what you observe.
3. **Issue 1** - The single most impactful technical website issue you found. Be very specific: name the exact problem, where it appears, and the business impact (e.g. "Missing H1 tag on homepage forces Google to guess page topic, likely costing organic rankings for their primary service keywords").
4. **Issue 2** - The second most impactful website issue. Same level of specificity.
5. **Issue 3** - The third most impactful website issue. Same level of specificity.
6. **Pain Points** (2-3) - Specific operational challenges this business likely faces. Be specific: not "need better marketing" but "as a 15-person agency scaling past founder-led sales, they likely struggle with consistent lead generation beyond referrals."
Be specific and actionable. Generic research is useless for cold email. Every observation should reference something concrete from their actual website or business.`},
'custom':{name:'Custom Prompt',icon:'\u270F\uFE0F',desc:'Write your own research prompt',
sections:[],
prompt:`You are an expert B2B sales researcher. For each prospect, provide:\n1. **Company Overview** (2-3 sentences)\n2. **Recent News & Activity** (2-3 points)\n3. **Pain Points & Opportunities** (2-3 points)\n4. **Personalization Hooks** (2-3 suggestions)\n5. **Outreach Recommendation**\nKeep responses concise but actionable.`}
};

// ─── Rate Limit Intelligence ───
const rl={};
function gRL(p){if(!rl[p])rl[p]={delay:1000,min:300,max:60000,okRun:0,hits:0};return rl[p];}
function rlHit(p,retryMs){const r=gRL(p);r.okRun=0;r.hits++;r.delay=retryMs&&retryMs>r.delay?Math.min(retryMs*1.2,r.max):Math.min(r.delay*2,r.max);return r.delay;}
function rlOk(p){const r=gRL(p);r.okRun++;if(r.okRun>=5&&r.delay>r.min){r.delay=Math.max(r.delay*0.8,r.min);r.okRun=0;}}

// ─── LLM Callers ───
async function callGemini(prompt,prov,sys,web,apiKey){
  const url=`https://generativelanguage.googleapis.com/v1beta/models/${prov.model}:generateContent?key=${apiKey}`;
  const body={
    systemInstruction:{parts:[{text:sys}]},
    contents:[{parts:[{text:prompt}]}],
    generationConfig:{
      maxOutputTokens:16000,        // raised — 4000 was too low when thinking tokens consume budget
      thinkingConfig:{thinkingBudget:0}  // disable thinking: faster + no hidden token consumption
    }
  };
  if(web)body.tools=[{google_search:{}}];
  const res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  if(res.status===429){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}
    if(m.includes('quota')||m.includes('limit: 0')||m.includes('RESOURCE_EXHAUSTED'))throw{type:'api_error',message:'Gemini quota exhausted'};
    const rm=m.match(/retry in ([\d.]+)s/i);throw{type:'rate_limit',wait:rm?Math.ceil(parseFloat(rm[1]))*1000:30000};}
  if(!res.ok){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}throw{type:'api_error',message:m};}
  const data=await res.json();

  const candidate=data.candidates?.[0];
  const finishReason=candidate?.finishReason;
  const parts=candidate?.content?.parts||[];
  const u=data.usageMetadata||{};

  // Collect ALL text parts (ignore executableCode, toolUse, etc.) and join before stripping citations.
  // Never select a single "clean" part — the first citation-free chunk is usually just the
  // pages-checked header, which would silently discard the entire rest of the response.
  const allTexts=parts.filter(p=>typeof p.text==='string'&&p.text.trim()).map(p=>p.text);
  const research=allTexts.join('\n').replace(/\s*\[cite:\s*[\d,\s]+\]/g,'').trim();

  // If Gemini stopped because it hit the token limit, treat as retriable error
  if(finishReason==='MAX_TOKENS'){
    throw{type:'api_error',message:`Gemini hit MAX_TOKENS limit (output was ${u.candidatesTokenCount} tokens) — retrying with fresh request.`};
  }

  // Empty response with no output tokens — retry
  if(!research&&(u.candidatesTokenCount||0)===0){
    throw{type:'api_error',message:'Gemini returned empty response — possible grounding-only output. Will retry.'};
  }

  return{research,inputTokens:u.promptTokenCount||0,outputTokens:u.candidatesTokenCount||0,cacheRead:0,cacheWrite:0};
}

async function callAnthropic(prompt,prov,sys,web,apiKey){
  const body={model:prov.model,max_tokens:4000,system:[{type:'text',text:sys,cache_control:{type:'ephemeral'}}],messages:[{role:'user',content:prompt}]};
  if(web)body.tools=[{type:'web_search_20250305',name:'web_search'}];
  const res=await fetch(prov.apiUrl,{method:'POST',headers:{'x-api-key':apiKey,'anthropic-version':'2023-06-01','content-type':'application/json'},body:JSON.stringify(body)});
  if(res.status===429||res.status===529)throw{type:'rate_limit',wait:30000};
  if(!res.ok){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}throw{type:'api_error',message:m};}
  const data=await res.json();const u=data.usage||{};
  return{research:(data.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('\n'),inputTokens:u.input_tokens||0,outputTokens:u.output_tokens||0,cacheRead:u.cache_read_input_tokens||0,cacheWrite:u.cache_creation_input_tokens||0};
}
async function callOpenAI(prompt,prov,sys,web,apiKey){
  const tk=prov.model.startsWith('gpt-5')?'max_completion_tokens':'max_tokens';
  const body={model:prov.model,[tk]:4000,messages:[{role:'system',content:sys},{role:'user',content:prompt}]};
  if(prov.webTool==='openai'&&web)body.tools=[{type:'web_search_preview'}];
  const res=await fetch(prov.apiUrl,{method:'POST',headers:{'content-type':'application/json','authorization':`Bearer ${apiKey}`},body:JSON.stringify(body)});
  if(res.status===429)throw{type:'rate_limit',wait:30000};
  if(!res.ok){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}throw{type:'api_error',message:m};}
  const data=await res.json();const c=data.choices?.[0];const u=data.usage||{};
  return{research:typeof c?.message?.content==='string'?c.message.content:'',inputTokens:u.prompt_tokens||0,outputTokens:u.completion_tokens||0,cacheRead:0,cacheWrite:0};
}
function callLLM(p,prov,sys,web,apiKey){
  if(prov.format==='gemini-native')return callGemini(p,prov,sys,web,apiKey);
  if(prov.format==='anthropic')return callAnthropic(p,prov,sys,web,apiKey);
  return callOpenAI(p,prov,sys,web,apiKey);
}

// ─── Structured Output Helpers ───

// Extract section definitions from any prompt text (for custom prompts)
function extractSectionsFromPrompt(promptText){
  if(!promptText)return[];
  const sections=[];const seen=new Set();
  const addSec=(rawLabel)=>{
    const label=rawLabel.replace(/\*\*/g,'').replace(/\s*\(.*$/,'').replace(/[-:]+$/,'').trim();
    if(!label||label.length<2||label.length>60)return;
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  };
  // Strategy 0: numbered items — any "N. <text>" line, strips all ** markers post-hoc
  // Handles: "1. **Company Snapshot** (2-3 sentences)", "3. Issue 1 from **Website Audit**", "2. Website Audit - Provide..."
  let m;
  const numberedAny=/(?:^|\n)\s*\d+\.\s+(.+?)(?:\n|$)/g;
  while((m=numberedAny.exec(promptText))!==null)addSec(m[1]);
  if(sections.length>=2)return sections;
  // Strategy 1: numbered bold — e.g. "1. **Company Snapshot**" or "1. **Company Snapshot** (2-3 sentences)"
  sections.length=0;seen.clear();
  const numberedBold=/(?:^|\n)\s*(\d+)\.\s*\*\*(.+?)\*\*/g;
  while((m=numberedBold.exec(promptText))!==null){
    const label=m[2].replace(/\s*\(.*$/, '').replace(/[-:]+$/, '').trim();
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  }
  if(sections.length>=2)return sections;
  // Strategy 2: bold with colon — e.g. "**Section Name:**" or "**Section Name** -"
  sections.length=0;seen.clear();
  const boldColon=/(?:^|\n)\s*\*\*(.+?)\*\*\s*[-:]/g;
  while((m=boldColon.exec(promptText))!==null){
    const label=m[1].replace(/\s*\(.*$/, '').replace(/^\d+\.\s*/, '').trim();
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  }
  if(sections.length>=2)return sections;
  // Strategy 3: numbered plain — e.g. "1. Section Name -" or "1. Section Name:"
  sections.length=0;seen.clear();
  const numberedPlain=/(?:^|\n)\s*(\d+)\.\s+([A-Z][^.\n]{2,40})(?:\s*[-:(]|\s*$)/gm;
  while((m=numberedPlain.exec(promptText))!==null){
    const label=m[2].replace(/\s*[-:(].*$/, '').trim();
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  }
  if(sections.length>=2)return sections;
  // Strategy 4: ALL-CAPS lines — e.g. "QUALIFICATION", "DECISION MAKERS"
  sections.length=0;seen.clear();
  const capsLine=/(?:^|\n)\s*([A-Z][A-Z\s&\-\/]{3,50})\s*(?:\(.*?\))?\s*$/gm;
  while((m=capsLine.exec(promptText))!==null){
    const txt=m[1].trim();
    if(txt===txt.toUpperCase()&&txt.length>=4){
      const label=txt;
      const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
      if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
    }
  }
  if(sections.length>=2)return sections;
  // Strategy 5: markdown ### or ## headers — e.g. "### Section Name"
  sections.length=0;seen.clear();
  const mdHeaders=/(?:^|\n)\s*#{1,3}\s+\*{0,2}(.+?)\*{0,2}\s*$/gm;
  while((m=mdHeaders.exec(promptText))!==null){
    const label=m[1].replace(/\s*\(.*$/,'').replace(/[-:]+$/,'').trim();
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  }
  if(sections.length>=2)return sections;
  // Strategy 6: standalone bold lines — e.g. "**Section Name**" on its own line
  sections.length=0;seen.clear();
  const boldLine=/(?:^|\n)\s*\*\*([^*\n]{3,50})\*\*\s*$/gm;
  while((m=boldLine.exec(promptText))!==null){
    const label=m[1].replace(/\s*\(.*$/,'').replace(/[-:]+$/,'').trim();
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  }
  return sections.length>=2?sections:[];
}

// Detect sections from LLM output text (universal fallback for any prompt)
function extractSectionsFromOutput(rawText){
  if(!rawText)return[];
  const sections=[];const seen=new Set();
  const addSec=(label)=>{
    label=label.replace(/\s*\(.*?\)\s*$/,'').replace(/[-:]+$/,'').trim();
    if(!label||label.length<2||label.length>60)return;
    const key=label.toLowerCase().replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,'_').slice(0,40);
    if(key&&key.length>1&&!seen.has(key)){seen.add(key);sections.push({key,label});}
  };
  let m;

  // Strategy A: markdown ### or ## headers
  const mdHeaders=/(?:^|\n)\s*#{1,3}\s+\*{0,2}(.+?)\*{0,2}\s*$/gm;
  while((m=mdHeaders.exec(rawText))!==null)addSec(m[1]);
  if(sections.length>=2)return sections;

  // Strategy B: numbered bold — "1. **Section Name**" or "**1. Section Name**"
  sections.length=0;seen.clear();
  const numBold=/(?:^|\n)\s*(?:\*\*\s*)?\d+[.)]\s*\*{0,2}([^*\n]{3,50})\*{0,2}/g;
  while((m=numBold.exec(rawText))!==null)addSec(m[1]);
  if(sections.length>=2)return sections;

  // Strategy C: standalone bold lines — "**SECTION NAME**" on its own line
  sections.length=0;seen.clear();
  const boldLine=/(?:^|\n)\s*\*\*([^*\n]{3,50})\*\*\s*$/gm;
  while((m=boldLine.exec(rawText))!==null){
    const txt=m[1].trim();
    // Skip lines that look like field labels (short with colon)
    if(txt.includes(':')||txt.length<4)continue;
    addSec(txt);
  }
  if(sections.length>=2)return sections;

  // Strategy D: ALL-CAPS lines (>=2 words, all uppercase letters)
  sections.length=0;seen.clear();
  const capsLine=/(?:^|\n)\s*([A-Z][A-Z\s&\-\/]{3,50})\s*(?:\(.*?\))?\s*$/gm;
  while((m=capsLine.exec(rawText))!==null){
    const txt=m[1].trim();
    if(txt===txt.toUpperCase()&&txt.split(/\s+/).length>=1&&txt.length>=4)addSec(txt);
  }
  if(sections.length>=2)return sections;

  // Strategy E: "---" separator followed by "### Header" (common LLM pattern)
  sections.length=0;seen.clear();
  const hrHeaders=/---\s*\n+\s*#{1,3}\s+\*{0,2}(.+?)\*{0,2}\s*$/gm;
  while((m=hrHeaders.exec(rawText))!==null)addSec(m[1]);
  if(sections.length>=2)return sections;

  return[];
}

// Wrap system prompt to request JSON output
function wrapPromptForStructuredOutput(systemPrompt,sections){
  if(!sections||!sections.length)return systemPrompt;
  const keyList=sections.map(s=>`"${s.key}"`).join(', ');
  const sampleObj={};sections.forEach(s=>{sampleObj[s.key]=`[Your ${s.label} content here]`;});
  const sampleJson=JSON.stringify(sampleObj,null,2);
  return systemPrompt+`

CRITICAL OUTPUT FORMAT INSTRUCTIONS:
1. Return your response as a single valid JSON object.
2. Use EXACTLY these keys: ${keyList}
3. Each value MUST be a plain text string. No markdown formatting (no **, no ##, no bullet points).
4. If information for a section is unavailable, write "No data found" instead of leaving it empty.
5. Do NOT wrap the JSON in code fences or add any text before or after it.
6. Keep each section concise (2-4 sentences or a short paragraph) unless the prompt specifies otherwise.
7. For lists, use semicolons to separate items (e.g. "Item 1; Item 2; Item 3").

Example format:
${sampleJson}`;
}

// Parse LLM response into structured sections (multi-layer, robust)
function parseStructuredResponse(rawText,sections){
  if(!rawText)return{_raw:'',_parsed:false};
  if(!sections||!sections.length)return{_raw:rawText,_parsed:false};

  // Layer 1: Try JSON parse
  let cleaned=rawText.trim();
  // Strip markdown code fences
  cleaned=cleaned.replace(/^```(?:json)?\s*\n?/i,'').replace(/\n?\s*```\s*$/,'').trim();
  const jsonVal=v=>{
    if(typeof v==='string')return v.trim();
    if(Array.isArray(v))return v.map(x=>typeof x==='string'?x.trim():JSON.stringify(x)).join('; ');
    if(typeof v==='object'&&v!==null)return Object.entries(v).map(([k,x])=>`${k}: ${x}`).join('; ');
    return String(v);
  };
  try{
    const parsed=JSON.parse(cleaned);
    if(typeof parsed==='object'&&parsed!==null){
      const result={_raw:rawText,_parsed:true};
      let hits=0;
      // Exact key match first
      for(const s of sections){
        if(parsed[s.key]!==undefined){result[s.key]=jsonVal(parsed[s.key]);hits++;}
        else result[s.key]='';
      }
      if(hits>=Math.ceil(sections.length/2))return result;
      // Fuzzy key match: normalize keys and try substring matching
      const pKeys=Object.keys(parsed).filter(k=>!k.startsWith('_'));
      const normLookup={};
      for(const pk of pKeys)normLookup[pk.toLowerCase().replace(/[^a-z0-9]/g,'')]=pk;
      for(const s of sections){
        if(result[s.key])continue;
        const normKey=s.key.replace(/[^a-z0-9]/g,'');
        const match=normLookup[normKey]||pKeys.find(pk=>{const n=pk.toLowerCase().replace(/[^a-z0-9]/g,'');return n.includes(normKey)||normKey.includes(n);})||null;
        if(match&&parsed[match]!==undefined){result[s.key]=jsonVal(parsed[match]);hits++;}
      }
      if(hits>=Math.ceil(sections.length/2))return result;
    }
  }catch{}

  // Layer 2: Flexible header matching by section label
  const normLabel=l=>l.toLowerCase().replace(/&/g,'and').replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,' ').trim();
  const buildPatterns=(lbl,num)=>{
    const eLbl=lbl.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    return[
      new RegExp(`(?:^|\\n)\\s*(?:\\*\\*\\s*)?${num}\\.?\\s*\\*?\\*?\\s*${eLbl}[^\\n]*`,'i'),
      new RegExp(`(?:^|\\n)\\s*(?:#{1,3}\\s*)?(?:\\*\\*)?\\s*${eLbl}\\s*(?:\\*\\*)?\\s*[-:.)]*[^\\n]*`,'i'),
      new RegExp(`(?:^|\\n)\\s*\\*\\*${eLbl}\\*\\*\\s*$`,'im'),
      new RegExp(`(?:^|\\n)\\s*${eLbl}\\s*$`,'im'),
    ];
  };
  const result={_raw:rawText,_parsed:true};
  let matchCount=0;
  for(let i=0;i<sections.length;i++){
    const s=sections[i];const num=i+1;
    const patterns=buildPatterns(s.label,num);
    let hMatch=null;
    for(const pat of patterns){hMatch=rawText.match(pat);if(hMatch)break;}
    if(!hMatch){result[s.key]='';continue;}
    const startIdx=hMatch.index+hMatch[0].length;
    // Find end: next section header or end of text
    let endIdx=rawText.length;
    for(let j=i+1;j<sections.length;j++){
      const nPats=buildPatterns(sections[j].label,j+1);
      let nMatch=null;
      for(const np of nPats){nMatch=rawText.slice(startIdx).match(np);if(nMatch)break;}
      if(nMatch){endIdx=startIdx+nMatch.index;break;}
    }
    result[s.key]=rawText.slice(startIdx,endIdx).trim();
    if(result[s.key])matchCount++;
  }
  if(matchCount>=Math.ceil(sections.length/3))return result;

  // Layer 3: Split by any numbered pattern and assign by order
  const numSplit=rawText.split(/(?:^|\n)\s*\d+\.\s/);
  if(numSplit.length>1){
    const chunks=numSplit.slice(1); // first element is preamble
    const result3={_raw:rawText,_parsed:true};
    for(let i=0;i<sections.length;i++){
      result3[sections[i].key]=i<chunks.length?chunks[i].replace(/^\*\*[^*]+\*\*\s*[-:]?\s*/,'').trim():'';
    }
    return result3;
  }

  // Layer 4: Nothing worked — single column fallback
  return{_raw:rawText,_parsed:false};
}

// Quality scoring for research results (0-100)
function scoreQuality(parsed,sections){
  if(!parsed||!sections||!sections.length)return 0;
  if(!parsed._parsed)return 10;
  const filled=sections.filter(s=>parsed[s.key]&&parsed[s.key].trim().length>10);
  const fillRate=filled.length/sections.length;
  let score=0;
  score+=fillRate*40; // section fill rate
  const avgLen=filled.reduce((sum,s)=>sum+parsed[s.key].length,0)/Math.max(filled.length,1);
  score+=Math.min(avgLen/100,1)*30; // content richness
  score+=parsed._parsed?20:0; // parsed successfully
  score+=fillRate===1?10:0; // no empty sections bonus
  return Math.round(score);
}

// Sanitize cell value for sequencer-ready CSV (strip markdown, collapse lists)
function sanitizeForCSV(text){
  if(!text||typeof text!=='string')return'';
  let s=text;
  s=s.replace(/\*\*(.+?)\*\*/g,'$1');s=s.replace(/\*(.+?)\*/g,'$1');
  s=s.replace(/__(.+?)__/g,'$1');s=s.replace(/_(.+?)_/g,'$1');
  s=s.replace(/^#{1,6}\s+/gm,'');
  s=s.replace(/(?:^|\n)\s*[-*+]\s+/g,'; ').replace(/^;\s*/,'');
  s=s.replace(/(?:^|\n)\s*\d+[.)]\s+/g,'; ').replace(/^;\s*/,'');
  s=s.replace(/\[([^\]]+)\]\([^)]+\)/g,'$1');
  s=s.replace(/```[\s\S]*?```/g,'');s=s.replace(/`([^`]+)`/g,'$1');
  s=s.replace(/\s+/g,' ').trim();
  s=s.replace(/^[;,\s]+/,'').replace(/[;,\s]+$/,'');
  return s;
}

// Safely parse research from DB (handles old string format + new JSON)
function safeParseResearch(text){
  if(!text)return null;
  try{const p=JSON.parse(text);if(typeof p==='object'&&p!==null)return p;}catch{}
  return{_raw:text,_parsed:false};
}

// Resolve sections for a job — tries explicit, prompt, template default, then first result output
function resolveSections(job,rows){
  // Priority 1: explicitly stored sections (from section editor)
  if(job.sections_json){try{const ex=JSON.parse(job.sections_json);if(Array.isArray(ex)&&ex.length>=2)return ex;}catch{}}
  // Priority 2: always try extracting from the actual system prompt first
  let secs=[];
  if(job.system_prompt)secs=extractSectionsFromPrompt(job.system_prompt);
  if(secs.length)return secs;
  // Priority 3: fall back to template hardcoded sections ONLY if prompt is unedited
  const tmpl=TEMPLATES[job.template_id];
  if(tmpl?.sections?.length&&tmpl.prompt===job.system_prompt)return tmpl.sections;
  // Priority 4: detect from first successful result
  const first=rows?rows.find(r=>r.status==='success'&&r.research):null;
  if(first){
    const parsed=safeParseResearch(first.research);
    if(parsed&&parsed._parsed){
      // Already structured JSON — extract keys as sections
      secs=Object.keys(parsed).filter(k=>!k.startsWith('_')).map(k=>({key:k,label:k.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}));
      if(secs.length>=2)return secs;
    }
    // Try detecting from raw output text
    const raw=parsed?._raw||first.research;
    secs=extractSectionsFromOutput(typeof raw==='string'?raw:JSON.stringify(raw));
    if(secs.length>=2)return secs;
  }
  return[];
}

// ─── CSV Parser (RFC 4180) ───
function parseCSV(text){
  if(text.charCodeAt(0)===0xfeff)text=text.slice(1);text=text.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
  const records=[];let cur=[];let field='';let inQ=false;
  for(let i=0;i<text.length;i++){const ch=text[i];
    if(inQ){if(ch==='"'){if(i+1<text.length&&text[i+1]==='"'){field+='"';i++;}else inQ=false;}else field+=ch;}
    else{if(ch==='"')inQ=true;else if(ch===','){cur.push(field.trim());field='';}else if(ch==='\n'){cur.push(field.trim());if(cur.length>1||cur[0]!=='')records.push(cur);cur=[];field='';}else field+=ch;}}
  cur.push(field.trim());if(cur.length>1||cur[0]!=='')records.push(cur);
  if(records.length<2)return{headers:[],rows:[]};
  const hdrs=records[0].map(h=>h.replace(/^["']|["']$/g,'').trim());const rows=[];
  for(let i=1;i<records.length;i++){const v=records[i];if(!v.length||(v.length===1&&!v[0]))continue;
    const row={};hdrs.forEach((h,idx)=>{row[h]=(v[idx]||'').replace(/^["']|["']$/g,'').trim();});rows.push(row);}
  return{headers:hdrs,rows};
}
const GUESSES={company:['company','company_name','business name','business','organization','name','firm','account'],website:['url','website','web','domain','site','webpage'],email:['email','email_address','e-mail','mail'],contact:['contact','contact_name','person','full name','first name'],title:['title','job_title','role','position','designation'],phone:['phone','telephone','tel','mobile','cell'],address:['address','location','city','street','region'],industry:['industry','sector','vertical','category','type','segment'],rating:['rating','score','stars'],reviews:['reviews','review count'],notes:['notes','additional_info','description','context','comments','bio']};
function autoGuess(headers){const map={};for(const[role,guesses]of Object.entries(GUESSES)){let found=null;
  for(const g of guesses){for(const h of headers){if(h.toLowerCase().trim()===g.toLowerCase()){found=h;break;}}if(found)break;}
  if(!found){for(const g of guesses){for(const h of headers){if(h.toLowerCase().trim().includes(g.toLowerCase())){found=h;break;}}if(found)break;}}
  map[role]=found||'';}return map;}
function buildPrompt(row,map,idx){
  const cl=v=>(v||'').replace(/^[\u00b7\u2022\s]+/,'').trim();
  const company=map.company?cl(row[map.company]):`Prospect ${idx+1}`;
  let url=map.website?cl(row[map.website]):'';let email=map.email?cl(row[map.email]):'';
  if(!url&&email&&(email.startsWith('http')||email.includes('www.')||/\.(com|ca|net|org|io)/.test(email))){url=email;email='';}
  let pr=`Research this prospect:\n\n**Company:** ${company}`;
  if(url)pr+=`\n**Website:** ${url}`;
  if(map.contact&&cl(row[map.contact]))pr+=`\n**Contact:** ${cl(row[map.contact])}`;
  if(map.title&&cl(row[map.title]))pr+=`\n**Title:** ${cl(row[map.title])}`;
  if(email)pr+=`\n**Email:** ${email}`;
  if(map.phone&&cl(row[map.phone]))pr+=`\n**Phone:** ${cl(row[map.phone])}`;
  if(map.address&&cl(row[map.address]))pr+=`\n**Address:** ${cl(row[map.address])}`;
  if(map.industry&&cl(row[map.industry]))pr+=`\n**Industry/Category:** ${cl(row[map.industry])}`;
  if(map.rating&&cl(row[map.rating]))pr+=`\n**Rating:** ${cl(row[map.rating])}`;
  if(map.reviews&&cl(row[map.reviews]))pr+=`\n**Reviews:** ${cl(row[map.reviews])}`;
  if(map.notes&&cl(row[map.notes]))pr+=`\n**Additional Context:** ${cl(row[map.notes])}`;
  // Include all unmapped CSV columns as additional context
  const usedHeaders=new Set(Object.values(map).filter(Boolean));
  for(const[header,value]of Object.entries(row)){
    if(!usedHeaders.has(header)&&value&&value.trim()&&value.trim().length>1)
      pr+=`\n**${header}:** ${cl(value)}`;
  }
  pr+='\n\nUse web search to find the most current information.';
  return{company,prompt:pr};
}

// ─── Job Runner (parallel worker pool) ───
const actv=new Map();

// How many concurrent requests to allow per provider
const CONCURRENCY={gemini:5,claude:5,haiku:5,gpt5:4,openai:5,deepseek:5};

async function runJob(jobId){
  const job=S.gJ.get(jobId);if(!job)return;const prov=PROVDEFS[job.provider];if(!prov)return;
  const apiKey=userKey(job.user_id,prov.envName);
  if(!apiKey){S.uJ.run(job.succeeded,job.failed,'error',0,0,0,0,0,0,jobId);return;}
  const ctx={cancelled:false,listeners:new Set()};actv.set(jobId,ctx);
  const emit=d=>{const msg=`data: ${JSON.stringify(d)}\n\n`;for(const l of ctx.listeners){try{l.write(msg);}catch{}}};
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));

  let pending=S.gP.all(jobId);
  if(!pending.length){
    S.uJ.run(job.succeeded,job.failed,'complete',job.total_in,job.total_out,job.total_cr,job.total_cw,job.cost,job.elapsed,jobId);
    emit({type:'done',status:'complete',succeeded:job.succeeded,failed:job.failed});
    actv.delete(jobId);return;
  }
  S.uJ.run(job.succeeded,job.failed,'running',job.total_in,job.total_out,job.total_cr,job.total_cw,job.cost,job.elapsed,jobId);

  const t0=Date.now();
  // Shared counters — workers mutate these; all reads/writes are in the same JS thread (event loop) so no race conditions
  let ok=job.succeeded,fail=job.failed,tIn=job.total_in,tOut=job.total_out,tCR=job.total_cr,tCW=job.total_cw,webCalls=0;

  // Resolve sections for structured output — explicit > prompt > template default
  let jobSections=[];
  if(job.sections_json){try{const ex=JSON.parse(job.sections_json);if(Array.isArray(ex)&&ex.length>=2)jobSections=ex;}catch{}}
  if(!jobSections.length&&job.system_prompt)jobSections=extractSectionsFromPrompt(job.system_prompt);
  if(!jobSections.length){const tmpl=TEMPLATES[job.template_id];if(tmpl?.sections?.length&&tmpl.prompt===job.system_prompt)jobSections=tmpl.sections;}
  let wrappedSys=wrapPromptForStructuredOutput(job.system_prompt,jobSections);
  let sectionsDiscovered=jobSections.length>0;

  // Stream already-completed rows back to any reconnecting client
  for(const r of S.gC.all(jobId))
    emit({type:'result',idx:r.idx,company:r.company,status:r.status,research:safeParseResearch(r.research),error:r.error,inputTokens:r.input_tokens,outputTokens:r.output_tokens});
  emit({type:'progress',succeeded:ok,failed:fail,total:job.total_rows,current:'Starting…'});

  // Shared queue — workers pull from the front
  const queue=[...pending];
  const concurrency=CONCURRENCY[job.provider]||3;

  // Flush updated job stats to DB periodically
  const flushStats=()=>{
    const elapsed=((Date.now()-t0)/1000)+job.elapsed;
    const cost=(tIn/1e6)*prov.inputCost+(tOut/1e6)*prov.outputCost+(tCW/1e6)*(prov.cacheWriteCost||0)+(tCR/1e6)*(prov.cacheReadCost||0)+(job.use_web_search?webCalls*(prov.webCostPerCall||0):0);
    S.uJ.run(ok,fail,'running',tIn,tOut,tCR,tCW,cost,elapsed,jobId);
  };

  // Worker: pulls rows off the queue and processes them until queue is empty or cancelled
  async function worker(){
    while(queue.length>0&&!ctx.cancelled){
      const row=queue.shift();if(!row)break;
      emit({type:'progress',succeeded:ok,failed:fail,total:job.total_rows,current:row.company});

      let retries=0,done=false,lastErr='';
      while(!done&&retries<5&&!ctx.cancelled){
        try{
          const r=await callLLM(row.prompt,prov,wrappedSys,!!job.use_web_search,apiKey);
          // Learn sections from first result if none detected from prompt
          if(!sectionsDiscovered&&r.research){
            const detected=extractSectionsFromOutput(r.research);
            if(detected.length>=2){
              jobSections=detected;sectionsDiscovered=true;
              wrappedSys=wrapPromptForStructuredOutput(job.system_prompt,jobSections);
              try{db.prepare('UPDATE jobs SET sections_json=? WHERE id=?').run(JSON.stringify(jobSections),jobId);}catch{}
              emit({type:'meta',sections:jobSections,templateId:job.template_id});
            }
          }
          let structured=parseStructuredResponse(r.research,jobSections);
          const quality=scoreQuality(structured,jobSections);
          // Smart retry: if quality is low and we haven't quality-retried yet, try once more
          if(quality<40&&retries<1&&jobSections.length>=2){
            const emptySecs=jobSections.filter(s=>!structured[s.key]||structured[s.key].trim().length<5);
            if(emptySecs.length>0){
              retries++;
              emit({type:'log',level:'warn',msg:`Low quality (${quality}%) for "${row.company}" — retrying with emphasis on: ${emptySecs.map(s=>s.label).join(', ')}`});
              const retryP=row.prompt+'\n\nIMPORTANT: Your previous response was missing these sections: '+emptySecs.map(s=>s.label).join(', ')+'. Ensure ALL sections contain substantive information.';
              try{
                const r2=await callLLM(retryP,prov,wrappedSys,!!job.use_web_search,apiKey);
                const s2=parseStructuredResponse(r2.research,jobSections);
                const q2=scoreQuality(s2,jobSections);
                if(q2>quality){structured=s2;tIn+=r2.inputTokens;tOut+=r2.outputTokens;tCR+=r2.cacheRead;tCW+=r2.cacheWrite;if(job.use_web_search)webCalls++;}
              }catch{}
            }
          }
          const researchJson=JSON.stringify(structured);
          S.uR.run('success',researchJson,null,r.inputTokens,r.outputTokens,r.cacheRead,r.cacheWrite,jobId,row.idx);
          try{db.prepare('UPDATE rows SET quality=? WHERE job_id=? AND idx=?').run(quality,jobId,row.idx);}catch{}
          ok++;tIn+=r.inputTokens;tOut+=r.outputTokens;tCR+=r.cacheRead;tCW+=r.cacheWrite;if(job.use_web_search)webCalls++;done=true;rlOk(job.provider);
          emit({type:'result',idx:row.idx,company:row.company,status:'success',research:structured,inputTokens:r.inputTokens,outputTokens:r.outputTokens,quality});
          emit({type:'progress',succeeded:ok,failed:fail,total:job.total_rows,current:row.company});
          flushStats();
        }catch(err){
          lastErr=err.message||String(err);
          if(err.type==='rate_limit'){
            retries++;
            const w=rlHit(job.provider,err.wait);
            emit({type:'log',level:'warn',msg:`⏳ Rate limit "${row.company}" — retry ${Math.round(w/1000)}s (${retries}/5)`});
            emit({type:'rate_info',delay:w,hits:gRL(job.provider).hits});
            await sleep(w);
          }else if(err.type==='api_error'&&(err.message?.includes('empty response')||err.message?.includes('MAX_TOKENS'))){
            retries++;
            const w=Math.min(3000*retries,15000);
            emit({type:'log',level:'warn',msg:`⚠️ Incomplete "${row.company}" — retry ${retries}/5 in ${w/1000}s`});
            await sleep(w);
          }else{
            S.uR.run('error',null,lastErr,0,0,0,0,jobId,row.idx);fail++;done=true;
            emit({type:'result',idx:row.idx,company:row.company,status:'error',error:lastErr});
            emit({type:'progress',succeeded:ok,failed:fail,total:job.total_rows,current:row.company});
            flushStats();
          }
        }
      }
      if(!done){
        S.uR.run('error',null,lastErr||'Max retries',0,0,0,0,jobId,row.idx);fail++;
        emit({type:'result',idx:row.idx,company:row.company,status:'error',error:lastErr||'Max retries'});
        flushStats();
      }
    }
  }

  // Launch N workers in parallel and wait for all to finish
  await Promise.all(Array.from({length:concurrency},()=>worker()));

  const fs=ctx.cancelled?'cancelled':(S.gP.all(jobId).length>0?'paused':'complete');
  const elapsed=((Date.now()-t0)/1000)+job.elapsed;
  const cost=(tIn/1e6)*prov.inputCost+(tOut/1e6)*prov.outputCost+(tCW/1e6)*(prov.cacheWriteCost||0)+(tCR/1e6)*(prov.cacheReadCost||0)+(job.use_web_search?webCalls*(prov.webCostPerCall||0):0);
  S.uJ.run(ok,fail,fs,tIn,tOut,tCR,tCW,cost,elapsed,jobId);
  emit({type:'done',status:fs,succeeded:ok,failed:fail,elapsed:elapsed.toFixed(1),cost:cost.toFixed(4),totalTokens:tIn+tOut,cacheRead:tCR,cacheWrite:tCW});
  actv.delete(jobId);
}

// ─── HTTP Server ───
const PORT=parseInt(process.env.PORT||'3000');
function readB(req){return new Promise(r=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>r(b));});}
function json(res,d,s=200){res.writeHead(s,{'content-type':'application/json','access-control-allow-origin':'*'});res.end(JSON.stringify(d));}
const VALID_KEYS=['GEMINI_API_KEY','ANTHROPIC_API_KEY','OPENAI_API_KEY','DEEPSEEK_API_KEY'];

const server=createServer(async(req,res)=>{
  const url=new URL(req.url,`http://localhost:${PORT}`);const p=url.pathname;
  if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'GET,POST,DELETE,OPTIONS','access-control-allow-headers':'content-type,authorization'});res.end();return;}
  if(req.method==='GET'&&p==='/'){res.writeHead(200,{'content-type':'text/html'});res.end(HTML);return;}

  // ── Public auth routes ──
  if(req.method==='POST'&&p==='/api/signup'){const b=await readB(req);try{
    const{email,password,name}=JSON.parse(b);
    if(!email||!password)return json(res,{error:'Email and password required'},400);
    if(password.length<6)return json(res,{error:'Password must be 6+ characters'},400);
    if(S.getUserByEmail.get(email.toLowerCase().trim()))return json(res,{error:'Email already registered'},400);
    const result=S.createUser.run(email.toLowerCase().trim(),hashPw(password),name||email.split('@')[0]);
    const uid=Number(result.lastInsertRowid);
    json(res,{token:jwtSign({uid,email:email.toLowerCase().trim()}),user:{id:uid,email:email.toLowerCase().trim(),name:name||email.split('@')[0]}});
  }catch(e){json(res,{error:e.message},400);}return;}

  if(req.method==='POST'&&p==='/api/login'){const b=await readB(req);try{
    const{email,password}=JSON.parse(b);
    if(!email||!password)return json(res,{error:'Email and password required'},400);
    const user=S.getUserByEmail.get(email.toLowerCase().trim());
    if(!user||!verifyPw(password,user.password_hash))return json(res,{error:'Invalid email or password'},400);
    json(res,{token:jwtSign({uid:user.id,email:user.email}),user:{id:user.id,email:user.email,name:user.name}});
  }catch(e){json(res,{error:e.message},400);}return;}

  if(req.method==='GET'&&p==='/api/templates'){const out={};for(const[id,t]of Object.entries(TEMPLATES))out[id]={name:t.name,icon:t.icon,desc:t.desc,prompt:t.prompt,sections:t.sections||[]};json(res,out);return;}

  // ── Auth required below ──
  let user=getUser(req);
  if(!user){const qt=url.searchParams.get('token');if(qt)user=jwtVerify(qt);}
  if(!user)return json(res,{error:'Unauthorized'},401);
  const uid=user.uid;

  if(req.method==='GET'&&p==='/api/me'){json(res,S.getUserById.get(uid)||{});return;}
  if(req.method==='GET'&&p==='/api/providers'){json(res,provSt(uid));return;}

  if(req.method==='POST'&&p==='/api/setkey'){const b=await readB(req);try{const{envName,key}=JSON.parse(b);
    if(!VALID_KEYS.includes(envName))return json(res,{error:'Invalid key name'},400);
    if(key)S.setUserKey.run(uid,envName,key);else S.delUserKey.run(uid,envName);
    json(res,provSt(uid));}catch(e){json(res,{error:e.message},400);}return;}

  if(req.method==='POST'&&p==='/api/preview'){const b=await readB(req);try{const{csv,colMapOverride}=JSON.parse(b);
    const{headers,rows}=parseCSV(csv);if(!rows.length)return json(res,{error:'No data'},400);
    const cm=colMapOverride||autoGuess(headers);json(res,{headers,colMap:cm,total:rows.length,previews:rows.slice(0,20).map((r,i)=>buildPrompt(r,cm,i))});
  }catch(e){json(res,{error:e.message},400);}return;}

  if(req.method==='POST'&&p==='/api/research'){const b=await readB(req);try{
    const{csv,provider:pid,useWebSearch:uw,systemPrompt:sp,colMapOverride,templateId,explicitSections}=JSON.parse(b);
    const prov=PROVDEFS[pid];if(!prov)return json(res,{error:'Unknown provider'},400);
    const ak=userKey(uid,prov.envName);if(!ak)return json(res,{error:`No API key for ${prov.name}. Add your key above.`},400);
    const{headers,rows}=parseCSV(csv);if(!rows.length)return json(res,{error:'No data'},400);
    const cm=colMapOverride||autoGuess(headers);if(!cm.company)return json(res,{error:'No Company column'},400);
    const sysPrompt=sp||TEMPLATES['b2b-outreach'].prompt;const actualWeb=uw!==false&&prov.webSearch;
    const sectionsJson=Array.isArray(explicitSections)&&explicitSections.length>=2?JSON.stringify(explicitSections):null;
    const result=S.iJ.run(uid,`${rows.length} prospects via ${prov.name}`,pid,templateId||'custom',sysPrompt,actualWeb?1:0,JSON.stringify(cm),rows.length,sectionsJson);
    const jobId=Number(result.lastInsertRowid);
    db.transaction(()=>{for(let i=0;i<rows.length;i++){const{company,prompt}=buildPrompt(rows[i],cm,i);S.iR.run(jobId,i,company,prompt);}})();
    runJob(jobId);json(res,{jobId,total:rows.length,provider:prov.name});
  }catch(e){json(res,{error:e.message},400);}return;}

  if(req.method==='POST'&&p.match(/^\/api\/resume\/\d+$/)){const jid=parseInt(p.split('/').pop());const job=S.gJ.get(jid);
    if(!job||job.user_id!==uid)return json(res,{error:'Not found'},404);
    if(actv.has(jid))return json(res,{error:'Already running'},400);
    const prov=PROVDEFS[job.provider];if(!prov||!userKey(uid,prov.envName))return json(res,{error:'No API key'},400);
    const pend=S.gP.all(jid);if(!pend.length)return json(res,{error:'No pending rows'},400);
    runJob(jid);json(res,{jobId:jid,remaining:pend.length,total:job.total_rows});return;}

  if(req.method==='GET'&&p.match(/^\/api\/stream\/\d+$/)){const jid=parseInt(p.split('/').pop());const job=S.gJ.get(jid);
    if(!job||job.user_id!==uid){res.writeHead(404);res.end('Not found');return;}
    res.writeHead(200,{'content-type':'text/event-stream','cache-control':'no-cache','connection':'keep-alive','access-control-allow-origin':'*'});
    // Emit column definitions so frontend knows the table structure
    const completedRows=S.gC.all(jid);
    const sseSections=resolveSections(job,completedRows);
    res.write(`data: ${JSON.stringify({type:'meta',sections:sseSections,templateId:job.template_id})}\n\n`);
    for(const r of completedRows){
      let parsed=safeParseResearch(r.research);
      // Re-parse old results with detected sections if not already structured
      if(sseSections.length&&!parsed?._parsed&&parsed?._raw)parsed=parseStructuredResponse(parsed._raw,sseSections);
      res.write(`data: ${JSON.stringify({type:'result',idx:r.idx,company:r.company,status:r.status,research:parsed,error:r.error,inputTokens:r.input_tokens,outputTokens:r.output_tokens})}\n\n`);
    }
    if(job.status==='complete'||job.status==='cancelled') res.write(`data: ${JSON.stringify({type:'done',status:job.status,succeeded:job.succeeded,failed:job.failed,elapsed:String(job.elapsed),cost:String(job.cost),totalTokens:job.total_in+job.total_out,cacheRead:job.total_cr,cacheWrite:job.total_cw})}\n\n`);
    const a2=actv.get(jid);if(a2){a2.listeners.add(res);req.on('close',()=>a2.listeners.delete(res));}return;}

  if(req.method==='POST'&&p.match(/^\/api\/cancel\/\d+$/)){const jid=parseInt(p.split('/').pop());const job=S.gJ.get(jid);
    if(job&&job.user_id===uid){const a2=actv.get(jid);if(a2)a2.cancelled=true;}json(res,{ok:true});return;}

  // Row-level retry endpoint
  if(req.method==='POST'&&p.match(/^\/api\/retry\/\d+\/\d+$/)){
    const parts=p.split('/');const jid=parseInt(parts[3]);const ridx=parseInt(parts[4]);
    const job=S.gJ.get(jid);if(!job||job.user_id!==uid)return json(res,{error:'Not found'},404);
    const prov=PROVDEFS[job.provider];if(!prov)return json(res,{error:'Unknown provider'},400);
    const apiKey=userKey(uid,prov.envName);if(!apiKey)return json(res,{error:'No API key'},400);
    const row=db.prepare('SELECT * FROM rows WHERE job_id=? AND idx=?').get(jid,ridx);
    if(!row)return json(res,{error:'Row not found'},404);
    try{
      const jobSections=resolveSections(job,S.gR.all(jid));
      const wrappedSys=wrapPromptForStructuredOutput(job.system_prompt,jobSections);
      const r=await callLLM(row.prompt,prov,wrappedSys,!!job.use_web_search,apiKey);
      const structured=parseStructuredResponse(r.research,jobSections);
      const quality=scoreQuality(structured,jobSections);
      const researchJson=JSON.stringify(structured);
      S.uR.run('success',researchJson,null,r.inputTokens,r.outputTokens,r.cacheRead||0,r.cacheWrite||0,jid,ridx);
      try{db.prepare('UPDATE rows SET quality=? WHERE job_id=? AND idx=?').run(quality,jid,ridx);}catch{}
      json(res,{status:'success',research:structured,quality,inputTokens:r.inputTokens,outputTokens:r.outputTokens});
    }catch(e){json(res,{error:e.message},500);}
    return;}

  if(req.method==='GET'&&p.match(/^\/api\/export\/\d+$/)){const jid=parseInt(p.split('/').pop());const job=S.gJ.get(jid);
    if(!job||job.user_id!==uid){res.writeHead(404);res.end('Not found');return;}const rows=S.gR.all(jid);
    let expSections=resolveSections(job,rows);
    const escRaw=s=>'"'+String(s||'').replace(/"/g,'""').replace(/\n/g,' ')+'"';
    const escClean=s=>'"'+sanitizeForCSV(String(s||'')).replace(/"/g,'""')+'"';
    // Build headers: Company + original mapped columns + Status + sections + Full Research + meta
    const colMap=JSON.parse(job.col_map||'{}');
    const origCols=Object.entries(colMap).filter(([role,hdr])=>hdr&&role!=='company').map(([role,hdr])=>({role,header:hdr}));
    const hdrCols=['Company'];
    origCols.forEach(c=>hdrCols.push(c.header));
    hdrCols.push('Status');
    if(expSections.length)expSections.forEach(s=>hdrCols.push(s.label));
    else hdrCols.push('Research Brief');
    hdrCols.push('Full Research','Input Tokens','Output Tokens','Provider');
    const hdr=hdrCols.join(',');
    const csvR=rows.map(r=>{
      let parsed=safeParseResearch(r.research);
      const cols=[escRaw(r.company)];
      // Extract original CSV columns from the stored prompt
      origCols.forEach(c=>{
        const roleLabel=c.role.charAt(0).toUpperCase()+c.role.slice(1);
        const pat=new RegExp('\\*\\*'+roleLabel.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(?:[/A-Za-z]*):\\*\\*\\s*(.+?)(?:\\n|$)','i');
        const m=r.prompt?r.prompt.match(pat):null;
        cols.push(escRaw(m?m[1].trim():''));
      });
      cols.push(escRaw(r.status));
      // If sections exist but data wasn't pre-parsed, try parsing now from raw text
      if(expSections.length&&!parsed?._parsed&&parsed?._raw){
        parsed=parseStructuredResponse(parsed._raw,expSections);
      }
      if(expSections.length&&parsed?._parsed)expSections.forEach(s=>cols.push(escClean(parsed[s.key]||'')));
      else if(expSections.length)expSections.forEach(()=>cols.push('""'));
      else cols.push(escClean(parsed?._raw||r.error||''));
      cols.push(escRaw(parsed?._raw||''),r.input_tokens||0,r.output_tokens||0,escRaw(job.provider));
      return cols.join(',');
    });
    res.writeHead(200,{'content-type':'text/csv','content-disposition':`attachment; filename="prospect_research_${new Date().toISOString().slice(0,10)}.csv"`,'access-control-allow-origin':'*'});
    res.end('\uFEFF'+[hdr,...csvR].join('\r\n'));return;}

  if(req.method==='GET'&&p==='/api/jobs'){json(res,S.lJ.all(uid).map(j=>({...j,templateName:TEMPLATES[j.template_id]?.name||'Custom',templateIcon:TEMPLATES[j.template_id]?.icon||'\u270F\uFE0F',providerName:PROVDEFS[j.provider]?.name||j.provider})));return;}

  if(req.method==='DELETE'&&p.match(/^\/api\/jobs\/\d+$/)){const jid=parseInt(p.split('/').pop());S.dR.run(jid);S.dJ.run(jid,uid);json(res,{ok:true});return;}

  res.writeHead(404);res.end('Not found');
});

server.listen(PORT,process.env.HOST||'0.0.0.0',()=>{
  console.log(`\n  🔍 Prospect Researcher v6 (multi-user)`);
  console.log('  '+'━'.repeat(30));
  console.log(`  URL:  http://localhost:${PORT}`);
  console.log(`  Data: ${DD}`);
  console.log(`  JWT:  ${process.env.JWT_SECRET?'persistent (env)':'ephemeral (set JWT_SECRET)'}`);
  console.log('  '+'━'.repeat(30)+'\n');
});
const HTML=readFileSync(new URL('./ui.html',import.meta.url),'utf8');
