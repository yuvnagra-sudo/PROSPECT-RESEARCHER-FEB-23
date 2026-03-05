#!/usr/bin/env node
import { createServer } from 'http';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { resolve, join } from 'path';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'crypto';

try { const ep=resolve(process.cwd(),'.env'); if(existsSync(ep)) readFileSync(ep,'utf8').split('\n').forEach(l=>{const m=l.match(/^\s*([^#=]+?)\s*=\s*(.*?)\s*$/);if(m&&!process.env[m[1]])process.env[m[1]]=m[2].replace(/^["']|["']$/g,'');}); } catch{}
const JWT_SECRET = process.env.JWT_SECRET || randomBytes(32).toString('hex');
const DD=resolve(process.cwd(),'.data'); if(!existsSync(DD))mkdirSync(DD,{recursive:true});

// Simple JSON file DB
const DBF=join(DD,'db.json');
let DB={users:[],keys:[],jobs:[],rows:[],nextId:{user:1,job:1,row:1}};
function loadDB(){try{if(existsSync(DBF))DB=JSON.parse(readFileSync(DBF,'utf8'));}catch{}}
function saveDB(){try{writeFileSync(DBF,JSON.stringify(DB));}catch(e){console.error('DB save error:',e.message);}}
loadDB();

function hashPw(pw){const salt=randomBytes(16).toString('hex');return salt+':'+scryptSync(pw,salt,64).toString('hex');}
function verifyPw(pw,stored){const[salt,hash]=stored.split(':');return timingSafeEqual(scryptSync(pw,salt,64),Buffer.from(hash,'hex'));}
function base64url(buf){return(typeof buf==='string'?Buffer.from(buf):buf).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');}
function jwtSign(p){const h=base64url(JSON.stringify({alg:'HS256',typ:'JWT'}));const b=base64url(JSON.stringify({...p,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+604800}));return h+'.'+b+'.'+base64url(createHmac('sha256',JWT_SECRET).update(h+'.'+b).digest());}
function jwtVerify(token){try{const[h,b,s]=token.split('.');if(s!==base64url(createHmac('sha256',JWT_SECRET).update(h+'.'+b).digest()))return null;const p=JSON.parse(Buffer.from(b,'base64url').toString());return p.exp&&p.exp<Math.floor(Date.now()/1000)?null:p;}catch{return null;}}
function getUser(req){const a=req.headers.authorization;return a?.startsWith('Bearer ')?jwtVerify(a.slice(7)):null;}
function userKey(uid,k){const r=DB.keys.find(x=>x.uid===uid&&x.name===k);return r?.value||'';}

const PROVDEFS={
  gemini:{name:'Gemini 2.5 Flash',model:'gemini-2.5-flash',inputCost:0.15,outputCost:0.60,format:'gemini-native',webSearch:true,webCostPerCall:0.035,envName:'GEMINI_API_KEY'},
  claude:{name:'Claude Sonnet 4',model:'claude-sonnet-4-20250514',apiUrl:'https://api.anthropic.com/v1/messages',inputCost:3,outputCost:15,format:'anthropic',webSearch:true,webCostPerCall:0.015,cacheReadCost:0.30,cacheWriteCost:3.75,envName:'ANTHROPIC_API_KEY'},
  haiku:{name:'Claude Haiku 4.5',model:'claude-haiku-4-5-20251001',apiUrl:'https://api.anthropic.com/v1/messages',inputCost:1,outputCost:5,format:'anthropic',webSearch:true,webCostPerCall:0.005,cacheReadCost:0.10,cacheWriteCost:1.25,envName:'ANTHROPIC_API_KEY'},
  gpt5:{name:'GPT-5',model:'gpt-5',apiUrl:'https://api.openai.com/v1/chat/completions',inputCost:1.25,outputCost:10,format:'openai',webSearch:true,webTool:'openai',webCostPerCall:0.018,envName:'OPENAI_API_KEY'},
  openai:{name:'GPT-4o Mini',model:'gpt-4o-mini',apiUrl:'https://api.openai.com/v1/chat/completions',inputCost:0.15,outputCost:0.60,format:'openai',webSearch:false,webCostPerCall:0,envName:'OPENAI_API_KEY'},
  deepseek:{name:'DeepSeek V3',model:'deepseek-chat',apiUrl:'https://api.deepseek.com/v1/chat/completions',inputCost:0.56,outputCost:1.68,format:'openai',webSearch:false,webCostPerCall:0,envName:'DEEPSEEK_API_KEY'},
};
function provSt(uid){const a={};const uk=DB.keys.filter(r=>r.uid===uid).map(r=>r.name);for(const[id,p]of Object.entries(PROVDEFS))a[id]={name:p.name,hasKey:uk.includes(p.envName),inputCost:p.inputCost,outputCost:p.outputCost,webSearch:p.webSearch,webCostPerCall:p.webCostPerCall||0};return a;}

const TEMPLATES={
'b2b-outreach':{name:'B2B Sales Outreach',icon:'📧',desc:'Pain points, triggers, hooks',prompt:'You are an expert B2B sales researcher. For each prospect, provide:\n1. **Company Snapshot** (2-3 sentences)\n2. **Recent Triggers** - Funding, launches, leadership changes, hiring surges\n3. **Pain Points** (2-3) - Specific operational challenges\n4. **Personalization Hooks** (2-3) - Concrete references with source\n5. **Outreach Angle** - Specific pain + framing + sample opener\nBe specific and actionable.'},
'vc-research':{name:'VC / PE Due Diligence',icon:'💰',desc:'Investment thesis, check sizes, stages',prompt:'You are a capital raising research assistant. Determine if this company invests in startups. If NOT, return "Not an Investor" and stop.\nIf investor:\n1. **Investment Niche**\n2. **Check Size & Stages**\n3. **Investment Constraints**\n4. **2025 Portfolio Activity**\n5. **Contact & Process**\nInclude confidence scores.'},
'real-estate':{name:'Real Estate Prospecting',icon:'🏠',desc:'Online presence, marketing gaps',prompt:'You are a real estate researcher for a marketing agency. For each agent/brokerage:\n1. **Agent Profile**\n2. **Market Activity**\n3. **Online Presence Audit** (1-10)\n4. **Pain Points** (2-3)\n5. **Personalization Hook**\n6. **Outreach Recommendation**'},
'local-business':{name:'Local Business Outreach',icon:'🏪',desc:'Presence audit, competitor gaps',prompt:'You are a local business marketing researcher. For each business:\n1. **Business Overview**\n2. **Online Presence Audit** (GBP, Website, Social, SEO)\n3. **Competitive Landscape** (2-3 competitors)\n4. **Gap Analysis** (top 3)\n5. **Quick Win** (30-day action)\n6. **Outreach Hook**'},
'saas-competitor':{name:'SaaS Competitor Analysis',icon:'⚔️',desc:'Pricing, positioning, vulnerabilities',prompt:'You are a SaaS competitive intelligence analyst. For each company:\n1. **Product Overview**\n2. **Pricing & Packaging**\n3. **Market Position**\n4. **Tech Stack & Integrations**\n5. **Recent Moves** (12 months)\n6. **Strengths & Vulnerabilities** (3 each)\n7. **Sales Approach**'},
'recruiting':{name:'Recruiting Intel',icon:'👥',desc:'Hiring velocity, culture, pain points',prompt:'You are a recruiting researcher. For each company:\n1. **Company Overview**\n2. **Hiring Velocity**\n3. **Key Open Roles**\n4. **Culture & Employer Brand**\n5. **Hiring Pain Points** (2-3)\n6. **Outreach Recommendation**'},
'custom':{name:'Custom Prompt',icon:'✏️',desc:'Write your own',prompt:'You are an expert B2B sales researcher. For each prospect, provide:\n1. **Company Overview**\n2. **Recent News & Activity**\n3. **Pain Points & Opportunities**\n4. **Personalization Hooks**\n5. **Outreach Recommendation**'}
};
const EMAIL_FRAMEWORKS={
  'pas':{name:'PAS (Pain → Agitate → Solve)',instruction:'Use PAS: 1) Specific pain from research, 2) Why it gets worse, 3) Offer as solution. Under 100 words.'},
  'aida':{name:'AIDA (Attention → Interest → Desire → Action)',instruction:'Use AIDA: 1) Trigger hook, 2) Insight, 3) Proof/desire, 4) CTA. Under 100 words.'},
  'bab':{name:'Before → After → Bridge',instruction:'Before-After-Bridge: 1) Current state, 2) Better state, 3) Offer as bridge. Under 100 words.'},
  'quick':{name:'Quick Question (ultra-short)',instruction:'2-3 sentences max. One specific question about a pain/trigger. Soft CTA. Under 50 words.'},
  'case-study':{name:'Case Study Lead',instruction:'Lead with sender result/proof. Connect to prospect via research. Under 100 words.'},
};

function gradeResearch(text,tid){
  if(!text||typeof text!=='string')return{score:0,tier:'weak'};const t=text.trim();
  if(t.length<30)return{score:0,tier:'weak'};
  if(tid==='vc-research'&&/not an investor/i.test(t)&&t.length<200)return{score:75,tier:'moderate'};
  let s=0;
  if(t.length>1500)s+=15;else if(t.length>800)s+=12;else if(t.length>400)s+=8;else if(t.length>200)s+=4;
  const sec=Math.max((t.match(/\*\*[^*]+\*\*/g)||[]).length,(t.match(/^\d+\.\s/gm)||[]).length,(t.match(/^#{1,3}\s/gm)||[]).length);
  if(sec>=5)s+=25;else if(sec>=3)s+=18;else if(sec>=2)s+=12;else if(sec>=1)s+=6;
  const sp=[(t.match(/\$[\d,.]+[KkMmBb]?/g)||[]).length,(t.match(/\b20[12]\d\b/g)||[]).length,(t.match(/https?:\/\/\S+/g)||[]).length,(t.match(/\d+%/g)||[]).length,(t.match(/(?:Series [A-F]|seed|raised|funding|revenue)/gi)||[]).length].reduce((a,b)=>a+b,0);
  if(sp>=8)s+=20;else if(sp>=5)s+=15;else if(sp>=3)s+=10;else if(sp>=1)s+=5;
  let nh=0;for(const p of[/couldn'?t find/i,/no information available/i,/limited data/i,/not publicly available/i,/unable to (?:find|locate|determine)/i,/could not (?:find|locate)/i])if(p.test(t))nh++;
  if(nh===0)s+=20;else if(nh===1)s+=12;else if(nh===2)s+=5;
  const trig=(t.match(/\b(?:recently|just (?:announced|launched|raised|hired)|Q[1-4] 20[2-3]\d|launched|raised|hired|expanded|acquired|partnered)\b/gi)||[]).length;
  if(trig>=4)s+=10;else if(trig>=2)s+=7;else if(trig>=1)s+=4;
  const bl=(t.match(/^[-*•]\s/gm)||[]).length;if(bl>=6)s+=10;else if(bl>=3)s+=6;else if(bl>=1)s+=3;
  s=Math.min(100,Math.max(0,s));return{score:s,tier:s>=75?'strong':s>=45?'moderate':'weak'};
}
function buildEmailPrompt(research,offer,fw){const f=EMAIL_FRAMEWORKS[fw]||EMAIL_FRAMEWORKS['pas'];return`Write a personalized cold email using research below.\n\nFRAMEWORK: ${f.instruction}\n\nRESEARCH:\n${research}\n\nSENDER:\nCompany: ${offer.company||'Our Company'}\nWhat we do: ${offer.whatWeSell||'We help businesses grow'}\nKey result: ${offer.proof||'Proven results'}\nCTA: ${offer.cta||'Quick call'}\n\nRULES:\n- First line: specific reference from research\n- No "I hope this finds you well" or "I came across"\n- Sound like busy founder, short sentences\n- Subject: max 6 words, lowercase, no punctuation\n- Soft CTA, no [brackets]\n- Under 100 words body\n\nFORMAT:\nSUBJECT: subject here\n\nBODY:\nemail here`;}

async function callGemini(prompt,prov,sys,web,key){
  const url=`https://generativelanguage.googleapis.com/v1beta/models/${prov.model}:generateContent?key=${key}`;
  const body={systemInstruction:{parts:[{text:sys}]},contents:[{parts:[{text:prompt}]}],generationConfig:{maxOutputTokens:16000,thinkingConfig:{thinkingBudget:0}}};
  if(web)body.tools=[{google_search:{}}];
  const res=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  if(res.status===429){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}const rm=m.match(/retry in ([\d.]+)s/i);throw{type:'rate_limit',wait:rm?Math.ceil(parseFloat(rm[1]))*1000:30000};}
  if(!res.ok){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}throw{type:'api_error',message:m};}
  const data=await res.json();const c=data.candidates?.[0];const u=data.usageMetadata||{};
  const txt=(c?.content?.parts||[]).filter(p=>typeof p.text==='string'&&p.text.trim()).map(p=>p.text).join('\n').replace(/\s*\[cite:\s*[\d,\s]+\]/g,'').trim();
  if(!txt&&(u.candidatesTokenCount||0)===0)throw{type:'api_error',message:'empty response'};
  return{research:txt,inputTokens:u.promptTokenCount||0,outputTokens:u.candidatesTokenCount||0,cacheRead:0,cacheWrite:0};
}
async function callAnthropic(prompt,prov,sys,web,key){
  const body={model:prov.model,max_tokens:4000,system:[{type:'text',text:sys,cache_control:{type:'ephemeral'}}],messages:[{role:'user',content:prompt}]};
  if(web)body.tools=[{type:'web_search_20250305',name:'web_search'}];
  const res=await fetch(prov.apiUrl,{method:'POST',headers:{'x-api-key':key,'anthropic-version':'2023-06-01','content-type':'application/json'},body:JSON.stringify(body)});
  if(res.status===429||res.status===529)throw{type:'rate_limit',wait:30000};
  if(!res.ok){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}throw{type:'api_error',message:m};}
  const data=await res.json();const u=data.usage||{};
  return{research:(data.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('\n'),inputTokens:u.input_tokens||0,outputTokens:u.output_tokens||0,cacheRead:u.cache_read_input_tokens||0,cacheWrite:u.cache_creation_input_tokens||0};
}
async function callOpenAI(prompt,prov,sys,web,key){
  const tk=prov.model.startsWith('gpt-5')?'max_completion_tokens':'max_tokens';
  const body={model:prov.model,[tk]:4000,messages:[{role:'system',content:sys},{role:'user',content:prompt}]};
  if(prov.webTool==='openai'&&web)body.tools=[{type:'web_search_preview'}];
  const res=await fetch(prov.apiUrl,{method:'POST',headers:{'content-type':'application/json','authorization':`Bearer ${key}`},body:JSON.stringify(body)});
  if(res.status===429)throw{type:'rate_limit',wait:30000};
  if(!res.ok){const t=await res.text();let m;try{m=JSON.parse(t).error?.message||t}catch{m=t}throw{type:'api_error',message:m};}
  const data=await res.json();const c=data.choices?.[0];const u=data.usage||{};
  return{research:typeof c?.message?.content==='string'?c.message.content:'',inputTokens:u.prompt_tokens||0,outputTokens:u.completion_tokens||0,cacheRead:0,cacheWrite:0};
}
function callLLM(p,prov,sys,web,key){if(prov.format==='gemini-native')return callGemini(p,prov,sys,web,key);if(prov.format==='anthropic')return callAnthropic(p,prov,sys,web,key);return callOpenAI(p,prov,sys,web,key);}

function parseCSV(text){
  if(text.charCodeAt(0)===0xfeff)text=text.slice(1);text=text.replace(/\r\n/g,'\n').replace(/\r/g,'\n');
  const records=[];let cur=[];let field='';let inQ=false;
  for(let i=0;i<text.length;i++){const ch=text[i];if(inQ){if(ch==='"'){if(i+1<text.length&&text[i+1]==='"'){field+='"';i++;}else inQ=false;}else field+=ch;}else{if(ch==='"')inQ=true;else if(ch===','){cur.push(field.trim());field='';}else if(ch==='\n'){cur.push(field.trim());if(cur.length>1||cur[0]!=='')records.push(cur);cur=[];field='';}else field+=ch;}}
  cur.push(field.trim());if(cur.length>1||cur[0]!=='')records.push(cur);
  if(records.length<2)return{headers:[],rows:[]};
  const hdrs=records[0].map(h=>h.replace(/^["']|["']$/g,'').trim());const rows=[];
  for(let i=1;i<records.length;i++){const v=records[i];if(!v.length||(v.length===1&&!v[0]))continue;const row={};hdrs.forEach((h,idx)=>{row[h]=(v[idx]||'').replace(/^["']|["']$/g,'').trim();});rows.push(row);}
  return{headers:hdrs,rows};
}
const GUESSES={company:['company','company_name','business name','business','organization','name','firm','account'],website:['url','website','web','domain','site','webpage'],email:['email','email_address','e-mail','mail'],contact:['contact','contact_name','person','full name','first name'],title:['title','job_title','role','position','designation'],phone:['phone','telephone','tel','mobile','cell'],address:['address','location','city','street','region'],industry:['industry','sector','vertical','category','type','segment'],rating:['rating','score','stars'],reviews:['reviews','review count'],notes:['notes','additional_info','description','context','comments','bio']};
function autoGuess(headers){const map={};for(const[role,guesses]of Object.entries(GUESSES)){let f=null;for(const g of guesses){for(const h of headers){if(h.toLowerCase().trim()===g.toLowerCase()){f=h;break;}}if(f)break;}if(!f){for(const g of guesses){for(const h of headers){if(h.toLowerCase().trim().includes(g.toLowerCase())){f=h;break;}}if(f)break;}}map[role]=f||'';}return map;}
function buildPrompt(row,map,idx){
  const cl=v=>(v||'').replace(/^[\u00b7\u2022\s]+/,'').trim();const company=map.company?cl(row[map.company]):`Prospect ${idx+1}`;
  let url=map.website?cl(row[map.website]):'';let email=map.email?cl(row[map.email]):'';
  if(!url&&email&&(email.startsWith('http')||email.includes('www.')||/\.(com|ca|net|org|io)/.test(email))){url=email;email='';}
  let pr=`Research this prospect:\n\n**Company:** ${company}`;
  if(url)pr+=`\n**Website:** ${url}`;if(map.contact&&cl(row[map.contact]))pr+=`\n**Contact:** ${cl(row[map.contact])}`;
  if(map.title&&cl(row[map.title]))pr+=`\n**Title:** ${cl(row[map.title])}`;if(email)pr+=`\n**Email:** ${email}`;
  if(map.phone&&cl(row[map.phone]))pr+=`\n**Phone:** ${cl(row[map.phone])}`;if(map.address&&cl(row[map.address]))pr+=`\n**Address:** ${cl(row[map.address])}`;
  if(map.industry&&cl(row[map.industry]))pr+=`\n**Industry:** ${cl(row[map.industry])}`;if(map.notes&&cl(row[map.notes]))pr+=`\n**Notes:** ${cl(row[map.notes])}`;
  pr+='\n\nUse web search to find the most current information.';return{company,prompt:pr};}

const actv=new Map();const CONC={gemini:5,claude:5,haiku:5,gpt5:4,openai:5,deepseek:5};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

async function runJob(jobId){
  const job=DB.jobs.find(j=>j.id===jobId);if(!job)return;const prov=PROVDEFS[job.provider];if(!prov)return;
  const apiKey=userKey(job.uid,prov.envName);if(!apiKey){job.status='error';saveDB();return;}
  const ctx={cancelled:false,listeners:new Set()};actv.set(jobId,ctx);
  const emit=d=>{const msg=`data: ${JSON.stringify(d)}\n\n`;for(const l of ctx.listeners){try{l.write(msg);}catch{}}};
  let offer=null,eProv=null,eKey='';
  if(job.generateEmails){try{offer=JSON.parse(job.offerJson||'{}');}catch{offer={};}const ep=job.emailProvider||'haiku';eProv=PROVDEFS[ep];if(eProv)eKey=userKey(job.uid,eProv.envName);}
  const fbOn=!!job.fallbackProvider&&job.fallbackProvider!=='none';
  const fbP=fbOn?PROVDEFS[job.fallbackProvider]:null;const fbK=fbP?userKey(job.uid,fbP.envName):'';
  let fbSpent=job.fallbackSpent||0,fbCnt=0;
  const rows=DB.rows.filter(r=>r.jobId===jobId);const pending=rows.filter(r=>r.status==='pending');const completed=rows.filter(r=>r.status!=='pending');
  if(!pending.length){job.status='complete';saveDB();emit({type:'done',status:'complete',succeeded:job.succeeded,failed:job.failed});actv.delete(jobId);return;}
  job.status='running';saveDB();
  const t0=Date.now();let ok=job.succeeded||0,fl=job.failed||0,tI=job.totalIn||0,tO=job.totalOut||0,tCR=0,tCW=0;
  for(const r of completed)emit({type:'result',idx:r.idx,company:r.company,status:r.status,research:r.research,error:r.error,qualityScore:r.qualityScore,qualityTier:r.qualityTier,emailDraft:r.emailDraft,wasFallback:r.wasFallback||0});
  emit({type:'progress',succeeded:ok,failed:fl,total:job.totalRows,current:'Starting…'});
  const queue=[...pending];
  const cc=()=>(tI/1e6)*prov.inputCost+(tO/1e6)*prov.outputCost+(tCW/1e6)*(prov.cacheWriteCost||0)+(tCR/1e6)*(prov.cacheReadCost||0);
  const flush=()=>{job.succeeded=ok;job.failed=fl;job.totalIn=tI;job.totalOut=tO;job.cost=cc();job.elapsed=((Date.now()-t0)/1000)+(job._prevElapsed||0);job.fallbackSpent=fbSpent;saveDB();};

  async function genEmail(row,res){
    if(!offer||!eProv||!eKey)return;
    try{const p=buildEmailPrompt(res,offer,job.emailFramework||'pas');const r=await callLLM(p,eProv,'You are a cold email copywriter.',false,eKey);tI+=r.inputTokens;tO+=r.outputTokens;row.emailDraft=r.research;row.emailStatus='success';emit({type:'email',idx:row.idx,emailDraft:r.research});}
    catch(e){row.emailStatus='error';}saveDB();}

  async function worker(){
    while(queue.length>0&&!ctx.cancelled){
      const row=queue.shift();if(!row)break;
      emit({type:'progress',succeeded:ok,failed:fl,total:job.totalRows,current:row.company});
      let retries=0,done=false,lastErr='';
      while(!done&&retries<5&&!ctx.cancelled){
        try{
          const r=await callLLM(row.prompt,prov,job.systemPrompt,!!job.useWebSearch,apiKey);
          const g=gradeResearch(r.research,job.templateId);
          let fR=r.research,fG=g,fb=false;
          if(fbOn&&fbK&&g.score<(job.fallbackThreshold||50)&&fbCnt<Math.ceil(job.totalRows*(job.fallbackMaxPct||20)/100)&&fbSpent<(job.fallbackBudget||2)){
            emit({type:'log',level:'warn',msg:`⚡ Weak(${g.score}) "${row.company}" → ${fbP.name}`});
            try{const fr=await callLLM(row.prompt,fbP,job.systemPrompt,!!job.useWebSearch&&fbP.webSearch,fbK);const fg=gradeResearch(fr.research,job.templateId);fbSpent+=(fr.inputTokens/1e6)*fbP.inputCost+(fr.outputTokens/1e6)*fbP.outputCost;fbCnt++;tI+=fr.inputTokens;tO+=fr.outputTokens;
              if(fg.score>g.score){fR=fr.research;fG=fg;fb=true;row.primaryScore=g.score;}
              emit({type:'log',level:'info',msg:`⚡ ${g.score}→${fg.score} "${row.company}" ${fg.score>g.score?'✓':'✗'}`});}catch(fe){emit({type:'log',level:'warn',msg:`⚡ FB fail: ${fe.message||fe}`});}}
          row.status='success';row.research=fR;row.qualityScore=fG.score;row.qualityTier=fG.tier;row.wasFallback=fb?1:0;row.inputTokens=r.inputTokens;row.outputTokens=r.outputTokens;
          ok++;tI+=r.inputTokens;tO+=r.outputTokens;done=true;
          emit({type:'result',idx:row.idx,company:row.company,status:'success',research:fR,inputTokens:r.inputTokens,outputTokens:r.outputTokens,qualityScore:fG.score,qualityTier:fG.tier,wasFallback:fb?1:0});
          emit({type:'progress',succeeded:ok,failed:fl,total:job.totalRows,current:row.company});flush();
          if(job.generateEmails&&fG.tier!=='weak')await genEmail(row,fR);
        }catch(err){
          lastErr=err.message||String(err);
          if(err.type==='rate_limit'){retries++;const w=err.wait||30000;emit({type:'log',level:'warn',msg:`⏳ ${row.company} retry ${Math.round(w/1000)}s`});await sleep(w);}
          else{row.status='error';row.error=lastErr;row.qualityScore=-1;row.qualityTier='error';fl++;done=true;emit({type:'result',idx:row.idx,company:row.company,status:'error',error:lastErr,qualityScore:-1,qualityTier:'error'});flush();}
        }
      }
      if(!done){row.status='error';row.error=lastErr||'Max retries';fl++;emit({type:'result',idx:row.idx,company:row.company,status:'error',error:lastErr||'Max retries'});flush();}
    }
  }
  await Promise.all(Array.from({length:CONC[job.provider]||3},()=>worker()));
  const fs=ctx.cancelled?'cancelled':(DB.rows.filter(r=>r.jobId===jobId&&r.status==='pending').length>0?'paused':'complete');
  job.status=fs;job.succeeded=ok;job.failed=fl;job.cost=cc();
  job.elapsed=((Date.now()-t0)/1000)+(job._prevElapsed||0);job.fallbackSpent=fbSpent;saveDB();
  const allR=DB.rows.filter(r=>r.jobId===jobId);
  emit({type:'done',status:fs,succeeded:ok,failed:fl,elapsed:job.elapsed.toFixed(1),cost:cc().toFixed(4),totalTokens:tI+tO,strong:allR.filter(r=>r.qualityTier==='strong').length,moderate:allR.filter(r=>r.qualityTier==='moderate').length,weak:allR.filter(r=>r.qualityTier==='weak'||r.status==='error').length,emailCount:allR.filter(r=>r.emailStatus==='success').length,fallbackSpent:fbSpent.toFixed(4),fallbackCount:fbCnt});
  actv.delete(jobId);
}

const PORT=parseInt(process.env.PORT||'3000');
function readB(req){return new Promise(r=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>r(b));});}
function json(res,d,s=200){res.writeHead(s,{'content-type':'application/json','access-control-allow-origin':'*'});res.end(JSON.stringify(d));}

const HTML=readFileSync(new URL('./ui.html',import.meta.url),'utf8');
const server=createServer(async(req,res)=>{
  const url=new URL(req.url,`http://localhost:${PORT}`);const p=url.pathname;
  if(req.method==='OPTIONS'){res.writeHead(204,{'access-control-allow-origin':'*','access-control-allow-methods':'GET,POST,DELETE,OPTIONS','access-control-allow-headers':'content-type,authorization'});res.end();return;}
  if(req.method==='GET'&&p==='/'){res.writeHead(200,{'content-type':'text/html'});res.end(HTML);return;}
  if(req.method==='POST'&&p==='/api/signup'){const b=await readB(req);try{const{email,password,name}=JSON.parse(b);if(!email||!password)return json(res,{error:'Email+password required'},400);if(password.length<6)return json(res,{error:'6+ chars'},400);if(DB.users.find(u=>u.email===email.toLowerCase().trim()))return json(res,{error:'Already registered'},400);const uid=DB.nextId.user++;DB.users.push({id:uid,email:email.toLowerCase().trim(),hash:hashPw(password),name:name||email.split('@')[0]});saveDB();json(res,{token:jwtSign({uid,email:email.toLowerCase().trim()}),user:{id:uid,email:email.toLowerCase().trim(),name:name||email.split('@')[0]}});}catch(e){json(res,{error:e.message},400);}return;}
  if(req.method==='POST'&&p==='/api/login'){const b=await readB(req);try{const{email,password}=JSON.parse(b);const u=DB.users.find(x=>x.email===email.toLowerCase().trim());if(!u||!verifyPw(password,u.hash))return json(res,{error:'Invalid credentials'},400);json(res,{token:jwtSign({uid:u.id,email:u.email}),user:{id:u.id,email:u.email,name:u.name}});}catch(e){json(res,{error:e.message},400);}return;}
  if(req.method==='GET'&&p==='/api/templates'){const o={};for(const[id,t]of Object.entries(TEMPLATES))o[id]={name:t.name,icon:t.icon,desc:t.desc,prompt:t.prompt};json(res,o);return;}
  if(req.method==='GET'&&p==='/api/email-frameworks'){json(res,Object.fromEntries(Object.entries(EMAIL_FRAMEWORKS).map(([k,v])=>[k,{name:v.name}])));return;}
  let user=getUser(req);if(!user){const qt=url.searchParams.get('token');if(qt)user=jwtVerify(qt);}
  if(!user)return json(res,{error:'Unauthorized'},401);const uid=user.uid;
  if(req.method==='GET'&&p==='/api/me'){const u=DB.users.find(x=>x.id===uid);json(res,u?{id:u.id,email:u.email,name:u.name}:{});return;}
  if(req.method==='GET'&&p==='/api/providers'){json(res,provSt(uid));return;}
  if(req.method==='POST'&&p==='/api/setkey'){const b=await readB(req);try{const{envName,key}=JSON.parse(b);if(!['GEMINI_API_KEY','ANTHROPIC_API_KEY','OPENAI_API_KEY','DEEPSEEK_API_KEY'].includes(envName))return json(res,{error:'Invalid'},400);DB.keys=DB.keys.filter(k=>!(k.uid===uid&&k.name===envName));if(key)DB.keys.push({uid,name:envName,value:key});saveDB();json(res,provSt(uid));}catch(e){json(res,{error:e.message},400);}return;}
  if(req.method==='POST'&&p==='/api/preview'){const b=await readB(req);try{const{csv,colMapOverride,systemPrompt,rowStart,rowEnd}=JSON.parse(b);const{headers,rows}=parseCSV(csv);if(!rows.length)return json(res,{error:'No data'},400);const cm=colMapOverride||autoGuess(headers);const rs=Math.max(0,(rowStart||1)-1);const re=(!rowEnd||rowEnd<0)?rows.length:Math.min(rowEnd,rows.length);const sl=rows.slice(rs,re);json(res,{headers,colMap:cm,total:rows.length,selectedCount:sl.length,rowStart:rs+1,rowEnd:re,previews:sl.slice(0,5).map((r,i)=>buildPrompt(r,cm,rs+i)),systemPrompt:systemPrompt||null});}catch(e){json(res,{error:e.message},400);}return;}
  if(req.method==='POST'&&p==='/api/research'){const b=await readB(req);try{
    const{csv,provider:pid,useWebSearch:uw,systemPrompt:sp,colMapOverride,templateId,offerJson,emailFramework,generateEmails,emailProvider,fallbackProvider,fallbackThreshold,fallbackBudget,fallbackMaxPct,rowStart,rowEnd}=JSON.parse(b);
    const prov=PROVDEFS[pid];if(!prov)return json(res,{error:'Unknown provider'},400);if(!userKey(uid,prov.envName))return json(res,{error:'No API key for '+prov.name},400);
    const{headers,rows}=parseCSV(csv);if(!rows.length)return json(res,{error:'No data'},400);const cm=colMapOverride||autoGuess(headers);if(!cm.company)return json(res,{error:'No Company column'},400);
    const rs=Math.max(0,(rowStart||1)-1);const re=(!rowEnd||rowEnd<0)?rows.length:Math.min(rowEnd,rows.length);const sl=rows.slice(rs,re);if(!sl.length)return json(res,{error:'No rows'},400);
    const sys=sp||TEMPLATES['b2b-outreach'].prompt;const web=uw!==false&&prov.webSearch;
    const jid=DB.nextId.job++;const job={id:jid,uid,name:`${sl.length} prospects via ${prov.name}`,provider:pid,templateId:templateId||'custom',systemPrompt:sys,useWebSearch:web?1:0,totalRows:sl.length,succeeded:0,failed:0,status:'queued',totalIn:0,totalOut:0,cost:0,elapsed:0,_prevElapsed:0,createdAt:new Date().toISOString(),offerJson:offerJson||null,emailFramework:emailFramework||null,generateEmails:generateEmails?1:0,emailProvider:emailProvider||null,fallbackProvider:fallbackProvider||null,fallbackThreshold:fallbackThreshold||50,fallbackBudget:fallbackBudget||2,fallbackMaxPct:fallbackMaxPct||20,fallbackSpent:0};
    DB.jobs.push(job);
    for(let i=0;i<sl.length;i++){const{company,prompt}=buildPrompt(sl[i],cm,rs+i);DB.rows.push({id:DB.nextId.row++,jobId:jid,idx:i,company,prompt,status:'pending',research:null,error:null,inputTokens:0,outputTokens:0,qualityScore:-1,qualityTier:null,emailDraft:null,emailStatus:'pending',wasFallback:0,primaryScore:-1});}
    saveDB();runJob(jid);json(res,{jobId:jid,total:sl.length,provider:prov.name});
  }catch(e){json(res,{error:e.message},400);}return;}
  if(req.method==='POST'&&p.match(/^\/api\/resume\/\d+$/)){const jid=+p.split('/').pop();const j=DB.jobs.find(x=>x.id===jid&&x.uid===uid);if(!j)return json(res,{error:'Not found'},404);if(actv.has(jid))return json(res,{error:'Running'},400);j._prevElapsed=j.elapsed||0;runJob(jid);json(res,{jobId:jid});return;}
  if(req.method==='GET'&&p.match(/^\/api\/stream\/\d+$/)){const jid=+p.split('/').pop();const j=DB.jobs.find(x=>x.id===jid&&x.uid===uid);if(!j){res.writeHead(404);res.end();return;}res.writeHead(200,{'content-type':'text/event-stream','cache-control':'no-cache','connection':'keep-alive','access-control-allow-origin':'*'});
    for(const r of DB.rows.filter(x=>x.jobId===jid&&x.status!=='pending'))res.write(`data: ${JSON.stringify({type:'result',idx:r.idx,company:r.company,status:r.status,research:r.research,error:r.error,qualityScore:r.qualityScore,qualityTier:r.qualityTier,emailDraft:r.emailDraft,wasFallback:r.wasFallback})}\n\n`);
    if(j.status==='complete'||j.status==='cancelled')res.write(`data: ${JSON.stringify({type:'done',status:j.status,succeeded:j.succeeded,failed:j.failed,elapsed:String(j.elapsed),cost:String(j.cost)})}\n\n`);
    const a=actv.get(jid);if(a){a.listeners.add(res);req.on('close',()=>a.listeners.delete(res));}return;}
  if(req.method==='POST'&&p.match(/^\/api\/cancel\/\d+$/)){const jid=+p.split('/').pop();const j=DB.jobs.find(x=>x.id===jid&&x.uid===uid);if(j){const a=actv.get(jid);if(a)a.cancelled=true;}json(res,{ok:true});return;}
  if(req.method==='GET'&&p.match(/^\/api\/export\/\d+$/)){const jid=+p.split('/').pop();const j=DB.jobs.find(x=>x.id===jid&&x.uid===uid);if(!j){res.writeHead(404);res.end();return;}const rows=DB.rows.filter(r=>r.jobId===jid).sort((a,b)=>a.idx-b.idx);
    const esc=s=>'"'+String(s||'').replace(/"/g,'""').replace(/\n/g,' ')+'"';
    const pe=d=>{if(!d)return{s:'',b:''};const sm=d.match(/SUBJECT:\s*(.+?)(?:\n|$)/i);const bm=d.match(/BODY:\s*([\s\S]+)/i);return{s:sm?sm[1].trim():'',b:bm?bm[1].trim():d};};
    const h='Company,Status,Quality Score,Quality Tier,Research Brief,Email Subject,Email Body,Fallback,Input Tokens,Output Tokens,Provider';
    const c=rows.map(r=>{const e=pe(r.emailDraft);return[esc(r.company),esc(r.status),r.qualityScore>=0?r.qualityScore:'',esc(r.qualityTier||''),esc(r.research||r.error||''),esc(e.s),esc(e.b),r.wasFallback?'Yes':'',r.inputTokens||0,r.outputTokens||0,esc(j.provider)].join(',');});
    res.writeHead(200,{'content-type':'text/csv','content-disposition':`attachment; filename="research_${new Date().toISOString().slice(0,10)}.csv"`,'access-control-allow-origin':'*'});res.end('\uFEFF'+[h,...c].join('\r\n'));return;}
  if(req.method==='GET'&&p==='/api/jobs'){json(res,DB.jobs.filter(j=>j.uid===uid).sort((a,b)=>b.id-a.id).slice(0,50).map(j=>({id:j.id,name:j.name,provider:j.provider,templateId:j.templateId,totalRows:j.totalRows,succeeded:j.succeeded,failed:j.failed,status:j.status,cost:j.cost,elapsed:j.elapsed,created_at:j.createdAt,generateEmails:j.generateEmails,templateName:TEMPLATES[j.templateId]?.name||'Custom',templateIcon:TEMPLATES[j.templateId]?.icon||'✏️',providerName:PROVDEFS[j.provider]?.name||j.provider})));return;}
  if(req.method==='DELETE'&&p.match(/^\/api\/jobs\/\d+$/)){const jid=+p.split('/').pop();DB.rows=DB.rows.filter(r=>r.jobId!==jid);DB.jobs=DB.jobs.filter(j=>!(j.id===jid&&j.uid===uid));saveDB();json(res,{ok:true});return;}
  res.writeHead(404);res.end('Not found');
});
server.listen(PORT,process.env.HOST||'0.0.0.0',()=>{console.log(`\n  🔍 Prospect Researcher v7\n  URL: http://localhost:${PORT}\n  Data: ${DD}\n`);});
