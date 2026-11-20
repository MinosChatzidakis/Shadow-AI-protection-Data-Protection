const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8502;
const JUDGE_URL = process.env.JUDGE_URL || 'http://localhost:8000';
const RULES_FILE = path.join(__dirname, '..', 'rules.json');

// Retrieve active API Key from environment or judge/.env
function getApiKey() {
  if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim()) {
    return process.env.GEMINI_API_KEY.trim();
  }
  try {
    const envPath = path.join(__dirname, '..', 'judge', '.env');
    if (fs.existsSync(envPath)) {
      const match = fs.readFileSync(envPath, 'utf8').match(/GEMINI_API_KEY=(.+)/);
      if (match && match[1].trim()) {
        return match[1].trim();
      }
    }
  } catch (e) {}
  return '';
}

// Manager Custom Rules Storage
function loadCustomRules() {
  try {
    if (fs.existsSync(RULES_FILE)) {
      return JSON.parse(fs.readFileSync(RULES_FILE, 'utf8'));
    }
  } catch (e) {}
  return [];
}

function saveCustomRules(rules) {
  try {
    fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2), 'utf8');
    return true;
  } catch (e) {
    return false;
  }
}

// Real-time in-memory incident log store
let userLogs = [];

// High-severity DLP patterns (Hard Block)
const BLOCK_PATTERNS = [
  { label: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { label: 'API Secret Key', regex: /sk-[a-zA-Z0-9]{20,}/ },
  { label: 'Private Key', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { label: 'Database URL', regex: /(?:postgres|mysql|mongodb):\/\/[^\s]+:[^\s]+@[^\s]+/ },
  { label: 'Prompt Injection (Instruction Override)', regex: /(?:ignore|disregard|forget|bypass)\s+(?:all\s+|previous\s+|prior\s+|system\s+)*(?:instructions|rules|guidelines|prompts)/i },
  { label: 'Prompt Injection (System Prompt Leak)', regex: /(?:reveal|show|display|output|print|repeat)\s+(?:your\s+|the\s+)*(?:system\s+prompt|developer\s+instructions|initial\s+prompt|core\s+directives)/i },
  { label: 'Prompt Injection (Jailbreak Persona)', regex: /\b(?:DAN\s+mode|jailbreak|do\s+anything\s+now|unrestricted\s+ai|developer\s+mode\s+enabled|bypass\s+safety)\b/i },
  { label: 'Prompt Injection (Roleplay Exploit)', regex: /(?:pretend\s+you\s+have\s+no\s+(?:rules|filters|morals)|act\s+as\s+(?:an?\s+)?unfiltered)/i },
];

function normalizePattern(p) {
  if (!p) return null;
  let s = String(p).trim();
  // Strip inline python flags like (?i) which crash JavaScript RegExp
  s = s.replace(/^\(\?[a-zA-Z]+\)/, '');

  // Support human shortcuts (0-infinity, 0-9, numbers, a-z, iban)
  if (/^0\s*-\s*(?:9|\u221e|infinity|inf|\+|\*)$/i.test(s) || /^(?:numbers?|digits?)$/i.test(s)) {
    return '\\b\\d+\\b';
  }
  if (/^a\s*-\s*z$/i.test(s) || /^(?:letters?|words?)$/i.test(s)) {
    return '\\b[a-zA-Z]+\\b';
  }
  if (/^(?:a\s*-\s*z\s*0\s*-\s*9|0\s*-\s*9\s*a\s*-\s*z|alphanumeric)$/i.test(s)) {
    return '\\b[a-zA-Z0-9]+\\b';
  }
  if (/^iban$/i.test(s)) {
    return '\\b(?:IBAN[:\\s]*)?[A-Z]{2}\\d{2}(?:[-\\s]?[0-9A-Z]){11,30}\\b';
  }
  if (s.includes('GR') && s.includes('{23}')) {
    return '\\b(?:IBAN[:\\s]*)?GR\\d{2}(?:[-\\s]?[0-9A-Z]){23}\\b';
  }
  if (/^[A-Z]{2}\d{2}[0-9A-Z]{11,30}$/i.test(s.replace(/[\s-]+/g, ''))) {
    const raw = s.replace(/[\s-]+/g, '');
    return raw.split('').map((c, i) => i === 0 ? c : '[-\\s]*' + c).join('');
  }
  return s;
}

function createSafeRegExp(pattern, flags = 'i') {
  const norm = normalizePattern(pattern);
  if (!norm) return null;
  try {
    return new RegExp(norm, flags);
  } catch (e) {
    const escaped = String(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(escaped, flags);
  }
}

function inspectPrompt(prompt) {
  const findings = [];
  const customRules = loadCustomRules();

  // 1. Check Hard-Block Secrets & Injections
  for (const p of BLOCK_PATTERNS) {
    if (p.regex.test(prompt)) {
      findings.push(p.label);
    }
  }

  // 2. Check Manager Custom BLOCK Rules (with smart normalization)
  for (const r of customRules) {
    if (r.enabled !== false && r.action === 'BLOCK' && r.pattern) {
      const re = createSafeRegExp(r.pattern, 'i');
      let matched = false;
      if (re && re.test(prompt)) {
        matched = true;
      } else if (prompt.toLowerCase().includes(String(r.pattern).toLowerCase())) {
        matched = true;
      }
      if (matched) {
        findings.push(`Policy: ${r.name}`);
      }
    }
  }

  if (findings.length > 0) {
    return { action: 'BLOCK', processed: null, findings };
  }

  // 3. Redact sensitive PII (Greek & EU IBAN, Greek AMKA, Greek AFM, Email, Phone, Credit Cards)
  let processed = prompt;

  // Check if IBAN protection is enabled in custom rules (allows manager to pause it)
  const ibanRule = customRules.find(r => r.id === 'rule-iban' || r.id === 'rule-any-iban' || /iban/i.test(r.name));
  const isIbanEnabled = ibanRule ? (ibanRule.enabled !== false) : true;

  if (isIbanEnabled) {
    const ibanRegex = /\b(?:IBAN[:\s]*)?[A-Z]{2}\d{2}(?:[-\s]?[0-9A-Z]){11,30}\b/gi;
    if (ibanRegex.test(processed)) {
      findings.push('IBAN');
      ibanRegex.lastIndex = 0;
      processed = processed.replace(ibanRegex, '[REDACTED_IBAN]');
    }
  }

  // Credit Card (16 digits for Visa, Mastercard, Amex, Discover - avoids false positives on IBAN digits)
  const ccRegex = /\b(?:4[0-9]{3}|5[1-5][0-9]{2}|6[0-9]{3}|3[47][0-9]{2})[-\s]?(?:[0-9]{4}[-\s]?){2}[0-9]{3,4}\b/gi;
  if (ccRegex.test(processed)) {
    findings.push('CREDIT_CARD');
    ccRegex.lastIndex = 0;
    processed = processed.replace(ccRegex, '[REDACTED_CREDIT_CARD]');
  }

  // Greek AMKA (11 digits: DDMMYYXXXXX)
  const amkaRegex = /(?:(?:ΑΜΚΑ|Α\.Μ\.Κ\.Α\.|AMKA|Social\s*Security)[^\w\n]{1,6})?\b\d{6}[-\s]?\d{5}\b/gi;
  if (amkaRegex.test(processed)) {
    findings.push('AMKA');
    processed = processed.replace(amkaRegex, (m, prefix) => (prefix || '') + '[REDACTED_AMKA]');
  }

  // Greek AFM (9 digits)
  const afmRegex = /(?:(?:ΑΦΜ|Α\.Φ\.Μ\.|AFM|VAT|Tax\s*ID)[^\w\n]{1,6})?\b\d{9}\b/gi;
  if (afmRegex.test(processed)) {
    findings.push('AFM');
    processed = processed.replace(afmRegex, (m, prefix) => (prefix || '') + '[REDACTED_AFM]');
  }

  // Phone
  if (/\b(?:\+?30[-.\s]?)?[26]\d{9}\b|\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(processed)) {
    findings.push('PHONE');
    processed = processed.replace(/\b(?:\+?30[-.\s]?)?[26]\d{9}\b|\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED_PHONE]');
  }

  // Email
  if (/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/.test(processed)) {
    findings.push('EMAIL');
    processed = processed.replace(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g, '[REDACTED_EMAIL]');
  }

  // 4. Redact Manager Custom REDACT Rules (with smart normalization)
  for (const r of customRules) {
    if (r.enabled !== false && r.action === 'REDACT' && r.pattern) {
      const re = createSafeRegExp(r.pattern, 'gi');
      const tag = r.name.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/_+/g, '_').slice(0, 24);
      if (re && re.test(processed)) {
        findings.push(`Policy: ${r.name}`);
        re.lastIndex = 0;
        processed = processed.replace(re, `[REDACTED_${tag}]`);
      } else if (processed.toLowerCase().includes(String(r.pattern).toLowerCase())) {
        findings.push(`Policy: ${r.name}`);
        const esc = String(r.pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        processed = processed.replace(new RegExp(esc, 'gi'), `[REDACTED_${tag}]`);
      }
    }
  }

  if (findings.length > 0) {
    return { action: 'REDACT', processed, findings };
  }

  return { action: 'ALLOW', processed: prompt, findings: [] };
}

const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.8-flash';

// Calls Google Gemini API
function callGemini(prompt) {
  const apiKey = getApiKey();
  if (!apiKey) {
    return Promise.resolve(`[LOCAL MOCK LLM] Safe prompt processed. Forwarded: "${prompt}"`);
  }

  console.log(`[AI Gateway] Forwarding prompt to Google Gemini (${GEMINI_MODEL}) with key: ${apiKey.slice(0, 8)}...`);

  // Try Native Google Gemini endpoint first
  return new Promise((resolve) => {
    const payloadNative = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
    });

    const nativeUrl = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`;
    const req = https.request(nativeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payloadNative),
      },
      timeout: 25000,
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (parsed.candidates && parsed.candidates[0] && parsed.candidates[0].content && parsed.candidates[0].content.parts) {
            const answer = parsed.candidates[0].content.parts.map(p => p.text).join('\n');
            console.log(`[AI Gateway] Received response from Gemini ${GEMINI_MODEL} (${res.statusCode})`);
            resolve(answer);
            return;
          }
        } catch (e) {}

        // Fallback to OpenAI-compatible endpoint
        callGeminiOpenAI(prompt, apiKey, GEMINI_MODEL).then(resolve);
      });
    });

    req.on('error', (e) => {
      console.log(`[AI Gateway Network Note] ${e.message}`);
      callGeminiOpenAI(prompt, apiKey, GEMINI_MODEL).then(resolve);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(`[Gateway Notice: Timeout] Forwarded prompt: "${prompt}"`);
    });

    req.write(payloadNative);
    req.end();
  });
}

function callGeminiOpenAI(prompt, apiKey, modelToUse) {
  return new Promise((resolve) => {
    const data = JSON.stringify({
      model: modelToUse || GEMINI_MODEL,
      messages: [{ role: 'user', content: prompt }]
    });

    const req = https.request('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'x-goog-api-key': apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
      timeout: 25000,
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (parsed.choices && parsed.choices[0] && parsed.choices[0].message) {
            console.log(`[AI Gateway] OpenAI endpoint returned 200 with model ${modelToUse || GEMINI_MODEL}`);
            resolve(parsed.choices[0].message.content);
            return;
          }
          if (parsed.error) {
            console.log(`[AI Gateway] Google error on ${modelToUse}:`, parsed.error.message || parsed.error);
            if (modelToUse === 'gemini-3.8-flash' && res.statusCode === 404) {
              console.log(`[AI Gateway] gemini-3.8-flash not found on Google v1beta, trying gemini-1.5-flash fallback...`);
              callGeminiOpenAI(prompt, apiKey, 'gemini-1.5-flash').then(resolve);
              return;
            }
            resolve(`[GEMINI API NOTICE (${res.statusCode})] ${parsed.error.message || JSON.stringify(parsed.error)}`);
            return;
          }
        } catch (e) {}

        resolve(`[GEMINI RESPONSE] ${body.substring(0, 300)}`);
      });
    });

    req.on('error', (e) => {
      resolve(`[LLM Offline Notice: ${e.message}] Forwarded: "${prompt}"`);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(`[LLM Timeout] Forwarded: "${prompt}"`);
    });

    req.write(data);
    req.end();
  });
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // GET /api/rules -> Return all manager rules
  if (pathname === '/api/rules' && req.method === 'GET') {
    const rules = loadCustomRules();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ rules }));
    return;
  }

  // POST /api/rules -> Add or update a manager rule
  if (pathname === '/api/rules' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const item = JSON.parse(body);
        const rules = loadCustomRules();
        const ruleId = item.id || `rule-${Date.now()}`;
        item.id = ruleId;
        item.enabled = item.enabled !== false;
        
        const idx = rules.findIndex(r => r.id === ruleId);
        if (idx >= 0) {
          rules[idx] = item;
        } else {
          rules.push(item);
        }
        saveCustomRules(rules);
        console.log(`[Manager Policy] Added/Updated rule: "${item.name}" [Action: ${item.action}]`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', rule: item, rules }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // POST /api/rules/delete -> Delete a manager rule
  if (pathname === '/api/rules/delete' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { id } = JSON.parse(body);
        let rules = loadCustomRules();
        rules = rules.filter(r => r.id !== id);
        saveCustomRules(rules);
        console.log(`[Manager Policy] Deleted rule ID: "${id}"`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', deleted: id, rules }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // POST /api/rules/toggle -> Toggle enabled state of a rule
  if (pathname === '/api/rules/toggle' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { id } = JSON.parse(body);
        const rules = loadCustomRules();
        const r = rules.find(rule => rule.id === id);
        if (r) {
          r.enabled = !r.enabled;
          saveCustomRules(rules);
          console.log(`[Manager Policy] Toggled rule "${r.name}" to ${r.enabled}`);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', rules }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // POST /chat -> AI Gateway & DLP endpoint
  if (pathname === '/chat' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const user = payload.user || 'anonymous';
        const prompt = payload.prompt || '';
        const inspection = inspectPrompt(prompt);

        let reply = '';
        if (inspection.action === 'BLOCK') {
          reply = '⛔ PROMPT WAS BLOCKED BY POLICY - NEVER FORWARDED TO LLM';
        } else {
          reply = await callGemini(inspection.processed);
        }

        const logItem = {
          id: userLogs.length + 1,
          timestamp: new Date().toISOString(),
          client_ip: req.socket.remoteAddress || '127.0.0.1',
          username: user,
          action: inspection.action,
          findings: inspection.findings,
          original_prompt: prompt,
          forwarded_prompt: inspection.processed,
          response: reply,
        };
        userLogs.unshift(logItem);

        if (inspection.action === 'BLOCK') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'BLOCKED',
            reason: `Sensitive data detected: ${inspection.findings.join(', ')}`,
            response: reply,
          }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: inspection.action,
          findings: inspection.findings,
          forwarded_prompt: inspection.processed,
          response: reply,
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // POST /api/logs -> save a newly inspected prompt
  if (pathname === '/api/logs' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const item = JSON.parse(body);
        userLogs.unshift(item);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', id: item.id }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // POST /api/logs/clear -> clear all logs
  if (pathname === '/api/logs/clear' && req.method === 'POST') {
    userLogs = [];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'cleared' }));
    return;
  }

  // GET /api/logs or GET /logs -> return logs
  if ((pathname === '/api/logs' || pathname === '/logs') && req.method === 'GET') {
    const judgeReqUrl = `${JUDGE_URL}/logs`;
    const judgeReq = http.get(judgeReqUrl, { timeout: 800 }, (judgeRes) => {
      let body = '';
      judgeRes.on('data', chunk => body += chunk);
      judgeRes.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(parsed));
        } catch(e) {
          serveUserLogs(res);
        }
      });
    });

    judgeReq.on('error', () => {
      serveUserLogs(res);
    });

    judgeReq.on('timeout', () => {
      judgeReq.destroy();
      serveUserLogs(res);
    });
    return;
  }

  // Serve index.html
  const filePath = path.join(__dirname, 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Error loading dashboard page');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(data);
  });
});

function serveUserLogs(res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ total: userLogs.length, logs: userLogs }));
}

const activeKey = getApiKey();
server.listen(PORT, '0.0.0.0', () => {
  console.log(`=======================================================`);
  console.log(`🛡️ Shadow AI & DLP Governance Server active`);
  console.log(`👉 Open in your browser: http://localhost:${PORT}`);
  console.log(`🔑 Active Gemini Key: ${activeKey ? activeKey.slice(0, 8) + '... (' + activeKey.length + ' chars)' : 'MOCK / DEMO MODE'}`);
  console.log(`📋 Custom Rules Loaded: ${loadCustomRules().length} active policies`);
  console.log(`=======================================================`);
});
