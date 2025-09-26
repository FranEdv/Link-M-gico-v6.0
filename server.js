// server.js - LinkMágico v6.0 (Consolidado, completo)
// Features:
// - Rate limiting multi-tenant (Redis)
// - Widget /widget.js protegido por JWT (token embutido no JS servido)
// - Token usage logging (logs/token-usage.log)
// - Extraction (axios + cheerio + puppeteer fallback)
// - LGPD endpoints (consent, data deletion) + privacy page
// - Admin endpoint /admin/generate-token (protegido por ADMIN_SECRET)
// - Chat endpoint integrated with OpenAI/Groq with token logging
// - Static files served from ./public
// - Graceful shutdown and health endpoint

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const winston = require('winston');
const axios = require('axios');
const cheerio = require('cheerio');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');

// Optional: Puppeteer (graceful fallback if not installed)
let puppeteer = null;
try {
  puppeteer = require('puppeteer');
  console.log('✅ Puppeteer available');
} catch (e) {
  console.log('⚠️ Puppeteer not installed — dynamic rendering disabled');
}

// App init
const app = express();
const PORT = process.env.PORT || 3000;

// Ensure logs dir exists
const LOGS_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });

// Winston logger (console + file)
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.Console({ format: winston.format.simple() }),
    new winston.transports.File({ filename: path.join(LOGS_DIR, 'combined.log') })
  ]
});

// Trust proxy
app.set('trust proxy', true);

// Security middlewares
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: [
    process.env.FRONTEND_ORIGIN || 'http://localhost:3000',
    'https://link-m-gico-v6-0-hmpl.onrender.com'
  ],
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Requested-With','x-widget-token','x-tenant-id']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(morgan('combined'));

// Redis client (used by rate-limit store and optionally cache)
const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Rate limiting (multi-tenant)
const tenantRateLimit = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args)
  }),
  windowMs: 60 * 1000, // 1 minute
  max: (req) => {
    const tenant = (req.headers['x-tenant-id'] || '').toString();
    if (tenant.startsWith('pro_')) return 500;
    if (tenant.startsWith('scale_')) return 2000;
    return 60; // default free tier
  },
  keyGenerator: (req) => req.headers['x-tenant-id'] || req.ip,
  handler: (req, res) => res.status(429).json({ success: false, error: 'Limite de requisições atingido. Aguarde e tente novamente.' })
});
app.use(tenantRateLimit);

// Serve static files from public
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  etag: true,
  lastModified: true
}));

// ===== Analytics & cache (in-memory simple cache) =====
const analytics = {
  totalRequests: 0,
  chatRequests: 0,
  extractRequests: 0,
  errors: 0,
  activeChats: new Set(),
  startTime: Date.now(),
  responseTimeHistory: [],
  successfulExtractions: 0,
  failedExtractions: 0
};

app.use((req, res, next) => {
  const start = Date.now();
  analytics.totalRequests++;
  res.on('finish', () => {
    const responseTime = Date.now() - start;
    analytics.responseTimeHistory.push(responseTime);
    if (analytics.responseTimeHistory.length > 100) analytics.responseTimeHistory.shift();
    if (res.statusCode >= 400) analytics.errors++;
  });
  next();
});

const dataCache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes
function setCacheData(key, data) { dataCache.set(key, { data, timestamp: Date.now() }); }
function getCacheData(key) {
  const cached = dataCache.get(key);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) return cached.data;
  dataCache.delete(key);
  return null;
}

// ===== Utilities =====
function normalizeText(text) { return (text || '').replace(/\s+/g, ' ').trim(); }
function uniqueLines(text) {
  if (!text) return '';
  const seen = new Set();
  return text.split('\n').map(l => l.trim()).filter(Boolean).filter(l => {
    if (seen.has(l)) return false;
    seen.add(l);
    return true;
  }).join('\n');
}
function clampSentences(text, maxSentences = 2) {
  if (!text) return '';
  const sentences = normalizeText(text).split(/(?<=[.!?])\s+/);
  return sentences.slice(0, maxSentences).join(' ');
}
function extractBonuses(text) {
  if (!text) return [];
  const bonusKeywords = /(bônus|bonus|brinde|extra|grátis|template|planilha|checklist|e-book|ebook)/gi;
  const lines = String(text).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const bonuses = [];
  for (const line of lines) {
    if (bonusKeywords.test(line) && line.length > 10 && line.length < 200) {
      bonuses.push(line);
      if (bonuses.length >= 5) break;
    }
  }
  return Array.from(new Set(bonuses));
}

// ===== Extraction (cheerio + puppeteer fallback) =====
function extractCleanTextFromHTML(html) {
  try {
    const $ = cheerio.load(html || '');
    $('script, style, noscript, iframe, nav, footer, aside').remove();
    const textBlocks = [];
    const selectors = ['h1','h2','h3','p','li','span','div'];
    for (const sel of selectors) {
      $(sel).each((i, el) => {
        const t = normalizeText($(el).text() || '');
        if (t && t.length > 15 && t.length < 1000) textBlocks.push(t);
      });
    }
    const metaDesc = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '';
    if (metaDesc && metaDesc.trim().length > 20) textBlocks.unshift(normalizeText(metaDesc.trim()));
    const uniqueBlocks = [...new Set(textBlocks.map(b => b.trim()).filter(Boolean))];
    return uniqueBlocks.join('\n');
  } catch (err) {
    logger.warn('extractCleanTextFromHTML error:', err.message || err);
    return '';
  }
}

async function extractPageData(url) {
  const startTime = Date.now();
  try {
    if (!url) throw new Error('URL is required');
    const cacheKey = url;
    const cached = getCacheData(cacheKey);
    if (cached) {
      logger.info(`Cache hit for ${url}`);
      return cached;
    }

    logger.info(`Starting extraction for: ${url}`);
    const extractedData = {
      title: '', description: '', benefits: [], testimonials: [], cta: '',
      summary: '', cleanText: '', imagesText: [], url, extractionTime: 0,
      method: 'unknown', bonuses_detected: [], price_detected: []
    };

    let html = '';
    try {
      logger.info('Attempting Axios + Cheerio extraction...');
      const response = await axios.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; LinkMagico-Bot/6.0; +https://link-m-gico-v6-0-hmpl.onrender.com)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
        },
        timeout: 15000,
        maxRedirects: 5,
        validateStatus: status => status >= 200 && status < 400
      });
      html = response.data || '';
      const finalUrl = response.request?.res?.responseUrl || url;
      if (finalUrl && finalUrl !== url) extractedData.url = finalUrl;
      extractedData.method = 'axios-cheerio';
      logger.info(`Axios extraction ok — HTML length: ${String(html).length}`);
    } catch (axiosErr) {
      logger.warn(`Axios extraction failed for ${url}: ${axiosErr.message || axiosErr}`);
    }

    if (html && html.length > 100) {
      try {
        const $ = cheerio.load(html);
        $('script, style, noscript, iframe').remove();

        // Title
        const titleSelectors = ['h1','meta[property="og:title"]','meta[name="twitter:title"]','title'];
        for (const sel of titleSelectors) {
          const el = $(sel).first();
          const t = (el.attr && (el.attr('content') || el.text) ? (el.attr('content') || el.text()) : el.text ? el.text() : '').toString().trim();
          if (t && t.length > 5 && t.length < 200) { extractedData.title = t; break; }
        }

        // Description
        const descSelectors = ['meta[name="description"]','meta[property="og:description"]','.description','article p','main p'];
        for (const sel of descSelectors) {
          const el = $(sel).first();
          const d = (el.attr && (el.attr('content') || el.text) ? (el.attr('content') || el.text()) : el.text ? el.text() : '').toString().trim();
          if (d && d.length > 50 && d.length < 1000) { extractedData.description = d; break; }
        }

        extractedData.cleanText = extractCleanTextFromHTML(html);
        const bodyText = $('body').text() || '';
        const summaryText = bodyText.replace(/\s+/g,' ').trim();
        const sentences = summaryText.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);
        extractedData.summary = sentences.slice(0,3).join('. ').substring(0,400) + (sentences.length > 3 ? '...' : '');
        extractedData.bonuses_detected = extractBonuses(bodyText);

        logger.info(`Cheerio extraction completed for ${url}`);
        analytics.successfulExtractions++;
      } catch (err) {
        logger.warn('Cheerio parsing failed:', err.message || err);
        analytics.failedExtractions++;
      }
    }

    // Puppeteer fallback when necessary
    const minAcceptableLength = 200;
    if ((!extractedData.cleanText || extractedData.cleanText.length < minAcceptableLength) && puppeteer) {
      logger.info('Falling back to Puppeteer for dynamic rendering...');
      let browser = null;
      try {
        browser = await puppeteer.launch({
          headless: true,
          args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage'],
          defaultViewport: { width: 1200, height: 800 },
          timeout: 20000
        });
        const page = await browser.newPage();
        await page.setUserAgent('Mozilla/5.0 (compatible; LinkMagico-Bot/6.0)');
        await page.setRequestInterception(true);
        page.on('request', (req) => {
          const rt = req.resourceType();
          if (['stylesheet','font','image','media'].includes(rt)) req.abort();
          else req.continue();
        });

        try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 }); }
        catch (gotoErr) { logger.warn('Puppeteer goto failed:', gotoErr.message || gotoErr); }

        // quick scroll
        try {
          await page.evaluate(async () => {
            await new Promise((resolve) => {
              let total = 0, dist = 300;
              const timer = setInterval(() => {
                window.scrollBy(0, dist); total += dist;
                if (total >= document.body.scrollHeight || total > 3000) { clearInterval(timer); resolve(); }
              }, 100);
            });
          });
          await page.waitForTimeout(500);
        } catch (scrollErr) { logger.warn('Puppeteer scroll failed:', scrollErr.message || scrollErr); }

        const puppeteerData = await page.evaluate(() => {
          const clone = document.cloneNode(true);
          const removeEls = clone.querySelectorAll('script, style, noscript, iframe');
          removeEls.forEach(e => e.remove());
          return {
            bodyText: clone.body ? clone.body.innerText : '',
            title: document.title || '',
            metaDescription: document.querySelector('meta[name="description"]')?.content || ''
          };
        });

        const cleanedText = normalizeText(puppeteerData.bodyText || '').replace(/\s{2,}/g,' ');
        const lines = cleanedText.split('\n').map(l => l.trim()).filter(Boolean);
        const uniq = [...new Set(lines)];
        const finalText = uniq.join('\n');

        if (finalText && finalText.length > (extractedData.cleanText || '').length) {
          extractedData.cleanText = finalText;
          extractedData.method = 'puppeteer';
          if (!extractedData.title && puppeteerData.title) extractedData.title = puppeteerData.title.slice(0,200);
          if (!extractedData.description && puppeteerData.metaDescription) extractedData.description = puppeteerData.metaDescription.slice(0,500);
          const sents = finalText.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);
          if (!extractedData.summary && sents.length) extractedData.summary = sents.slice(0,3).join('. ').substring(0,400) + (sents.length > 3 ? '...' : '');
          extractedData.bonuses_detected = extractBonuses(finalText);
          analytics.successfulExtractions++;
        }

      } catch (err) {
        logger.warn('Puppeteer extraction failed:', err.message || err);
        analytics.failedExtractions++;
      } finally {
        try { if (browser) await browser.close(); } catch (e) {}
      }
    }

    // Final processing
    try {
      if (extractedData.cleanText) extractedData.cleanText = uniqueLines(extractedData.cleanText);
      if (!extractedData.title && extractedData.cleanText) {
        const firstLine = extractedData.cleanText.split('\n').find(l => l && l.length > 10 && l.length < 150);
        if (firstLine) extractedData.title = firstLine.slice(0,150);
      }
      if (!extractedData.summary && extractedData.cleanText) {
        const sents = extractedData.cleanText.split(/(?<=[.!?])\s+/).filter(Boolean);
        extractedData.summary = sents.slice(0,3).join('. ').slice(0,400) + (sents.length > 3 ? '...' : '');
      }
    } catch (procErr) { logger.warn('Final processing failed:', procErr.message || procErr); }

    extractedData.extractionTime = Date.now() - startTime;
    setCacheData(cacheKey, extractedData);
    logger.info(`Extraction completed for ${url} in ${extractedData.extractionTime}ms using ${extractedData.method}`);
    return extractedData;

  } catch (err) {
    analytics.failedExtractions++;
    logger.error(`Page extraction failed for ${url}:`, err.message || err);
    return {
      title: '', description: '', benefits: [], testimonials: [], cta: '',
      summary: 'Erro ao extrair dados da página. Verifique se a URL está acessível.',
      cleanText: '', imagesText: [], url: url || '', extractionTime: Date.now()-startTime,
      method: 'failed', error: err.message || String(err), bonuses_detected: [], price_detected: []
    };
  }
}

// ===== Token usage logging (per tenant) =====
const TOKEN_USAGE_LOG = path.join(LOGS_DIR, 'token-usage.log');
function logTokenUsage(tenantId, model, tokensUsed, provider) {
  try {
    const entry = { id: crypto.randomUUID(), tenantId: tenantId || 'anon', model, tokensUsed, provider, timestamp: new Date().toISOString() };
    fs.appendFileSync(TOKEN_USAGE_LOG, JSON.stringify(entry) + '\n');
  } catch (err) {
    logger.warn('Failed to log token usage:', err.message || err);
  }
}

// ===== LLM Integration (Groq + OpenAI wrappers) =====
async function callGroq(messages, temperature = 0.4, maxTokens = 300, tenantId = 'anon') {
  if (!process.env.GROQ_API_KEY) throw new Error('GROQ_API_KEY missing');
  const payload = { model: process.env.GROQ_MODEL || 'llama-3.1-70b-versatile', messages, temperature, max_tokens: maxTokens };
  const url = process.env.GROQ_API_BASE || 'https://api.groq.com/openai/v1/chat/completions';
  const headers = { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' };
  const res = await axios.post(url, payload, { headers, timeout: 15000 });
  if (!(res && res.status >= 200 && res.status < 300)) throw new Error(`GROQ API failed with status ${res?.status}`);
  if (res.data?.usage?.total_tokens) logTokenUsage(tenantId, payload.model, res.data.usage.total_tokens, 'groq');
  if (res.data?.choices?.[0]?.message?.content) return res.data.choices[0].message.content;
  throw new Error('Invalid GROQ API response format');
}

async function callOpenAI(messages, temperature = 0.2, maxTokens = 300, tenantId = 'anon') {
  if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing');
  const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
  const url = process.env.OPENAI_API_BASE || 'https://api.openai.com/v1/chat/completions';
  const payload = { model, messages, temperature, max_tokens: maxTokens };
  const headers = { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' };
  const res = await axios.post(url, payload, { headers, timeout: 15000 });
  if (!(res && res.status >= 200 && res.status < 300)) throw new Error(`OpenAI API failed with status ${res?.status}`);
  if (res.data?.usage?.total_tokens) logTokenUsage(tenantId, model, res.data.usage.total_tokens, 'openai');
  if (res.data?.choices?.[0]?.message?.content) return res.data.choices[0].message.content;
  throw new Error('Invalid OpenAI API response format');
}

// ===== Response generation helpers =====
const NOT_FOUND_MSG = "Não encontrei essa informação específica na página. Posso te ajudar com outras dúvidas?";

function shouldActivateSalesMode(instructions = '') {
  if (!instructions) return false;
  const text = String(instructions || '').toLowerCase();
  return /sales_mode:on|consultivo|vendas|venda|cta|sempre.*link|finalize.*cta/i.test(text);
}

function generateLocalResponse(userMessage, pageData = {}, instructions = '') {
  const q = (userMessage || '').toLowerCase();
  const salesMode = shouldActivateSalesMode(instructions);

  if (/preço|valor|quanto custa/.test(q)) return 'Para informações sobre preços, consulte diretamente a página do produto.';
  if (/como funciona|funcionamento/.test(q)) {
    const summary = pageData.summary || pageData.description;
    if (summary) return salesMode ? `${clampSentences(summary,2)} Quer saber mais detalhes?` : clampSentences(summary,2);
  }
  if (/bônus|bonus/.test(q)) {
    if (pageData.bonuses_detected && pageData.bonuses_detected.length > 0) {
      const bonuses = pageData.bonuses_detected.slice(0,2).join(', ');
      return salesMode ? `Inclui: ${bonuses}. Quer garantir todos os bônus?` : `Bônus: ${bonuses}`;
    }
    return 'Informações sobre bônus não encontradas.';
  }
  if (pageData.summary) return salesMode ? `${clampSentences(pageData.summary,2)} Posso te ajudar com mais alguma dúvida?` : clampSentences(pageData.summary,2);
  return NOT_FOUND_MSG;
}

async function generateAIResponse(userMessage, pageData = {}, conversation = [], instructions = '', tenantId = 'anon') {
  const start = Date.now();
  try {
    const salesMode = shouldActivateSalesMode(instructions);

    // Direct link handling
    if (/\b(link|página|site|comprar|inscrever)\b/i.test(userMessage) && pageData && pageData.url) {
      const url = pageData.url;
      if (salesMode) return `Aqui está o link oficial: ${url}\n\nQuer que eu te ajude com mais alguma informação sobre o produto?`;
      return `Aqui está o link: ${url}`;
    }

    const systemLines = [
      "Você é um assistente especializado em vendas online.",
      "Responda de forma clara, útil e concisa.",
      "Use apenas informações da página extraída.",
      "Nunca invente dados que não estejam disponíveis.",
      "Máximo 2-3 frases por resposta."
    ];
    if (salesMode) {
      systemLines.push("Tom consultivo e entusiasmado.");
      systemLines.push("Termine com pergunta que leve à compra.");
    }
    const systemPrompt = systemLines.join('\n');

    const contextLines = [];
    if (pageData.title) contextLines.push(`Produto: ${pageData.title}`);
    if (pageData.bonuses_detected && pageData.bonuses_detected.length > 0) contextLines.push(`Bônus: ${pageData.bonuses_detected.slice(0,3).join(', ')}`);
    const contentExcerpt = (pageData.summary || pageData.cleanText || '').slice(0,1000);
    if (contentExcerpt) contextLines.push(`Informações: ${contentExcerpt}`);

    const pageContext = contextLines.join('\n');
    const userPrompt = `${instructions ? `Instruções: ${instructions}\n\n` : ''}Contexto:\n${pageContext}\n\nPergunta: ${userMessage}\n\nResponda de forma concisa usando apenas as informações fornecidas.`;

    const messages = [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }];

    let response = null;
    let usedProvider = 'local';

    if (process.env.GROQ_API_KEY) {
      try { response = await callGroq(messages, 0.4, 250, tenantId); usedProvider = 'groq'; logger.info('GROQ call success'); }
      catch (err) { logger.warn('GROQ failed:', err.message || err); }
    }
    if (!response && process.env.OPENAI_API_KEY) {
      try { response = await callOpenAI(messages, 0.2, 250, tenantId); usedProvider = 'openai'; logger.info('OpenAI call success'); }
      catch (err) { logger.warn('OpenAI failed:', err.message || err); }
    }
    if (!response || !String(response).trim()) {
      response = generateLocalResponse(userMessage, pageData, instructions);
      usedProvider = 'local';
    }

    const final = clampSentences(String(response).trim(), 3);
    logger.info(`AI response generated in ${Date.now()-start}ms using ${usedProvider}`);
    return final;

  } catch (err) {
    logger.error('AI generation failed:', err.message || err);
    return NOT_FOUND_MSG;
  }
}

// ===== Widget token validation middleware (single source) =====
function validateWidgetToken(req, res, next) {
  const token = req.query.token || req.headers['x-widget-token'];
  if (!token) return res.status(401).send('// Widget token ausente; widget não autorizado.');

  try {
    const decoded = jwt.verify(token, process.env.WIDGET_SECRET || 'super_secret_key');
    req.tenant = decoded.tenantId;
    req.widgetToken = token;
    next();
  } catch (err) {
    logger.warn('Widget token inválido:', err.message || err);
    return res.status(403).send('// Widget token inválido; widget não autorizado.');
  }
}

// ===== Health endpoint =====
app.get('/health', (req, res) => {
  const uptime = process.uptime();
  const avgResponseTime = analytics.responseTimeHistory.length > 0 ? Math.round(analytics.responseTimeHistory.reduce((a,b) => a+b, 0) / analytics.responseTimeHistory.length) : 0;
  res.json({
    status: 'healthy',
    uptime: Math.floor(uptime),
    timestamp: new Date().toISOString(),
    version: '6.0.0',
    analytics: {
      totalRequests: analytics.totalRequests,
      chatRequests: analytics.chatRequests,
      extractRequests: analytics.extractRequests,
      errors: analytics.errors,
      activeChats: analytics.activeChats.size,
      avgResponseTime,
      successfulExtractions: analytics.successfulExtractions,
      failedExtractions: analytics.failedExtractions,
      cacheSize: dataCache.size
    },
    services: {
      groq: !!process.env.GROQ_API_KEY,
      openai: !!process.env.OPENAI_API_KEY,
      puppeteer: !!puppeteer,
      redis: !!redisClient
    }
  });
});

// ===== Main routes =====

// Root -> serve index.html from public
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// chat.html -> redirect to /chatbot
app.get('/chat.html', (req, res) => {
  const robotName = req.query.name || 'Assistente IA';
  const url = req.query.url || '';
  const instructions = req.query.instructions || '';
  res.redirect(`/chatbot?name=${encodeURIComponent(robotName)}&url=${encodeURIComponent(url)}&instructions=${encodeURIComponent(instructions)}`);
});

// /extract - extracts page data
app.post('/extract', async (req, res) => {
  analytics.extractRequests++;
  try {
    const { url, instructions, robotName } = req.body || {};
    logger.info('📥 Extract request for:', url);
    if (!url) return res.status(400).json({ success: false, error: 'URL é obrigatório' });

    try { new URL(url); } catch (e) { return res.status(400).json({ success: false, error: 'URL inválido' }); }

    const extracted = await extractPageData(url);
    if (instructions) extracted.custom_instructions = instructions;
    if (robotName) extracted.robot_name = robotName;
    logger.info('✅ Extração concluída');
    return res.json({ success: true, data: extracted });

  } catch (err) {
    analytics.errors++;
    logger.error('/extract error:', err.message || err);
    return res.status(500).json({ success: false, error: 'Erro interno ao extrair página: ' + (err.message || 'Erro desconhecido') });
  }
});

// /chat-universal - main chat endpoint
app.post('/chat-universal', validateWidgetToken, async (req, res) => {
  analytics.chatRequests++;
  try {
    const { message, pageData, url, conversationId, instructions = '', robotName } = req.body || {};
    if (!message) return res.status(400).json({ success: false, error: 'Mensagem é obrigatória' });

    if (conversationId) {
      analytics.activeChats.add(conversationId);
      setTimeout(() => analytics.activeChats.delete(conversationId), 30 * 60 * 1000);
    }

    let processedPageData = pageData;
    if (!processedPageData && url) processedPageData = await extractPageData(url);

    const tenantId = req.tenant || extractTenantFromReq(req) || 'anon';
    const aiResponse = await generateAIResponse(message, processedPageData || {}, [], instructions, tenantId);

    let finalResponse = aiResponse;
    if (processedPageData?.url && !String(finalResponse).includes(processedPageData.url)) {
      finalResponse = `${finalResponse}\n\n${processedPageData.url}`;
    }

    return res.json({
      success: true,
      response: finalResponse,
      bonuses_detected: processedPageData?.bonuses_detected || [],
      metadata: {
        hasPageData: !!processedPageData,
        contentLength: processedPageData?.cleanText?.length || 0,
        method: processedPageData?.method || 'none'
      }
    });

  } catch (err) {
    analytics.errors++;
    logger.error('Chat endpoint error:', err.message || err);
    return res.status(500).json({ success: false, error: 'Erro interno ao gerar resposta: ' + (err.message || 'Erro desconhecido') });
  }
});

// ===== Widget route (protected) =====
// Widget served here will contain the token that was passed when requesting /widget.js?token=...
app.get('/widget.js', validateWidgetToken, (req, res) => {
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  const tokenForClient = (req.widgetToken || '').replace(/`/g, '');
  const tenant = req.tenant || 'anon';
  res.send(`// LinkMágico Protected Widget v6.0 - Tenant: ${tenant}
(function() {
  'use strict';
  var WIDGET_TOKEN = '${tokenForClient}';
  if (window.LinkMagicoWidget) return;

  var LinkMagicoWidget = {
    config: {
      position: 'bottom-right',
      primaryColor: '#3b82f6',
      robotName: 'Assistente IA',
      salesUrl: '',
      instructions: '',
      apiBase: window.location.origin
    },

    init: function(userConfig) {
      this.config = Object.assign(this.config, userConfig || {});
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', this.createWidget.bind(this));
      } else {
        this.createWidget();
      }
    },

    createWidget: function() {
      var container = document.createElement('div');
      container.id = 'linkmagico-widget';
      container.innerHTML = this.getHTML();
      this.addStyles();
      document.body.appendChild(container);
      this.bindEvents();
    },

    getHTML: function() {
      return '<div class="lm-button" id="lm-button"><i class="fas fa-comments"></i></div>' +
             '<div class="lm-chat" id="lm-chat" style="display:none;">' +
             '<div class="lm-header"><span>' + this.config.robotName + '</span><button id="lm-close">×</button></div>' +
             '<div class="lm-messages" id="lm-messages">' +
             '<div class="lm-msg lm-bot">Olá! Como posso ajudar?</div></div>' +
             '<div class="lm-input"><input id="lm-input" placeholder="Digite..."><button id="lm-send">➤</button></div></div>';
    },

    addStyles: function() {
      if (document.getElementById('lm-styles')) return;
      var css = '#linkmagico-widget{position:fixed;right:20px;bottom:20px;z-index:999999;font-family:sans-serif}' +
               '.lm-button{width:60px;height:60px;background:' + this.config.primaryColor + ';border-radius:50%;display:flex;align-items:center;justify-content:center;color:white;font-size:24px;cursor:pointer;box-shadow:0 4px 20px rgba(0,0,0,0.15);transition:all 0.3s}' +
               '.lm-chat{position:absolute;bottom:80px;right:0;width:350px;height:500px;background:white;border-radius:15px;box-shadow:0 10px 40px rgba(0,0,0,0.15);display:flex;flex-direction:column;overflow:hidden}' +
               '.lm-header{background:' + this.config.primaryColor + ';color:white;padding:15px;display:flex;justify-content:space-between;align-items:center}' +
               '.lm-close{background:none;border:none;color:white;cursor:pointer;font-size:20px}' +
               '.lm-messages{flex:1;padding:15px;overflow-y:auto;display:flex;flex-direction:column;gap:10px}' +
               '.lm-msg{max-width:80%;padding:10px 15px;border-radius:12px;font-size:14px}' +
               '.lm-bot{background:#f1f3f4;color:#333;align-self:flex-start}' +
               '.lm-user{background:' + this.config.primaryColor + ';color:white;align-self:flex-end}' +
               '.lm-input{padding:15px;display:flex;gap:10px}' +
               '.lm-input input{flex:1;border:1px solid #e0e0e0;border-radius:20px;padding:10px 15px;outline:none}' +
               '.lm-input button{background:' + this.config.primaryColor + ';border:none;border-radius:50%;width:40px;height:40px;color:white;cursor:pointer}';
      var style = document.createElement('style');
      style.id = 'lm-styles';
      style.textContent = css;
      document.head.appendChild(style);
    },

    bindEvents: function() {
      var self = this;
      document.addEventListener('click', function(ev) {
        if (ev.target && ev.target.id === 'lm-button') {
          var chat = document.getElementById('lm-chat');
          if (chat) chat.style.display = chat.style.display === 'flex' ? 'none' : 'flex';
        }
        if (ev.target && ev.target.id === 'lm-close') {
          document.getElementById('lm-chat').style.display = 'none';
        }
        if (ev.target && ev.target.id === 'lm-send') self.send();
      });
      document.addEventListener('keypress', function(e){
        if (e.key === 'Enter' && document.activeElement && document.activeElement.id === 'lm-input') self.send();
      });
    },

    send: function() {
      var input = document.getElementById('lm-input');
      var msg = input ? input.value.trim() : '';
      if (!msg) return;
      this.addMsg(msg, true);
      if (input) input.value = '';
      var self = this;

      fetch(this.config.apiBase + '/chat-universal', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'x-widget-token': WIDGET_TOKEN},
        body: JSON.stringify({
          message: msg,
          robotName: this.config.robotName,
          instructions: this.config.instructions,
          url: this.config.salesUrl,
          conversationId: 'widget_' + Date.now()
        })
      }).then(function(r){ return r.json(); })
      .then(function(d){
        if (d.success) self.addMsg(d.response, false);
        else self.addMsg('Erro. Tente novamente.', false);
      })
      .catch(function(){ self.addMsg('Erro de conexão.', false); });
    },

    addMsg: function(text, isUser) {
      var div = document.createElement('div');
      div.className = 'lm-msg ' + (isUser ? 'lm-user' : 'lm-bot');
      div.textContent = text;
      var container = document.getElementById('lm-messages');
      if (container) { container.appendChild(div); container.scrollTop = container.scrollHeight; }
    }
  };

  window.LinkMagicoWidget = LinkMagicoWidget;
})();
`);
});

// ===== LGPD routes (privacy + deletion pages + APIs) =====

// Dynamic privacy policy page
app.get('/privacy.html', (req, res) => {
  res.set('Content-Type','text/html; charset=utf-8');
  res.send(generatePrivacyPolicyHTML());
});

// Data deletion page (HTML)
app.get('/excluir-dados', (req, res) => {
  res.set('Content-Type','text/html; charset=utf-8');
  res.send(generateDataDeletionHTML());
});

// Redirect aliases
app.get('/privacy-policy', (req, res) => res.redirect('/privacy.html'));
app.get('/delete-data', (req, res) => res.redirect('/excluir-dados'));
app.get('/data-deletion', (req, res) => res.redirect('/excluir-dados'));

// API: log consent
app.post('/api/log-consent', (req, res) => {
  try {
    const consentData = req.body || {};
    const ipHash = hashIP(req.ip || req.connection.remoteAddress || 'unknown');
    const logEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      consent: consentData,
      ipHash,
      userAgent: req.headers['user-agent'] || 'unknown',
      referer: req.headers.referer || ''
    };
    const logDir = path.join(__dirname, 'logs','consent');
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, `consent-${new Date().getFullYear()}-${String(new Date().getMonth()+1).padStart(2,'0')}.log`);
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
    logger.info(`Consent saved: ${logEntry.id}`);
    res.json({ success: true, consentId: logEntry.id });
  } catch (err) {
    logger.error('Erro log-consent:', err);
    res.status(500).json({ error: 'Falha ao registrar consentimento' });
  }
});

// API: data deletion request
app.post('/api/data-deletion', (req, res) => {
  try {
    const requestData = req.body || {};
    const requestId = crypto.randomUUID();
    const ipHash = hashIP(req.ip || req.connection.remoteAddress || 'unknown');
    const deletionRequest = {
      id: requestId, timestamp: new Date().toISOString(),
      email: requestData.email, robotName: requestData.robotName, url: requestData.url,
      requestType: requestData.requestType, dataTypes: requestData.dataTypes,
      reason: requestData.reason, status: 'pending', ipHash,
      userAgent: req.headers['user-agent'] || 'unknown',
      processingDeadline: new Date(Date.now() + 72*60*60*1000).toISOString()
    };
    const logDir = path.join(__dirname, 'logs','deletion');
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, `deletion-${new Date().getFullYear()}-${String(new Date().getMonth()+1).padStart(2,'0')}.log`);
    fs.appendFileSync(logFile, JSON.stringify(deletionRequest) + '\n');
    logger.info(`Deletion request recorded: ${requestId}`);
    res.json({ success: true, requestId, message: 'Solicitação recebida. Será processada em até 72 horas.' });
  } catch (err) {
    logger.error('Erro data-deletion:', err);
    res.status(500).json({ error: 'Falha ao processar solicitação' });
  }
});

// Fallback route (serve index.html for SPA)
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  return res.status(404).send('Not found');
});

// ===== Admin endpoint: generate token (protected by ADMIN_SECRET) =====
// Use this endpoint to issue widget tokens to tenants. Example: POST /admin/generate-token { tenantId: "pro_loja123", expiresIn: "7d" }
app.post('/admin/generate-token', (req, res) => {
  const adminSecret = req.headers['x-admin-secret'] || req.body.adminSecret;
  if (!adminSecret || adminSecret !== (process.env.ADMIN_SECRET || 'admin_change_me')) {
    return res.status(403).json({ success: false, error: 'Admin secret inválido' });
  }
  const { tenantId, expiresIn = '7d' } = req.body || {};
  if (!tenantId) return res.status(400).json({ success: false, error: 'tenantId é obrigatório' });
  const token = jwt.sign({ tenantId }, process.env.WIDGET_SECRET || 'super_secret_key', { expiresIn });
  return res.json({ success: true, tenantId, token, expiresIn });
});

// ===== Helpers for privacy pages generation =====
function hashIP(ip) {
  if (!ip) return 'unknown';
  return crypto.createHash('sha256').update(ip + (process.env.IP_SALT || 'default_salt')).digest('hex').substring(0,16);
}

function generatePrivacyPolicyHTML() {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Política de Privacidade - LinkMágico v6.0</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>:root{--primary:#3b82f6;--dark:#0f172a;--glass-bg:rgba(30,41,59,0.8);--glass-border:rgba(148,163,184,0.2)}body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#334155 100%);color:#f8fafc;margin:0;padding:0} .container{max-width:800px;margin:0 auto;padding:2rem} .header{padding:2rem;background:var(--glass-bg);border-radius:20px;border:1px solid var(--glass-border);text-align:center} .content{background:var(--glass-bg);padding:2rem;border-radius:12px;border:1px solid var(--glass-border);margin-top:1rem}</style>
</head><body><div class="container"><div class="header"><h1>🛡️ Política de Privacidade</h1><p>LinkMágico v6.0 - LGPD</p></div><div class="content"><h2>Informações Gerais</h2><p>Descrição de coleta e tratamento de dados...</p><h3>Contato</h3><p>DPO: dpo@linkmagico.com</p></div></div></body></html>`;
}

function generateDataDeletionHTML() {
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Exclusão de Dados - LinkMágico</title></head><body><h1>Exclusão de Dados</h1><form id="delForm"><input name="email" placeholder="email" required><button>Solicitar</button></form><script>document.getElementById('delForm').addEventListener('submit', async(e)=>{e.preventDefault();alert('Exclusão solicitada (demo)');});</script></body></html>`;
}

// ===== Start server =====
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`🚀 LinkMágico Server v6.0 rodando na porta ${PORT}`);
  logger.info(`Health: http://localhost:${PORT}/health`);
  logger.info(`Chatbot: http://localhost:${PORT}/chatbot`);
  logger.info(`Widget (protected): http://localhost:${PORT}/widget.js?token=...`);
  logger.info(`Privacy: http://localhost:${PORT}/privacy.html`);
  logger.info(`Data deletion: http://localhost:${PORT}/excluir-dados`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received — shutting down');
  server.close(() => { logger.info('Server terminated'); process.exit(0); });
});
process.on('SIGINT', () => {
  logger.info('SIGINT received — shutting down');
  server.close(() => { logger.info('Server terminated'); process.exit(0); });
});

module.exports = app;
