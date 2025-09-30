// server.js - LinkMágico v6.0 Final (API Key → LGPD → Ferramenta)
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

let puppeteer = null;
try {
    puppeteer = require('puppeteer');
    console.log('✅ Puppeteer loaded - Dynamic rendering available');
} catch (e) {
    console.log('⚠️ Puppeteer not installed - Using basic extraction only');
}

const app = express();

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

app.set('trust proxy', true);

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ['https://link-m-gico-v6-0-hmpl.onrender.com', 'http://localhost:3000', 'http://localhost:8080'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(morgan('combined'));

function loadApiKeys() {
    try {
        const dataFile = path.join(__dirname, 'data', 'api_keys.json');
        if (!fs.existsSync(dataFile)) {
            const dataDir = path.join(__dirname, 'data');
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            
            const initialData = {
                apiKeys: [],
                saved: new Date().toISOString()
            };
            fs.writeFileSync(dataFile, JSON.stringify(initialData, null, 2));
            return new Map();
        }
        
        const data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
        const keyMap = new Map();
        
        if (data.apiKeys && Array.isArray(data.apiKeys)) {
            data.apiKeys.forEach(([key, info]) => {
                if (key && info && info.active) {
                    keyMap.set(key, info);
                }
            });
        }
        
        console.log(`📊 Carregadas ${keyMap.size} API keys ativas`);
        return keyMap;
    } catch (error) {
        console.error('❌ Erro ao carregar API keys:', error);
        return new Map();
    }
}

let apiKeysCache = loadApiKeys();
let lastCacheUpdate = Date.now();
const CACHE_TTL = 5 * 60 * 1000;

function refreshApiKeysCache() {
    const now = Date.now();
    if (now - lastCacheUpdate > CACHE_TTL) {
        apiKeysCache = loadApiKeys();
        lastCacheUpdate = now;
    }
}

function validateApiKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
        return { valid: false, reason: 'API key inválida' };
    }
    
    if (!apiKey.startsWith('lm_')) {
        return { valid: false, reason: 'Formato de API key inválido' };
    }
    
    refreshApiKeysCache();
    
    const keyInfo = apiKeysCache.get(apiKey);
    if (!keyInfo) {
        return { valid: false, reason: 'API key não encontrada' };
    }
    
    if (!keyInfo.active) {
        return { valid: false, reason: 'API key desativada' };
    }
    
    return { 
        valid: true, 
        client: {
            nome: keyInfo.client || 'Cliente',
            plano: keyInfo.plan || 'pro',
            created: keyInfo.created,
            limits: keyInfo.limits
        }
    };
}

function authMiddleware(req, res, next) {
    const publicRoutes = [
        '/privacy.html',
        '/privacy-policy',
        '/excluir-dados',
        '/delete-data',
        '/data-deletion',
        '/api/log-consent',
        '/api/data-deletion'
    ];
    
    if (publicRoutes.includes(req.path)) {
        return next();
    }
    
    const apiKey = req.headers['x-api-key'] || req.query.api_key || req.query.key;
    
    if (!apiKey) {
        return res.status(401).json({ 
            error: 'API key obrigatória',
            hint: 'Acesse através da interface principal'
        });
    }
    
    const validation = validateApiKey(apiKey);
    
    if (!validation.valid) {
        console.log(`🔒 API key rejeitada: ${validation.reason}`);
        return res.status(401).json({ 
            error: 'API key inválida',
            reason: validation.reason
        });
    }
    
    req.cliente = validation.client;
    req.apiKey = apiKey;
    
    console.log(`✅ Cliente autenticado: ${validation.client.nome}`);
    next();
}

app.use(authMiddleware);

app.use(express.static('public', {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));

const analytics = {
    totalRequests: 0,
    chatRequests: 0,
    extractRequests: 0,
    errors: 0,
    activeChats: new Set(),
    startTime: Date.now(),
    responseTimeHistory: [],
    successfulExtractions: 0,
    failedExtractions: 0,
    authenticatedRequests: 0,
    uniqueClients: new Set()
};

app.use((req, res, next) => {
    const start = Date.now();
    analytics.totalRequests++;

    if (req.cliente) {
        analytics.authenticatedRequests++;
        analytics.uniqueClients.add(req.cliente.nome);
    }

    res.on('finish', () => {
        const responseTime = Date.now() - start;
        analytics.responseTimeHistory.push(responseTime);
        if (analytics.responseTimeHistory.length > 100) analytics.responseTimeHistory.shift();
        if (res.statusCode >= 400) analytics.errors++;
    });

    next();
});

const dataCache = new Map();
const CACHE_TTL_DATA = 30 * 60 * 1000;

function setCacheData(key, data) {
    dataCache.set(key, { data, timestamp: Date.now() });
}

function getCacheData(key) {
    const cached = dataCache.get(key);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_DATA) {
        return cached.data;
    }
    dataCache.delete(key);
    return null;
}

function normalizeText(text) {
    return (text || '').replace(/\s+/g, ' ').trim();
}

function uniqueLines(text) {
    if (!text) return '';
    const seen = new Set();
    return text.split('\n')
        .map(line => line.trim())
        .filter(Boolean)
        .filter(line => {
            if (seen.has(line)) return false;
            seen.add(line);
            return true;
        })
        .join('\n');
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

function extractCleanTextFromHTML(html) {
    try {
        const $ = cheerio.load(html || '');
        $('script, style, noscript, iframe, nav, footer, aside').remove();

        const textBlocks = [];
        const selectors = ['h1', 'h2', 'h3', 'p', 'li', 'span', 'div'];

        for (const selector of selectors) {
            $(selector).each((i, element) => {
                const text = normalizeText($(element).text() || '');
                if (text && text.length > 15 && text.length < 1000) {
                    textBlocks.push(text);
                }
            });
        }

        const metaDesc = $('meta[name="description"]').attr('content') ||
            $('meta[property="og:description"]').attr('content') || '';
        if (metaDesc && metaDesc.trim().length > 20) {
            textBlocks.unshift(normalizeText(metaDesc.trim()));
        }

        const uniqueBlocks = [...new Set(textBlocks.map(b => b.trim()).filter(Boolean))];
        return uniqueBlocks.join('\n');
    } catch (error) {
        logger.warn('extractCleanTextFromHTML error:', error.message || error);
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
            title: '',
            description: '',
            benefits: [],
            testimonials: [],
            cta: '',
            summary: '',
            cleanText: '',
            imagesText: [],
            url: url,
            extractionTime: 0,
            method: 'unknown',
            bonuses_detected: [],
            price_detected: []
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
            logger.info(`Axios extraction successful, HTML length: ${String(html).length}`);
        } catch (axiosError) {
            logger.warn(`Axios extraction failed for ${url}: ${axiosError.message || axiosError}`);
        }

        if (html && html.length > 100) {
            try {
                const $ = cheerio.load(html);
                $('script, style, noscript, iframe').remove();

                const titleSelectors = ['h1', 'meta[property="og:title"]', 'meta[name="twitter:title"]', 'title'];
                for (const selector of titleSelectors) {
                    const el = $(selector).first();
                    const title = (el.attr && (el.attr('content') || el.text) ? (el.attr('content') || el.text()) : el.text ? el.text() : '').toString().trim();
                    if (title && title.length > 5 && title.length < 200) {
                        extractedData.title = title;
                        break;
                    }
                }

                const descSelectors = ['meta[name="description"]', 'meta[property="og:description"]', '.description', 'article p', 'main p'];
                for (const selector of descSelectors) {
                    const el = $(selector).first();
                    const desc = (el.attr && (el.attr('content') || el.text) ? (el.attr('content') || el.text()) : el.text ? el.text() : '').toString().trim();
                    if (desc && desc.length > 50 && desc.length < 1000) {
                        extractedData.description = desc;
                        break;
                    }
                }

                extractedData.cleanText = extractCleanTextFromHTML(html);

                const bodyText = $('body').text() || '';
                const summaryText = bodyText.replace(/\s+/g, ' ').trim();
                const sentences = summaryText.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);
                extractedData.summary = sentences.slice(0, 3).join('. ').substring(0, 400) + (sentences.length > 3 ? '...' : '');

                extractedData.bonuses_detected = extractBonuses(bodyText);

                logger.info(`Cheerio extraction completed for ${url}`);
                analytics.successfulExtractions++;
            } catch (cheerioError) {
                logger.warn(`Cheerio parsing failed: ${cheerioError.message || cheerioError}`);
                analytics.failedExtractions++;
            }
        }

        const minAcceptableLength = 200;
        if ((!extractedData.cleanText || extractedData.cleanText.length < minAcceptableLength) && puppeteer) {
            logger.info('Trying Puppeteer for dynamic rendering...');
            let browser = null;
            try {
                browser = await puppeteer.launch({
                    headless: true,
                    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
                    defaultViewport: { width: 1200, height: 800 },
                    timeout: 20000
                });
                const page = await browser.newPage();
                await page.setUserAgent('Mozilla/5.0 (compatible; LinkMagico-Bot/6.0)');
                await page.setRequestInterception(true);
                page.on('request', (req) => {
                    const rt = req.resourceType();
                    if (['stylesheet', 'font', 'image', 'media'].includes(rt)) req.abort();
                    else req.continue();
                });

                try {
                    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
                } catch (gotoErr) {
                    logger.warn('Puppeteer goto failed:', gotoErr.message || gotoErr);
                }

                try {
                    await page.evaluate(async () => {
                        await new Promise((resolve) => {
                            let total = 0;
                            const dist = 300;
                            const timer = setInterval(() => {
                                window.scrollBy(0, dist);
                                total += dist;
                                if (total >= document.body.scrollHeight || total > 3000) {
                                    clearInterval(timer);
                                    resolve();
                                }
                            }, 100);
                        });
                    });
                    await page.waitForTimeout(500);
                } catch (scrollErr) {
                    logger.warn('Puppeteer scroll failed:', scrollErr.message || scrollErr);
                }

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

                const cleanedText = normalizeText(puppeteerData.bodyText || '').replace(/\s{2,}/g, ' ');
                const lines = cleanedText.split('\n').map(l => l.trim()).filter(Boolean);
                const uniq = [...new Set(lines)];
                const finalText = uniq.join('\n');

                if (finalText && finalText.length > (extractedData.cleanText || '').length) {
                    extractedData.cleanText = finalText;
                    extractedData.method = 'puppeteer';
                    if (!extractedData.title && puppeteerData.title) extractedData.title = puppeteerData.title.slice(0, 200);
                    if (!extractedData.description && puppeteerData.metaDescription) extractedData.description = puppeteerData.metaDescription.slice(0, 500);
                    const sents = finalText.split(/[.!?]+/).map(s => s.trim()).filter(Boolean);
                    if (!extractedData.summary && sents.length) extractedData.summary = sents.slice(0, 3).join('. ').substring(0, 400) + (sents.length > 3 ? '...' : '');
                    extractedData.bonuses_detected = extractBonuses(finalText);
                    analytics.successfulExtractions++;
                }

            } catch (puppeteerErr) {
                logger.warn('Puppeteer extraction failed:', puppeteerErr.message || puppeteerErr);
                analytics.failedExtractions++;
            } finally {
                try { if (browser) await browser.close(); } catch (e) {}
            }
        }

        try {
            if (extractedData.cleanText) extractedData.cleanText = uniqueLines(extractedData.cleanText);
            if (!extractedData.title && extractedData.cleanText) {
                const firstLine = extractedData.cleanText.split('\n').find(l => l && l.length > 10 && l.length < 150);
                if (firstLine) extractedData.title = firstLine.slice(0, 150);
            }
            if (!extractedData.summary && extractedData.cleanText) {
                const sents = extractedData.cleanText.split(/(?<=[.!?])\s+/).filter(Boolean);
                extractedData.summary = sents.slice(0, 3).join('. ').slice(0, 400) + (sents.length > 3 ? '...' : '');
            }
        } catch (procErr) {
            logger.warn('Final processing failed:', procErr.message || procErr);
        }

        extractedData.extractionTime = Date.now() - startTime;
        
        setCacheData(cacheKey, extractedData);
        logger.info(`Extraction completed for ${url} in ${extractedData.extractionTime}ms using ${extractedData.method}`);
        return extractedData;

    } catch (error) {
        analytics.failedExtractions++;
        logger.error(`Page extraction failed for ${url}:`, error.message || error);
        return {
            title: '',
            description: '',
            benefits: [],
            testimonials: [],
            cta: '',
            summary: 'Erro ao extrair dados da página. Verifique se a URL está acessível.',
            cleanText: '',
            imagesText: [],
            url: url || '',
            extractionTime: Date.now() - startTime,
            method: 'failed',
            error: error.message || String(error),
            bonuses_detected: [],
            price_detected: []
        };
    }
}

async function callGroq(messages, temperature = 0.4, maxTokens = 300) {
    if (!process.env.GROQ_API_KEY) throw new Error('GROQ_API_KEY missing');

    const payload = {
        model: process.env.GROQ_MODEL || 'llama-3.1-70b-versatile',
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.GROQ_API_BASE || 'https://api.groq.com/openai/v1/chat/completions';
    const headers = {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
    };

    const response = await axios.post(url, payload, { headers, timeout: 30000 });
    return response.data?.choices?.[0]?.message?.content || '';
}

app.post('/api/extract', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL é obrigatória' });

        analytics.extractRequests++;
        logger.info(`Extraction request from ${req.cliente.nome} for ${url}`);

        const extractedData = await extractPageData(url);
        
        res.json({
            success: true,
            data: extractedData,
            client: req.cliente.nome
        });

    } catch (error) {
        logger.error('Extract error:', error);
        res.status(500).json({ error: error.message || 'Erro na extração' });
    }
});

app.post('/api/chat', async (req, res) => {
    try {
        const { messages, context } = req.body;
        if (!messages || !Array.isArray(messages)) {
            return res.status(400).json({ error: 'Mensagens inválidas' });
        }

        analytics.chatRequests++;
        const chatId = crypto.randomUUID();
        analytics.activeChats.add(chatId);

        logger.info(`Chat request from ${req.cliente.nome}`);

        let systemMessage = 'Você é um assistente especializado em copywriting e marketing digital.';
        if (context && context.extractedData) {
            systemMessage += `\n\nContexto da página:\nTítulo: ${context.extractedData.title}\nDescrição: ${context.extractedData.description}\nConteúdo: ${context.extractedData.cleanText?.slice(0, 2000)}`;
        }

        const groqMessages = [
            { role: 'system', content: systemMessage },
            ...messages
        ];

        const response = await callGroq(groqMessages, 0.7, 500);

        analytics.activeChats.delete(chatId);

        res.json({
            success: true,
            response: response,
            chatId: chatId
        });

    } catch (error) {
        logger.error('Chat error:', error);
        res.status(500).json({ error: error.message || 'Erro no chat' });
    }
});

app.get('/api/analytics', (req, res) => {
    const uptime = Date.now() - analytics.startTime;
    const avgResponseTime = analytics.responseTimeHistory.length > 0
        ? analytics.responseTimeHistory.reduce((a, b) => a + b, 0) / analytics.responseTimeHistory.length
        : 0;

    res.json({
        totalRequests: analytics.totalRequests,
        chatRequests: analytics.chatRequests,
        extractRequests: analytics.extractRequests,
        errors: analytics.errors,
        activeChats: analytics.activeChats.size,
        uptime: Math.floor(uptime / 1000),
        avgResponseTime: Math.round(avgResponseTime),
        successfulExtractions: analytics.successfulExtractions,
        failedExtractions: analytics.failedExtractions,
        authenticatedRequests: analytics.authenticatedRequests,
        uniqueClients: analytics.uniqueClients.size,
        cacheSize: dataCache.size
    });
});

app.post('/api/log-consent', (req, res) => {
    const { consent, userId } = req.body;
    logger.info(`LGPD Consent logged: ${consent} for user ${userId || 'anonymous'}`);
    res.json({ success: true, message: 'Consentimento registrado' });
});

app.post('/api/data-deletion', (req, res) => {
    const { userId, email } = req.body;
    logger.info(`Data deletion request from ${email || userId || 'anonymous'}`);
    res.json({ 
        success: true, 
        message: 'Solicitação de exclusão registrada. Processaremos em até 48h.' 
    });
});

app.get('/privacy-policy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ error: 'Erro interno do servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n🚀 LinkMágico v6.0 rodando na porta ${PORT}`);
    console.log(`📊 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 API Keys carregadas: ${apiKeysCache.size}`);
    console.log(`🎯 Puppeteer: ${puppeteer ? 'Ativo' : 'Inativo'}`);
    console.log(`\n✅ Sistema pronto para uso!\n`);
});
