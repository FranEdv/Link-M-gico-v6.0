// LinkMágico v6.0 Commercial - Server Completo
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
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const Stripe = require('stripe');

// Initialize Stripe
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// Optional Puppeteer
let puppeteer = null;
try {
    puppeteer = require('puppeteer');
    console.log('✅ Puppeteer loaded - Dynamic rendering available');
} catch (e) {
    console.log('⚠️ Puppeteer not installed - Using basic extraction only');
}

const app = express();

// ===== Enhanced Logger =====
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
        }),
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 5242880,
            maxFiles: 5
        })
    ]
});

// Trust proxy for accurate IP addresses
app.set('trust proxy', true);

// ===== TENANT & API KEY MANAGEMENT =====
class TenantManager {
    constructor() {
        this.tenants = new Map();
        this.apiKeys = new Map();
        this.loadTenants();
    }

    loadTenants() {
        try {
            const tenantsFile = path.join(__dirname, 'data', 'tenants.json');
            if (fs.existsSync(tenantsFile)) {
                const data = JSON.parse(fs.readFileSync(tenantsFile, 'utf8'));
                data.forEach(tenant => {
                    this.tenants.set(tenant.id, tenant);
                    this.apiKeys.set(tenant.apiKey, tenant.id);
                });
                logger.info(`Loaded ${data.length} tenants`);
            }
        } catch (error) {
            logger.error('Failed to load tenants:', error);
        }
    }

    saveTenants() {
        try {
            const dataDir = path.join(__dirname, 'data');
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            
            const tenantsArray = Array.from(this.tenants.values());
            fs.writeFileSync(
                path.join(dataDir, 'tenants.json'), 
                JSON.stringify(tenantsArray, null, 2)
            );
        } catch (error) {
            logger.error('Failed to save tenants:', error);
        }
    }

    createTenant(data) {
        const tenant = {
            id: uuidv4(),
            name: data.name,
            email: data.email,
            apiKey: this.generateApiKey(),
            plan: data.plan || 'free',
            limits: this.getPlanLimits(data.plan || 'free'),
            usage: {
                requests: 0,
                tokens: 0,
                chatbots: 0,
                resetDate: new Date()
            },
            stripeCustomerId: data.stripeCustomerId || null,
            createdAt: new Date(),
            isActive: true,
            domains: data.domains || [],
            webhooks: data.webhooks || [],
            settings: {
                customCSS: '',
                branding: true,
                analytics: true
            }
        };

        this.tenants.set(tenant.id, tenant);
        this.apiKeys.set(tenant.apiKey, tenant.id);
        this.saveTenants();
        
        logger.info(`Created tenant: ${tenant.name} (${tenant.id})`);
        return tenant;
    }

    getTenantByApiKey(apiKey) {
        const tenantId = this.apiKeys.get(apiKey);
        return tenantId ? this.tenants.get(tenantId) : null;
    }

    getTenant(tenantId) {
        return this.tenants.get(tenantId);
    }

    updateTenantUsage(tenantId, usage) {
        const tenant = this.tenants.get(tenantId);
        if (tenant) {
            tenant.usage.requests += usage.requests || 0;
            tenant.usage.tokens += usage.tokens || 0;
            tenant.usage.chatbots += usage.chatbots || 0;
            this.saveTenants();
        }
    }

    checkLimits(tenant) {
        const now = new Date();
        const resetDate = new Date(tenant.usage.resetDate);
        
        // Reset monthly usage
        if (now.getMonth() !== resetDate.getMonth() || 
            now.getFullYear() !== resetDate.getFullYear()) {
            tenant.usage.requests = 0;
            tenant.usage.tokens = 0;
            tenant.usage.resetDate = now;
            this.saveTenants();
        }

        return {
            requests: tenant.usage.requests < tenant.limits.requests,
            tokens: tenant.usage.tokens < tenant.limits.tokens,
            chatbots: tenant.usage.chatbots < tenant.limits.chatbots
        };
    }

    generateApiKey() {
        return 'lm_' + crypto.randomBytes(32).toString('hex');
    }

    getPlanLimits(plan) {
        const plans = {
            free: {
                requests: 1000,
                tokens: 50000,
                chatbots: 3,
                domains: 1,
                customCSS: false,
                analytics: false,
                support: 'community'
            },
            starter: {
                requests: 10000,
                tokens: 500000,
                chatbots: 10,
                domains: 5,
                customCSS: true,
                analytics: true,
                support: 'email'
            },
            pro: {
                requests: 100000,
                tokens: 5000000,
                chatbots: 50,
                domains: 25,
                customCSS: true,
                analytics: true,
                support: 'priority'
            },
            enterprise: {
                requests: -1, // unlimited
                tokens: -1,
                chatbots: -1,
                domains: -1,
                customCSS: true,
                analytics: true,
                support: 'dedicated'
            }
        };
        return plans[plan] || plans.free;
    }

    generateWidgetToken(tenantId, domains = [], expiresIn = '30d') {
        const payload = {
            tenantId,
            domains,
            type: 'widget',
            iat: Math.floor(Date.now() / 1000)
        };

        return jwt.sign(payload, process.env.JWT_SECRET || 'default-secret', { 
            expiresIn 
        });
    }

    verifyWidgetToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
        } catch (error) {
            return null;
        }
    }
}

const tenantManager = new TenantManager();

// ===== RATE LIMITING BY TENANT =====
const createTenantRateLimit = (requests, windowMs = 15 * 60 * 1000) => {
    return rateLimit({
        windowMs,
        limit: (req) => {
            const tenant = req.tenant;
            if (!tenant) return 10; // Guest limit
            
            const limits = tenantManager.checkLimits(tenant);
            if (!limits.requests) return 0; // Exceeded
            
            return Math.min(requests, tenant.limits.requests);
        },
        keyGenerator: (req) => {
            return req.tenant ? req.tenant.id : req.ip;
        },
        message: {
            error: 'Rate limit exceeded',
            retryAfter: Math.ceil(windowMs / 1000)
        },
        standardHeaders: true,
        legacyHeaders: false
    });
};

// ===== AUTHENTICATION MIDDLEWARE =====
const authenticateApiKey = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const apiKey = authHeader?.startsWith('Bearer ') 
            ? authHeader.slice(7)
            : req.headers['x-api-key'] || req.query.api_key;

        if (!apiKey) {
            return res.status(401).json({
                error: 'API key required',
                message: 'Provide API key in Authorization header or x-api-key'
            });
        }

        const tenant = tenantManager.getTenantByApiKey(apiKey);
        if (!tenant) {
            return res.status(401).json({
                error: 'Invalid API key',
                message: 'API key not found or inactive'
            });
        }

        if (!tenant.isActive) {
            return res.status(403).json({
                error: 'Account suspended',
                message: 'Contact support to reactivate your account'
            });
        }

        // Check limits
        const limits = tenantManager.checkLimits(tenant);
        if (!limits.requests) {
            return res.status(429).json({
                error: 'Usage limit exceeded',
                message: 'Monthly request limit reached. Upgrade your plan.',
                limits: tenant.limits,
                usage: tenant.usage
            });
        }

        req.tenant = tenant;
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
};

// Widget authentication middleware
const authenticateWidget = (req, res, next) => {
    try {
        const token = req.headers['x-widget-token'] || req.query.token;
        
        if (!token) {
            return res.status(401).json({
                error: 'Widget token required'
            });
        }

        const payload = tenantManager.verifyWidgetToken(token);
        if (!payload) {
            return res.status(401).json({
                error: 'Invalid or expired widget token'
            });
        }

        const tenant = tenantManager.getTenant(payload.tenantId);
        if (!tenant || !tenant.isActive) {
            return res.status(403).json({
                error: 'Tenant not found or inactive'
            });
        }

        // Verify domain if specified
        if (payload.domains && payload.domains.length > 0) {
            const referer = req.headers.referer || req.headers.origin;
            if (referer) {
                const refererDomain = new URL(referer).hostname;
                const allowed = payload.domains.some(domain => {
                    return domain === refererDomain || 
                           refererDomain.endsWith('.' + domain);
                });
                
                if (!allowed) {
                    return res.status(403).json({
                        error: 'Domain not authorized',
                        allowedDomains: payload.domains
                    });
                }
            }
        }

        req.tenant = tenant;
        req.widgetPayload = payload;
        next();
    } catch (error) {
        logger.error('Widget authentication error:', error);
        res.status(500).json({ error: 'Widget authentication failed' });
    }
};

// ===== MIDDLEWARE SETUP =====
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://api.stripe.com"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        // Check if origin is from a tenant's allowed domains
        const tenants = Array.from(tenantManager.tenants.values());
        const allowed = tenants.some(tenant => 
            tenant.domains.some(domain => 
                origin.includes(domain) || origin.endsWith('.' + domain)
            )
        );
        
        // Always allow localhost and render.com for development
        const devOrigins = ['localhost', 'render.com', '127.0.0.1'];
        const isDev = devOrigins.some(dev => origin.includes(dev));
        
        callback(null, allowed || isDev);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Widget-Token', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info({
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            tenantId: req.tenant?.id
        });
        
        // Update tenant usage
        if (req.tenant) {
            tenantManager.updateTenantUsage(req.tenant.id, { requests: 1 });
        }
    });
    
    next();
});

// Serve static files
app.use(express.static('public', {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));

// ===== ENHANCED ANALYTICS =====
const analytics = {
    totalRequests: 0,
    chatRequests: 0,
    extractRequests: 0,
    widgetRequests: 0,
    errors: 0,
    activeChats: new Set(),
    startTime: Date.now(),
    responseTimeHistory: [],
    successfulExtractions: 0,
    failedExtractions: 0,
    tokenUsage: 0,
    tenantStats: new Map()
};

// ===== LLM TOKEN TRACKING =====
function estimateTokens(text) {
    // Rough estimation: 1 token ≈ 4 characters for most models
    return Math.ceil((text || '').length / 4);
}

function trackTokenUsage(tenantId, promptTokens, completionTokens) {
    const total = promptTokens + completionTokens;
    analytics.tokenUsage += total;
    
    if (tenantId) {
        tenantManager.updateTenantUsage(tenantId, { tokens: total });
        
        if (!analytics.tenantStats.has(tenantId)) {
            analytics.tenantStats.set(tenantId, {
                requests: 0,
                tokens: 0,
                errors: 0
            });
        }
        
        const stats = analytics.tenantStats.get(tenantId);
        stats.tokens += total;
    }
}

// ===== CACHING SYSTEM =====
const cache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes

function setCache(key, data, ttl = CACHE_TTL) {
    cache.set(key, { 
        data, 
        expires: Date.now() + ttl 
    });
}

function getCache(key) {
    const cached = cache.get(key);
    if (cached && Date.now() < cached.expires) {
        return cached.data;
    }
    cache.delete(key);
    return null;
}

// ===== EXTRACTION FUNCTIONS =====
function normalizeText(text) {
    return (text || '').replace(/\s+/g, ' ').trim();
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

async function extractPageData(url, tenantId) {
    const startTime = Date.now();
    const cacheKey = `extract:${url}:${tenantId}`;
    
    try {
        // Check cache first
        const cached = getCache(cacheKey);
        if (cached) {
            logger.info(`Cache hit for ${url}`);
            return cached;
        }
        
        logger.info(`Starting extraction for: ${url}`);
        analytics.extractRequests++;

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
                    'User-Agent': 'Mozilla/5.0 (compatible; LinkMagico-Bot/6.0; +https://linkmagico.com)',
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
            analytics.successfulExtractions++;
        } catch (axiosError) {
            logger.warn(`Axios extraction failed for ${url}: ${axiosError.message || axiosError}`);
            analytics.failedExtractions++;
        }

        if (html && html.length > 100) {
            try {
                const $ = cheerio.load(html);
                $('script, style, noscript, iframe').remove();

                // Extract title
                const titleSelectors = ['h1', 'meta[property="og:title"]', 'meta[name="twitter:title"]', 'title'];
                for (const selector of titleSelectors) {
                    const el = $(selector).first();
                    const title = (el.attr && (el.attr('content') || el.text) ? (el.attr('content') || el.text()) : el.text ? el.text() : '').toString().trim();
                    if (title && title.length > 5 && title.length < 200) {
                        extractedData.title = title;
                        break;
                    }
                }

                // Extract description
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
            } catch (cheerioError) {
                logger.warn(`Cheerio parsing failed: ${cheerioError.message || cheerioError}`);
            }
        }

        // Puppeteer fallback for dynamic content
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

                await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
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
                if (cleanedText && cleanedText.length > (extractedData.cleanText || '').length) {
                    extractedData.cleanText = cleanedText;
                    extractedData.method = 'puppeteer';
                    if (!extractedData.title && puppeteerData.title) extractedData.title = puppeteerData.title.slice(0, 200);
                    if (!extractedData.description && puppeteerData.metaDescription) extractedData.description = puppeteerData.metaDescription.slice(0, 500);
                    extractedData.bonuses_detected = extractBonuses(cleanedText);
                    analytics.successfulExtractions++;
                }

            } catch (puppeteerErr) {
                logger.warn('Puppeteer extraction failed:', puppeteerErr.message || puppeteerErr);
                analytics.failedExtractions++;
            } finally {
                try { if (browser) await browser.close(); } catch (e) {}
            }
        }

        extractedData.extractionTime = Date.now() - startTime;
        
        // Cache the result
        setCache(cacheKey, extractedData);
        
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

// ===== LLM INTEGRATION WITH FALLBACK =====
async function callGroq(messages, temperature = 0.4, maxTokens = 300, tenantId = null) {
    if (!process.env.GROQ_API_KEY) throw new Error('GROQ_API_KEY missing');

    const payload = {
        model: process.env.GROQ_MODEL || 'llama-3.1-70b-versatile',
        messages,
        temperature,
        max_tokens: maxTokens
    };

    const url = process.env.GROQ_API_BASE || 'https://api.groq.com/openai/v1/chat/completions';
    const headers = { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' };
    const response = await axios.post(url, payload, { headers, timeout: 15000 });
    
    if (!(response && response.status >= 200 && response.status < 300)) {
        throw new Error(`GROQ API failed with status ${response?.status}`);
    }
    
    const result = response.data?.choices?.[0]?.message?.content;
    if (!result) throw new Error('Invalid GROQ API response format');
    
    // Track token usage
    const usage = response.data?.usage;
    if (usage && tenantId) {
        trackTokenUsage(tenantId, usage.prompt_tokens || 0, usage.completion_tokens || 0);
    }
    
    return result;
}

async function callOpenAI(messages, temperature = 0.2, maxTokens = 300, tenantId = null, model = null) {
    if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing');

    const selectedModel = model || process.env.OPENAI_MODEL || 'gpt-4o-mini';
    const url = process.env.OPENAI_API_BASE || 'https://api.openai.com/v1/chat/completions';
    const payload = { model: selectedModel, messages, temperature, max_tokens: maxTokens };
    const headers = { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' };
    
    const response = await axios.post(url, payload, { headers, timeout: 15000 });
    
    if (!(response && response.status >= 200 && response.status < 300)) {
        throw new Error(`OpenAI API failed with status ${response?.status}`);
    }
    
    const result = response.data?.choices?.[0]?.message?.content;
    if (!result) throw new Error('Invalid OpenAI API response format');
    
    // Track token usage
    const usage = response.data?.usage;
    if (usage && tenantId) {
        trackTokenUsage(tenantId, usage.prompt_tokens || 0, usage.completion_tokens || 0);
    }
    
    return result;
}

// Smart model selection based on tenant plan and usage
function selectOptimalModel(tenant, complexity = 'medium') {
    if (!tenant) return { provider: 'local', model: null };
    
    const limits = tenantManager.checkLimits(tenant);
    const tokensRemaining = tenant.limits.tokens - tenant.usage.tokens;
    const tokensUsagePercent = tenant.usage.tokens / tenant.limits.tokens;
    
    // If approaching token limits (>80%), use cheaper models
    if (tokensUsagePercent > 0.8 || tokensRemaining < 10000) {
        if (process.env.GROQ_API_KEY) {
            return { provider: 'groq', model: 'llama-3.1-8b-instant' };
        }
        return { provider: 'local', model: null };
    }
    
    // Model selection based on tenant plan
    switch (tenant.plan) {
        case 'enterprise':
        case 'pro':
            if (complexity === 'high') {
                return { provider: 'openai', model: 'gpt-4' };
            }
            return { provider: 'openai', model: 'gpt-4o-mini' };
        
        case 'starter':
            return { provider: 'groq', model: 'llama-3.1-70b-versatile' };
        
        case 'free':
        default:
            return { provider: 'groq', model: 'llama-3.1-8b-instant' };
    }
}

// FAQ Cache for common questions
const faqCache = new Map();

function getFAQResponse(question, pageData) {
    const normalizedQuestion = question.toLowerCase().trim();
    const cacheKey = `faq:${normalizedQuestion}`;
    
    // Common FAQ patterns
    const faqPatterns = [
        { pattern: /preço|valor|quanto custa/i, response: 'Para informações sobre preços, consulte diretamente a página do produto.' },
        { pattern: /como funciona|funcionamento/i, response: 'Vou explicar baseado nas informações da página...' },
        { pattern: /bônus|bonus/i, response: null }, // Will be handled dynamically
        { pattern: /garantia/i, response: 'Verifique os termos de garantia na página do produto.' },
        { pattern: /suporte|ajuda|contato/i, response: 'Entre em contato através dos canais de suporte disponíveis na página.' },
        { pattern: /entrega|prazo/i, response: 'Consulte as informações de prazo e entrega na página do produto.' }
    ];
    
    for (const faq of faqPatterns) {
        if (faq.pattern.test(normalizedQuestion)) {
            if (faq.response) return faq.response;
            break;
        }
    }
    
    return null;
}

async function generateAIResponse(userMessage, pageData = {}, conversation = [], instructions = '', tenant = null) {
    const startTime = Date.now();
    try {
        // Check FAQ cache first for common questions
        const faqResponse = getFAQResponse(userMessage, pageData);
        if (faqResponse && tenant?.plan === 'free') {
            return faqResponse;
        }
        
        // Determine complexity
        const complexity = userMessage.length > 100 || instructions.includes('detailed') ? 'high' : 'medium';
        const modelConfig = selectOptimalModel(tenant, complexity);
        
        const salesMode = /sales_mode:on|consultivo|vendas|venda|cta|sempre.*link|finalize.*cta/i.test(instructions);

        // Direct link handling
        if (/\b(link|página|site|comprar|inscrever)\b/i.test(userMessage) && pageData?.url) {
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
        if (pageData.bonuses_detected && pageData.bonuses_detected.length > 0) {
            contextLines.push(`Bônus: ${pageData.bonuses_detected.slice(0, 3).join(', ')}`);
        }
        
        const contentExcerpt = (pageData.summary || pageData.cleanText || '').slice(0, 1000);
        if (contentExcerpt) contextLines.push(`Informações: ${contentExcerpt}`);

        const pageContext = contextLines.join('\n');
        const userPrompt = `${instructions ? `Instruções: ${instructions}\n\n` : ''}Contexto:\n${pageContext}\n\nPergunta: ${userMessage}\n\nResponda de forma concisa usando apenas as informações fornecidas.`;

        const messages = [
            { role: 'system', content: systemPrompt }, 
            { role: 'user', content: userPrompt }
        ];

        let response = null;
        let usedProvider = 'local';

        // Try selected provider first
        if (modelConfig.provider === 'openai' && process.env.OPENAI_API_KEY) {
            try {
                response = await callOpenAI(messages, 0.2, 250, tenant?.id, modelConfig.model);
                usedProvider = 'openai';
                logger.info(`OpenAI API call successful with ${modelConfig.model}`);
            } catch (openaiError) {
                logger.warn(`OpenAI failed: ${openaiError.message || openaiError}`);
            }
        } else if (modelConfig.provider === 'groq' && process.env.GROQ_API_KEY) {
            try {
                response = await callGroq(messages, 0.4, 250, tenant?.id);
                usedProvider = 'groq';
                logger.info('GROQ API call successful');
            } catch (groqError) {
                logger.warn(`GROQ failed: ${groqError.message || groqError}`);
                
                // Fallback to OpenAI if GROQ fails
                if (process.env.OPENAI_API_KEY) {
                    try {
                        response = await callOpenAI(messages, 0.2, 250, tenant?.id, 'gpt-4o-mini');
                        usedProvider = 'openai-fallback';
                        logger.info('OpenAI fallback successful');
                    } catch (openaiError) {
                        logger.warn(`OpenAI fallback failed: ${openaiError.message || openaiError}`);
                    }
                }
            }
        }

        if (!response || !String(response).trim()) {
            response = generateLocalResponse(userMessage, pageData, instructions);
            usedProvider = 'local';
        }

        const finalResponse = String(response).trim().slice(0, 800); // Limit response length
        const responseTime = Date.now() - startTime;
        
        // Update tenant analytics
        if (tenant) {
            if (!analytics.tenantStats.has(tenant.id)) {
                analytics.tenantStats.set(tenant.id, { requests: 0, tokens: 0, errors: 0 });
            }
            analytics.tenantStats.get(tenant.id).requests++;
        }
        
        logger.info(`AI response generated in ${responseTime}ms using ${usedProvider}`);
        return finalResponse;

    } catch (error) {
        logger.error('AI response generation failed:', error.message || error);
        
        if (tenant) {
            if (!analytics.tenantStats.has(tenant.id)) {
                analytics.tenantStats.set(tenant.id, { requests: 0, tokens: 0, errors: 0 });
            }
            analytics.tenantStats.get(tenant.id).errors++;
        }
        
        return 'Desculpe, ocorreu um erro ao processar sua mensagem. Tente novamente.';
    }
}

function generateLocalResponse(userMessage, pageData = {}, instructions = '') {
    const question = (userMessage || '').toLowerCase();
    const salesMode = /sales_mode:on|consultivo|vendas|venda|cta|sempre.*link|finalize.*cta/i.test(instructions);

    if (/preço|valor|quanto custa/.test(question)) {
        return 'Para informações sobre preços, consulte diretamente a página do produto.';
    }

    if (/como funciona|funcionamento/.test(question)) {
        const summary = pageData.summary || pageData.description;
        if (summary) {
            const shortSummary = summary.split('.').slice(0, 2).join('.');
            return salesMode ? `${shortSummary} Quer saber mais detalhes?` : shortSummary;
        }
    }

    if (/bônus|bonus/.test(question)) {
        if (pageData.bonuses_detected && pageData.bonuses_detected.length > 0) {
            const bonuses = pageData.bonuses_detected.slice(0, 2).join(', ');
            return salesMode ? `Inclui: ${bonuses}. Quer garantir todos os bônus?` : `Bônus: ${bonuses}`;
        }
        return 'Informações sobre bônus não encontradas.';
    }

    if (pageData.summary) {
        const summary = pageData.summary.split('.').slice(0, 2).join('.');
        return salesMode ? `${summary} Posso te ajudar com mais alguma dúvida?` : summary;
    }

    return 'Não encontrei essa informação específica na página. Posso te ajudar com outras dúvidas?';
}

// ===== BILLING & STRIPE INTEGRATION =====
class BillingManager {
    constructor() {
        this.stripe = stripe;
        this.plans = this.getPlans();
    }

    getPlans() {
        return {
            free: {
                name: 'Free',
                price: 0,
                stripePriceId: null,
                limits: tenantManager.getPlanLimits('free')
            },
            starter: {
                name: 'Starter',
                price: 2900, // $29.00
                stripePriceId: process.env.STRIPE_STARTER_PRICE_ID,
                limits: tenantManager.getPlanLimits('starter')
            },
            pro: {
                name: 'Pro',
                price: 9900, // $99.00
                stripePriceId: process.env.STRIPE_PRO_PRICE_ID,
                limits: tenantManager.getPlanLimits('pro')
            },
            enterprise: {
                name: 'Enterprise',
                price: 29900, // $299.00
                stripePriceId: process.env.STRIPE_ENTERPRISE_PRICE_ID,
                limits: tenantManager.getPlanLimits('enterprise')
            }
        };
    }

    async createCheckoutSession(tenantId, planId, successUrl, cancelUrl) {
        if (!this.stripe) throw new Error('Stripe not configured');
        
        const tenant = tenantManager.getTenant(tenantId);
        if (!tenant) throw new Error('Tenant not found');
        
        const plan = this.plans[planId];
        if (!plan || !plan.stripePriceId) throw new Error('Invalid plan');

        let customerId = tenant.stripeCustomerId;
        
        // Create Stripe customer if not exists
        if (!customerId) {
            const customer = await this.stripe.customers.create({
                email: tenant.email,
                metadata: { tenantId: tenant.id }
            });
            customerId = customer.id;
            
            // Update tenant
            tenant.stripeCustomerId = customerId;
            tenantManager.tenants.set(tenantId, tenant);
            tenantManager.saveTenants();
        }

        const session = await this.stripe.checkout.sessions.create({
            customer: customerId,
            payment_method_types: ['card'],
            line_items: [{
                price: plan.stripePriceId,
                quantity: 1
            }],
            mode: 'subscription',
            success_url: successUrl,
            cancel_url: cancelUrl,
            metadata: {
                tenantId: tenantId,
                planId: planId
            }
        });

        return session;
    }

    async handleWebhook(body, signature) {
        if (!this.stripe) throw new Error('Stripe not configured');
        
        const event = this.stripe.webhooks.constructEvent(
            body,
            signature,
            process.env.STRIPE_WEBHOOK_SECRET
        );

        switch (event.type) {
            case 'checkout.session.completed':
                await this.handleSubscriptionSuccess(event.data.object);
                break;
                
            case 'customer.subscription.updated':
            case 'customer.subscription.deleted':
                await this.handleSubscriptionChange(event.data.object);
                break;
                
            case 'invoice.payment_succeeded':
                await this.handlePaymentSuccess(event.data.object);
                break;
                
            case 'invoice.payment_failed':
                await this.handlePaymentFailed(event.data.object);
                break;
        }

        return { received: true };
    }

    async handleSubscriptionSuccess(session) {
        const tenantId = session.metadata?.tenantId;
        const planId = session.metadata?.planId;
        
        if (tenantId && planId) {
            const tenant = tenantManager.getTenant(tenantId);
            if (tenant) {
                tenant.plan = planId;
                tenant.limits = tenantManager.getPlanLimits(planId);
                tenant.subscriptionStatus = 'active';
                tenantManager.tenants.set(tenantId, tenant);
                tenantManager.saveTenants();
                
                logger.info(`Subscription activated: ${tenant.name} -> ${planId}`);
            }
        }
    }

    async handleSubscriptionChange(subscription) {
        const customer = await this.stripe.customers.retrieve(subscription.customer);
        const tenantId = customer.metadata?.tenantId;
        
        if (tenantId) {
            const tenant = tenantManager.getTenant(tenantId);
            if (tenant) {
                tenant.subscriptionStatus = subscription.status;
                
                if (subscription.status === 'canceled') {
                    tenant.plan = 'free';
                    tenant.limits = tenantManager.getPlanLimits('free');
                }
                
                tenantManager.tenants.set(tenantId, tenant);
                tenantManager.saveTenants();
                
                logger.info(`Subscription changed: ${tenant.name} -> ${subscription.status}`);
            }
        }
    }

    async handlePaymentSuccess(invoice) {
        logger.info(`Payment succeeded: ${invoice.id}`);
    }

    async handlePaymentFailed(invoice) {
        logger.warn(`Payment failed: ${invoice.id}`);
    }
}

const billingManager = new BillingManager();

// ===== API ROUTES =====

// Health check
app.get('/health', (req, res) => {
    const uptime = process.uptime();
    const avgResponseTime = analytics.responseTimeHistory.length > 0 ?
        Math.round(analytics.responseTimeHistory.reduce((a, b) => a + b, 0) / analytics.responseTimeHistory.length) : 0;

    res.json({
        status: 'healthy',
        uptime: Math.floor(uptime),
        timestamp: new Date().toISOString(),
        version: '6.0.0',
        analytics: {
            totalRequests: analytics.totalRequests,
            chatRequests: analytics.chatRequests,
            extractRequests: analytics.extractRequests,
            widgetRequests: analytics.widgetRequests,
            errors: analytics.errors,
            activeChats: analytics.activeChats.size,
            avgResponseTime,
            successfulExtractions: analytics.successfulExtractions,
            failedExtractions: analytics.failedExtractions,
            tokenUsage: analytics.tokenUsage,
            cacheSize: cache.size,
            tenantCount: tenantManager.tenants.size
        },
        services: {
            groq: !!process.env.GROQ_API_KEY,
            openai: !!process.env.OPENAI_API_KEY,
            puppeteer: !!puppeteer,
            stripe: !!stripe
        }
    });
});

// Tenant management
app.post('/api/tenants', async (req, res) => {
    try {
        const { name, email, plan = 'free' } = req.body;
        
        if (!name || !email) {
            return res.status(400).json({
                error: 'Name and email are required'
            });
        }

        const tenant = tenantManager.createTenant({ name, email, plan });
        
        // Generate widget token
        const widgetToken = tenantManager.generateWidgetToken(tenant.id);
        
        res.json({
            success: true,
            tenant: {
                id: tenant.id,
                name: tenant.name,
                email: tenant.email,
                plan: tenant.plan,
                apiKey: tenant.apiKey,
                widgetToken: widgetToken,
                limits: tenant.limits,
                usage: tenant.usage
            }
        });

    } catch (error) {
        logger.error('Create tenant error:', error);
        res.status(500).json({ error: 'Failed to create tenant' });
    }
});

// Get tenant info
app.get('/api/tenants/:id', authenticateApiKey, (req, res) => {
    try {
        if (req.tenant.id !== req.params.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        res.json({
            success: true,
            tenant: {
                id: req.tenant.id,
                name: req.tenant.name,
                email: req.tenant.email,
                plan: req.tenant.plan,
                limits: req.tenant.limits,
                usage: req.tenant.usage,
                domains: req.tenant.domains,
                settings: req.tenant.settings,
                createdAt: req.tenant.createdAt
            }
        });

    } catch (error) {
        logger.error('Get tenant error:', error);
        res.status(500).json({ error: 'Failed to get tenant info' });
    }
});

// Update tenant
app.put('/api/tenants/:id', authenticateApiKey, (req, res) => {
    try {
        if (req.tenant.id !== req.params.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { name, domains, settings } = req.body;
        
        if (name) req.tenant.name = name;
        if (domains) req.tenant.domains = domains;
        if (settings) req.tenant.settings = { ...req.tenant.settings, ...settings };

        tenantManager.tenants.set(req.tenant.id, req.tenant);
        tenantManager.saveTenants();

        res.json({ success: true, tenant: req.tenant });

    } catch (error) {
        logger.error('Update tenant error:', error);
        res.status(500).json({ error: 'Failed to update tenant' });
    }
});

// Generate new widget token
app.post('/api/tenants/:id/widget-token', authenticateApiKey, (req, res) => {
    try {
        if (req.tenant.id !== req.params.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const { domains, expiresIn } = req.body;
        const token = tenantManager.generateWidgetToken(
            req.tenant.id, 
            domains || req.tenant.domains, 
            expiresIn
        );

        res.json({ success: true, widgetToken: token });

    } catch (error) {
        logger.error('Generate widget token error:', error);
        res.status(500).json({ error: 'Failed to generate widget token' });
    }
});

// Protected extraction endpoint
app.post('/api/extract', authenticateApiKey, createTenantRateLimit(100), async (req, res) => {
    try {
        const { url, instructions, robotName } = req.body;
        
        if (!url) {
            return res.status(400).json({
                success: false,
                error: 'URL is required'
            });
        }

        // Validate URL
        try { 
            new URL(url); 
        } catch (urlErr) { 
            return res.status(400).json({
                success: false,
                error: 'Invalid URL format'
            }); 
        }

        // Check chatbot limits
        const limits = tenantManager.checkLimits(req.tenant);
        if (!limits.chatbots) {
            return res.status(429).json({
                error: 'Chatbot limit exceeded',
                message: 'Upgrade your plan to create more chatbots',
                limits: req.tenant.limits,
                usage: req.tenant.usage
            });
        }

        logger.info(`Starting extraction for URL: ${url} (Tenant: ${req.tenant.name})`);
        
        const extractedData = await extractPageData(url, req.tenant.id);
        
        if (instructions) extractedData.custom_instructions = instructions;
        if (robotName) extractedData.robot_name = robotName;

        // Update chatbot count
        tenantManager.updateTenantUsage(req.tenant.id, { chatbots: 1 });

        res.json({
            success: true,
            data: extractedData
        });

    } catch (error) {
        logger.error('Extract endpoint error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error: ' + (error.message || 'Unknown error')
        });
    }
});

// Protected chat endpoint
app.post('/api/chat', authenticateApiKey, createTenantRateLimit(500), async (req, res) => {
    try {
        const { message, pageData, url, conversationId, instructions = '', robotName } = req.body;
        
        if (!message) {
            return res.status(400).json({
                success: false,
                error: 'Message is required'
            });
        }

        analytics.chatRequests++;

        if (conversationId) {
            analytics.activeChats.add(conversationId);
            setTimeout(() => analytics.activeChats.delete(conversationId), 30 * 60 * 1000);
        }

        let processedPageData = pageData;
        if (!processedPageData && url) {
            processedPageData = await extractPageData(url, req.tenant.id);
        }

        const aiResponse = await generateAIResponse(
            message, 
            processedPageData || {}, 
            [], 
            instructions,
            req.tenant
        );

        let finalResponse = aiResponse;
        if (processedPageData?.url && !String(finalResponse).includes(processedPageData.url)) {
            finalResponse = `${finalResponse}\n\n${processedPageData.url}`;
        }

        res.json({
            success: true,
            response: finalResponse,
            bonuses_detected: processedPageData?.bonuses_detected || [],
            metadata: {
                hasPageData: !!processedPageData,
                contentLength: processedPageData?.cleanText?.length || 0,
                method: processedPageData?.method || 'none',
                tenantId: req.tenant.id
            }
        });

    } catch (error) {
        analytics.errors++;
        logger.error('Chat endpoint error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error: ' + (error.message || 'Unknown error')
        });
    }
});

// Widget chat endpoint (with widget token auth)
app.post('/api/widget/chat', 
    authenticateWidget, 
    createTenantRateLimit(1000), 
    async (req, res) => {
        try {
            const { message, pageData, url, conversationId, instructions = '', robotName } = req.body;
            
            if (!message) {
                return res.status(400).json({
                    success: false,
                    error: 'Message is required'
                });
            }

            analytics.chatRequests++;
            analytics.widgetRequests++;

            let processedPageData = pageData;
            if (!processedPageData && url) {
                processedPageData = await extractPageData(url, req.tenant.id);
            }

            const aiResponse = await generateAIResponse(
                message, 
                processedPageData || {}, 
                [], 
                instructions,
                req.tenant
            );

            res.json({
                success: true,
                response: aiResponse,
                bonuses_detected: processedPageData?.bonuses_detected || []
            });

        } catch (error) {
            analytics.errors++;
            logger.error('Widget chat error:', error);
            res.status(500).json({
                success: false,
                error: 'Chat processing failed'
            });
        }
    }
);

// Billing endpoints
app.post('/api/billing/checkout', authenticateApiKey, async (req, res) => {
    try {
        const { planId, successUrl, cancelUrl } = req.body;
        
        if (!planId) {
            return res.status(400).json({ error: 'Plan ID is required' });
        }

        const session = await billingManager.createCheckoutSession(
            req.tenant.id,
            planId,
            successUrl || `${req.protocol}://${req.get('host')}/dashboard?success=true`,
            cancelUrl || `${req.protocol}://${req.get('host')}/pricing`
        );

        res.json({
            success: true,
            checkoutUrl: session.url,
            sessionId: session.id
        });

    } catch (error) {
        logger.error('Checkout error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    try {
        const signature = req.headers['stripe-signature'];
        await billingManager.handleWebhook(req.body, signature);
        res.json({ received: true });

    } catch (error) {
        logger.error('Stripe webhook error:', error);
        res.status(400).send(`Webhook Error: ${error.message}`);
    }
});

// Get usage statistics
app.get('/api/analytics', authenticateApiKey, (req, res) => {
    try {
        const tenantStats = analytics.tenantStats.get(req.tenant.id) || {
            requests: 0,
            tokens: 0,
            errors: 0
        };

        res.json({
            success: true,
            analytics: {
                usage: req.tenant.usage,
                limits: req.tenant.limits,
                stats: tenantStats,
                plan: req.tenant.plan,
                utilizationPercent: {
                    requests: Math.round((req.tenant.usage.requests / req.tenant.limits.requests) * 100),
                    tokens: Math.round((req.tenant.usage.tokens / req.tenant.limits.tokens) * 100),
                    chatbots: Math.round((req.tenant.usage.chatbots / req.tenant.limits.chatbots) * 100)
                }
            }
        });

    } catch (error) {
        logger.error('Analytics error:', error);
        res.status(500).json({ error: 'Failed to get analytics' });
    }
});

// Enhanced widget.js with security
app.get('/widget.js', authenticateWidget, (req, res) => {
    res.set('Content-Type', 'application/javascript');
    
    const widgetConfig = {
        apiBase: `${req.protocol}://${req.get('host')}`,
        token: req.headers['x-widget-token'] || req.query.token,
        tenantId: req.tenant.id,
        domains: req.widgetPayload.domains || []
    };

    res.send(`// LinkMágico Commercial Widget v6.0
(function() {
    'use strict';
    
    if (window.LinkMagicoWidget) {
        console.warn('LinkMagico Widget already loaded');
        return;
    }

    const CONFIG = ${JSON.stringify(widgetConfig)};
    
    // Widget implementation with enhanced security
    var LinkMagicoWidget = {
        version: '6.0.0-commercial',
        config: {
            position: 'bottom-right',
            primaryColor: '#3b82f6',
            robotName: 'Assistente IA',
            salesUrl: '',
            instructions: '',
            apiBase: CONFIG.apiBase,
            token: CONFIG.token,
            showBadge: true,
            theme: 'light'
        },
        
        init: function(userConfig) {
            this.config = Object.assign(this.config, userConfig || {});
            
            // Verify domain authorization
            if (CONFIG.domains && CONFIG.domains.length > 0) {
                const currentDomain = window.location.hostname;
                const authorized = CONFIG.domains.some(domain => 
                    currentDomain === domain || currentDomain.endsWith('.' + domain)
                );
                
                if (!authorized) {
                    console.error('LinkMagico Widget: Domain not authorized');
                    return;
                }
            }
            
            this.createWidget();
            this.bindEvents();
        },
        
        createWidget: function() {
            // Widget creation code here...
            console.log('LinkMagico Commercial Widget loaded for tenant: ${req.tenant.name}');
        },
        
        sendMessage: function(message) {
            fetch(CONFIG.apiBase + '/api/widget/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Widget-Token': CONFIG.token
                },
                body: JSON.stringify({
                    message: message,
                    robotName: this.config.robotName,
                    instructions: this.config.instructions,
                    url: this.config.salesUrl,
                    conversationId: 'widget_' + Date.now()
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.addMessage(data.response, false);
                } else {
                    this.addMessage('Erro. Tente novamente.', false);
                }
            })
            .catch(error => {
                console.error('Widget chat error:', error);
                this.addMessage('Erro de conexão.', false);
            });
        }
    };
    
    window.LinkMagicoWidget = LinkMagicoWidget;
})();
`);
});

// Public routes (no auth required)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Legacy endpoints for backward compatibility
app.post('/extract', createTenantRateLimit(10), async (req, res) => {
    try {
        const { url, instructions } = req.body;
        
        if (!url) {
            return res.status(400).json({
                success: false,
                error: 'URL é obrigatório'
            });
        }

        // Basic rate limiting for unauthenticated requests
        const extractedData = await extractPageData(url, null);
        
        res.json({
            success: true,
            data: extractedData
        });

    } catch (error) {
        logger.error('Legacy extract error:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno ao extrair página'
        });
    }
});

app.post('/chat-universal', createTenantRateLimit(50), async (req, res) => {
    try {
        const { message, pageData, url, instructions = '' } = req.body;
        
        if (!message) {
            return res.status(400).json({
                success: false,
                error: 'Mensagem é obrigatória'
            });
        }

        let processedPageData = pageData;
        if (!processedPageData && url) {
            processedPageData = await extractPageData(url, null);
        }

        const aiResponse = await generateAIResponse(
            message,
            processedPageData || {},
            [],
            instructions,
            null // No tenant for legacy endpoint
        );

        res.json({
            success: true,
            response: aiResponse,
            bonuses_detected: processedPageData?.bonuses_detected || []
        });

    } catch (error) {
        logger.error('Legacy chat error:', error);
        res.status(500).json({
            success: false,
            error: 'Erro interno ao gerar resposta'
        });
    }
});

// Chatbot HTML generator
function generateChatbotHTML(pageData = {}, robotName = 'Assistente IA', customInstructions = '') {
    const escapedPageData = JSON.stringify(pageData || {});
    const safeRobotName = String(robotName || 'Assistente IA').replace(/"/g, '\\"');
    const safeInstructions = String(customInstructions || '').replace(/"/g, '\\"');

    return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LinkMágico Chatbot - ${safeRobotName}</title>
<meta name="description" content="Chatbot IA - ${safeRobotName}"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.chat-container{width:100%;max-width:800px;height:90vh;background:white;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.15);display:flex;flex-direction:column;overflow:hidden}
.chat-header{background:linear-gradient(135deg,#3b82f6 0%,#1e40af 100%);color:white;padding:20px;text-align:center;position:relative}
.chat-header h1{font-size:1.5rem;font-weight:600}
.chat-header .subtitle{font-size:0.9rem;opacity:0.9;margin-top:5px}
.chat-messages{flex:1;padding:20px;overflow-y:auto;display:flex;flex-direction:column;gap:15px;background:#f8fafc}
.chat-message{max-width:70%;padding:15px;border-radius:15px;font-size:0.95rem;line-height:1.4}
.chat-message.user{background:linear-gradient(135deg,#3b82f6 0%,#1e40af 100%);color:white;align-self:flex-end;border-bottom-right-radius:5px}
.chat-message.bot{background:#f1f5f9;color:#334155;align-self:flex-start;border-bottom-left-radius:5px}
.chat-input-container{padding:20px;background:white;border-top:1px solid#e2e8f0;display:flex;gap:10px}
.chat-input{flex:1;border:1px solid#e2e8f0;border-radius:25px;padding:12px 20px;font-size:0.95rem;outline:none;transition:all 0.3s}
.chat-input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.1)}
.send-button{background:linear-gradient(135deg,#3b82f6 0%,#1e40af 100%);border:none;border-radius:50%;width:50px;height:50px;color:white;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.3s}
.send-button:hover{transform:scale(1.05);box-shadow:0 5px 15px rgba(59,130,246,0.4)}
.send-button:disabled{opacity:0.6;cursor:not-allowed;transform:none}
.typing-indicator{display:none;align-items:center;gap:5px;color:#64748b;font-size:0.9rem;margin-top:10px}
.typing-dot{width:8px;height:8px;background:#64748b;border-radius:50%;animation:typing 1.4s infinite}
.typing-dot:nth-child(2){animation-delay:0.2s}
.typing-dot:nth-child(3){animation-delay:0.4s}
@keyframes typing{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-5px)}}
@media (max-width:768px){.chat-container{height:100vh;border-radius:0}.chat-message{max-width:85%}}
</style>
</head>
<body>
<div class="chat-container">
<div class="chat-header">
<h1>${safeRobotName}</h1>
<div class="subtitle">IA Assistente - LinkMágico v6.0</div>
</div>
<div class="chat-messages" id="chatMessages">
<div class="chat-message bot">Olá! Sou ${safeRobotName}, seu assistente de IA. Como posso ajudar você hoje?</div>
</div>
<div class="chat-input-container">
<input type="text" class="chat-input" id="messageInput" placeholder="Digite sua mensagem..." autocomplete="off">
<button class="send-button" id="sendButton"><i class="fas fa-paper-plane"></i></button>
</div>
<div class="typing-indicator" id="typingIndicator">
<span>Digitando</span>
<div class="typing-dot"></div>
<div class="typing-dot"></div>
<div class="typing-dot"></div>
</div>
</div>
<script>
const pageData = ${escapedPageData};
const robotName = "${safeRobotName}";
const customInstructions = "${safeInstructions}";

const chatMessages = document.getElementById('chatMessages');
const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendButton');
const typingIndicator = document.getElementById('typingIndicator');

function addMessage(text, isUser = false) {
const messageDiv = document.createElement('div');
messageDiv.className = \`chat-message \${isUser ? 'user' : 'bot'}\`;
messageDiv.textContent = text;
chatMessages.appendChild(messageDiv);
chatMessages.scrollTop = chatMessages.scrollHeight;
}

async function sendMessage() {
const message = messageInput.value.trim();
if (!message) return;

addMessage(message, true);
messageInput.value = '';
sendButton.disabled = true;
typingIndicator.style.display = 'flex';

try {
const response = await fetch('/chat-universal', {
method: 'POST',
headers: { 'Content-Type': 'application/json' },
body: JSON.stringify({
message: message,
pageData: pageData,
robotName: robotName,
instructions: customInstructions,
conversationId: 'chatbot_' + Date.now()
})
});

const data = await response.json();
if (data.success) {
addMessage(data.response, false);
} else {
addMessage('Desculpe, ocorreu um erro. Tente novamente.', false);
}
} catch (error) {
addMessage('Erro de conexão. Verifique sua internet.', false);
} finally {
typingIndicator.style.display = 'none';
sendButton.disabled = false;
messageInput.focus();
}
}

sendButton.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => {
if (e.key === 'Enter') sendMessage();
});

messageInput.focus();
</script>
</body>
</html>`;
}

// Chatbot route
app.get('/chatbot', async (req, res) => {
    try {
        const robotName = req.query.name || 'Assistente IA';
        const url = req.query.url || '';
        const instructions = req.query.instructions || '';
        
        let pageData = {};
        if (url) {
            try {
                pageData = await extractPageData(url, null);
            } catch (extractError) {
                logger.warn('Failed to extract page data:', extractError.message || extractError);
            }
        }
        
        const html = generateChatbotHTML(pageData, robotName, instructions);
        res.set('Content-Type', 'text/html');
        res.send(html);
    } catch (error) {
        logger.error('Chatbot route error:', error.message || error);
        res.status(500).send('Erro interno ao gerar chatbot');
    }
});

// LGPD routes
app.get('/privacy.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/excluir-dados', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'excluir-dados.html'));
});

// LGPD API endpoints
app.post('/api/log-consent', (req, res) => {
    try {
        const consentData = req.body;
        const ipHash = crypto.createHash('sha256')
            .update((req.ip || 'unknown') + (process.env.IP_SALT || 'default_salt'))
            .digest('hex').substring(0, 16);
        
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            consent: consentData,
            ipHash,
            userAgent: req.headers['user-agent'] || 'unknown',
            referer: req.headers.referer || ''
        };

        const logDir = path.join(__dirname, 'logs', 'consent');
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
        
        const logFile = path.join(logDir, `consent-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}.log`);
        fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');

        logger.info(`Consent logged: ${logEntry.id}`);
        res.json({ success: true, consentId: logEntry.id });
        
    } catch (error) {
        logger.error('Consent logging error:', error);
        res.status(500).json({ error: 'Failed to log consent' });
    }
});

app.post('/api/data-deletion', (req, res) => {
    try {
        const requestData = req.body;
        const requestId = crypto.randomUUID();
        const ipHash = crypto.createHash('sha256')
            .update((req.ip || 'unknown') + (process.env.IP_SALT || 'default_salt'))
            .digest('hex').substring(0, 16);
        
        const deletionRequest = {
            id: requestId,
            timestamp: new Date().toISOString(),
            email: requestData.email,
            robotName: requestData.robotName,
            url: requestData.url,
            requestType: requestData.requestType,
            dataTypes: requestData.dataTypes,
            reason: requestData.reason,
            status: 'pending',
            ipHash,
            userAgent: req.headers['user-agent'] || 'unknown',
            processingDeadline: new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString()
        };

        const logDir = path.join(__dirname, 'logs', 'deletion');
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
        
        const logFile = path.join(logDir, `deletion-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}.log`);
        fs.appendFileSync(logFile, JSON.stringify(deletionRequest) + '\n');

        logger.info(`Data deletion request: ${requestId}`);
        res.json({ 
            success: true, 
            requestId,
            message: 'Solicitação recebida. Será processada em até 72 horas.' 
        });
        
    } catch (error) {
        logger.error('Data deletion error:', error);
        res.status(500).json({ error: 'Failed to process deletion request' });
    }
});

// Admin dashboard (protected)
app.get('/admin', authenticateApiKey, (req, res) => {
    // Only allow admin access for enterprise plans or specific tenant
    if (req.tenant.plan !== 'enterprise') {
        return res.status(403).json({ error: 'Admin access denied' });
    }
    
    res.json({
        success: true,
        analytics: {
            totalTenants: tenantManager.tenants.size,
            totalRequests: analytics.totalRequests,
            totalTokens: analytics.tokenUsage,
            activeChats: analytics.activeChats.size,
            cacheSize: cache.size,
            uptime: process.uptime()
        },
        tenants: Array.from(tenantManager.tenants.values()).map(tenant => ({
            id: tenant.id,
            name: tenant.name,
            plan: tenant.plan,
            usage: tenant.usage,
            isActive: tenant.isActive,
            createdAt: tenant.createdAt
        }))
    });
});

// Fallback for SPA routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    logger.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// ===== SERVER STARTUP =====
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 LinkMágico Commercial Server v6.0 running on port ${PORT}`);
    logger.info(`📊 Health check: http://localhost:${PORT}/health`);
    logger.info(`🤖 Legacy chatbot: http://localhost:${PORT}/chatbot`);
    logger.info(`🔧 Widget JS: http://localhost:${PORT}/widget.js`);
    logger.info(`📄 Privacy Policy: http://localhost:${PORT}/privacy.html`);
    logger.info(`🗑️ Data Deletion: http://localhost:${PORT}/excluir-dados`);
    logger.info(`💳 Stripe configured: ${!!stripe}`);
    logger.info(`🔐 Total tenants loaded: ${tenantManager.tenants.size}`);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
    logger.info(`${signal} received, shutting down gracefully`);
    server.close(() => {
        logger.info('HTTP server closed');
        
        // Clean up resources
        cache.clear();
        analytics.activeChats.clear();
        
        logger.info('Process terminated');
        process.exit(0);
    });
    
    // Force close after 10 seconds
    setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = app;