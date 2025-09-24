// server.js - LinkMágico v6.0 Server Corrigido
require('dotenv').config();

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

// Optional dependencies with graceful fallback
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
        })
    ]
});

// Trust proxy for accurate IP addresses
app.set('trust proxy', true);

// ===== Middleware =====
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: ['https://link-m-gico-v6-0-hmpl.onrender.com', 'http://localhost:3000', 'http://localhost:8080'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));

app.use(morgan('combined'));

// Serve static files from public directory
app.use(express.static('public', {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));

// ===== Analytics & Cache =====
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

function setCacheData(key, data) {
    dataCache.set(key, { data, timestamp: Date.now() });
}

function getCacheData(key) {
    const cached = dataCache.get(key);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
        return cached.data;
    }
    dataCache.delete(key);
    return null;
}

// ===== Utility functions =====
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

// ===== Content extraction =====
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

// ===== Page extraction =====
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

                // Title
                const titleSelectors = ['h1', 'meta[property="og:title"]', 'meta[name="twitter:title"]', 'title'];
                for (const selector of titleSelectors) {
                    const el = $(selector).first();
                    const title = (el.attr && (el.attr('content') || el.text) ? (el.attr('content') || el.text()) : el.text ? el.text() : '').toString().trim();
                    if (title && title.length > 5 && title.length < 200) {
                        extractedData.title = title;
                        break;
                    }
                }

                // Description
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

        // Puppeteer fallback
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

                // Quick scroll for dynamic content
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

        // Final processing
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

// ===== LLM Integration =====
async function callGroq(messages, temperature = 0.4, maxTokens = 300) {
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
    if (!(response && response.status >= 200 && response.status < 300)) throw new Error(`GROQ API failed with status ${response?.status}`);
    if (response.data?.choices?.[0]?.message?.content) return response.data.choices[0].message.content;
    throw new Error('Invalid GROQ API response format');
}

async function callOpenAI(messages, temperature = 0.2, maxTokens = 300) {
    if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY missing');

    const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
    const url = process.env.OPENAI_API_BASE || 'https://api.openai.com/v1/chat/completions';
    const payload = { model, messages, temperature, max_tokens: maxTokens };
    const headers = { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' };
    const response = await axios.post(url, payload, { headers, timeout: 15000 });
    if (!(response && response.status >= 200 && response.status < 300)) throw new Error(`OpenAI API failed with status ${response?.status}`);
    if (response.data?.choices?.[0]?.message?.content) return response.data.choices[0].message.content;
    throw new Error('Invalid OpenAI API response format');
}

// ===== Answer generation =====
const NOT_FOUND_MSG = "Não encontrei essa informação específica na página. Posso te ajudar com outras dúvidas?";

function shouldActivateSalesMode(instructions = '') {
    if (!instructions) return false;
    const text = String(instructions || '').toLowerCase();
    return /sales_mode:on|consultivo|vendas|venda|cta|sempre.*link|finalize.*cta/i.test(text);
}

async function generateAIResponse(userMessage, pageData = {}, conversation = [], instructions = '') {
    const startTime = Date.now();
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
        if (pageData.bonuses_detected && pageData.bonuses_detected.length > 0) contextLines.push(`Bônus: ${pageData.bonuses_detected.slice(0, 3).join(', ')}`);
        const contentExcerpt = (pageData.summary || pageData.cleanText || '').slice(0, 1000);
        if (contentExcerpt) contextLines.push(`Informações: ${contentExcerpt}`);

        const pageContext = contextLines.join('\n');
        const userPrompt = `${instructions ? `Instruções: ${instructions}\n\n` : ''}Contexto:\n${pageContext}\n\nPergunta: ${userMessage}\n\nResponda de forma concisa usando apenas as informações fornecidas.`;

        const messages = [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }];

        let response = null;
        let usedProvider = 'local';

        if (process.env.GROQ_API_KEY) {
            try {
                response = await callGroq(messages, 0.4, 250);
                usedProvider = 'groq';
                logger.info('GROQ API call successful');
            } catch (groqError) {
                logger.warn(`GROQ failed: ${groqError.message || groqError}`);
            }
        }

        if (!response && process.env.OPENAI_API_KEY) {
            try {
                response = await callOpenAI(messages, 0.2, 250);
                usedProvider = 'openai';
                logger.info('OpenAI API call successful');
            } catch (openaiError) {
                logger.warn(`OpenAI failed: ${openaiError.message || openaiError}`);
            }
        }

        if (!response || !String(response).trim()) {
            response = generateLocalResponse(userMessage, pageData, instructions);
            usedProvider = 'local';
        }

        const finalResponse = clampSentences(String(response).trim(), 3);
        const responseTime = Date.now() - startTime;
        logger.info(`AI response generated in ${responseTime}ms using ${usedProvider}`);
        return finalResponse;

    } catch (error) {
        logger.error('AI response generation failed:', error.message || error);
        return NOT_FOUND_MSG;
    }
}

function generateLocalResponse(userMessage, pageData = {}, instructions = '') {
    const question = (userMessage || '').toLowerCase();
    const salesMode = shouldActivateSalesMode(instructions);

    if (/preço|valor|quanto custa/.test(question)) {
        return 'Para informações sobre preços, consulte diretamente a página do produto.';
    }

    if (/como funciona|funcionamento/.test(question)) {
        const summary = pageData.summary || pageData.description;
        if (summary) {
            const shortSummary = clampSentences(summary, 2);
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
        const summary = clampSentences(pageData.summary, 2);
        return salesMode ? `${summary} Posso te ajudar com mais alguma dúvida?` : summary;
    }

    return NOT_FOUND_MSG;
}

// ===== API Routes =====
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
            puppeteer: !!puppeteer
        }
    });
});

// ROTA PRINCIPAL - Serve o index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ROTA CHAT.HTML - Que o frontend espera
app.get('/chat.html', (req, res) => {
    const robotName = req.query.name || 'Assistente IA';
    const url = req.query.url || '';
    const instructions = req.query.instructions || '';
    
    // Redireciona para a rota do chatbot
    res.redirect(`/chatbot?name=${encodeURIComponent(robotName)}&url=${encodeURIComponent(url)}&instructions=${encodeURIComponent(instructions)}`);
});

// /extract endpoint CORRIGIDO
app.post('/extract', async (req, res) => {
    analytics.extractRequests++;
    try {
        const { url, instructions, robotName } = req.body || {};
        
        console.log('📥 Recebendo requisição para extrair:', url);
        
        if (!url) {
            return res.status(400).json({ 
                success: false, 
                error: 'URL é obrigatório' 
            });
        }

        // Validação básica de URL
        try { 
            new URL(url); 
        } catch (urlErr) { 
            return res.status(400).json({ 
                success: false, 
                error: 'URL inválido' 
            }); 
        }

        logger.info(`Starting extraction for URL: ${url}`);
        
        const extractedData = await extractPageData(url);
        
        if (instructions) extractedData.custom_instructions = instructions;
        if (robotName) extractedData.robot_name = robotName;

        console.log('✅ Extração concluída com sucesso');
        
        return res.json({ 
            success: true, 
            data: extractedData 
        });

    } catch (error) {
        analytics.errors++;
        console.error('❌ Erro no endpoint /extract:', error);
        logger.error('Extract endpoint error:', error.message || error);
        
        return res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao extrair página: ' + (error.message || 'Erro desconhecido')
        });
    }
});

// /chat-universal endpoint CORRIGIDO
app.post('/chat-universal', async (req, res) => {
    analytics.chatRequests++;
    try {
        const { message, pageData, url, conversationId, instructions = '', robotName } = req.body || {};
        
        if (!message) {
            return res.status(400).json({ 
                success: false, 
                error: 'Mensagem é obrigatória' 
            });
        }

        if (conversationId) {
            analytics.activeChats.add(conversationId);
            setTimeout(() => analytics.activeChats.delete(conversationId), 30 * 60 * 1000);
        }

        let processedPageData = pageData;
        if (!processedPageData && url) {
            processedPageData = await extractPageData(url);
        }

        const aiResponse = await generateAIResponse(message, processedPageData || {}, [], instructions);

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

    } catch (error) {
        analytics.errors++;
        logger.error('Chat endpoint error:', error.message || error);
        return res.status(500).json({ 
            success: false, 
            error: 'Erro interno ao gerar resposta: ' + (error.message || 'Erro desconhecido')
        });
    }
});

// Widget JS
app.get('/widget.js', (req, res) => {
    res.set('Content-Type', 'application/javascript');
    res.send(`// LinkMágico Widget v6.0
(function() {
    'use strict';
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
                headers: {'Content-Type': 'application/json'},
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
            if (container) { 
                container.appendChild(div); 
                container.scrollTop = container.scrollHeight; 
            }
        }
    };
    
        };
    
    window.LinkMagicoWidget = LinkMagicoWidget;
})();
`);
});

// Chatbot HTML endpoint
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
                pageData = await extractPageData(url);
            } catch (extractError) {
                console.warn('Failed to extract page data:', extractError.message || extractError);
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

// ===== ROTAS LGPD CORRIGIDAS - SERVIÇO DOS ARQUIVOS EXISTENTES =====

// Rota para Política de Privacidade (arquivo existente)
app.get('/privacy.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

// Rota para Excluir Dados (arquivo existente)
app.get('/excluir-dados', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'excluir-dados.html'));
});

// Rotas alternativas para compatibilidade
app.get('/privacy-policy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/delete-data', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'excluir-dados.html'));
});

// Rota para Data Deletion (alternativa em inglês)
app.get('/data-deletion', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'excluir-dados.html'));
});

// ===== FIM DAS ROTAS LGPD =====

// Rota de fallback para qualquer outra requisição
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== Server startup =====
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 LinkMágico Server v6.0 rodando na porta ${PORT}`);
    logger.info(`📊 Health check disponível em: http://localhost:${PORT}/health`);
    logger.info(`🤖 Chatbot disponível em: http://localhost:${PORT}/chatbot`);
    logger.info(`🔧 Widget JS disponível em: http://localhost:${PORT}/widget.js`);
    logger.info(`📄 Política de Privacidade disponível em: http://localhost:${PORT}/privacy.html`);
    logger.info(`🗑️ Exclusão de Dados disponível em: http://localhost:${PORT}/excluir-dados`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    logger.info('SIGINT received, shutting down gracefully');
    server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
    });
});

module.exports = app;
