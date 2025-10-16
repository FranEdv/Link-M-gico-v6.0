/**
 * 🛣️ NOVAS ROTAS DE API - Link Mágico
 * Rotas para as novas funcionalidades implementadas
 */

const express = require('express');
const { DatabaseHelpers } = require('./database');
const { CacheManager } = require('./cache');
const { webhookManager, WebhookEvents } = require('./webhooks');
const { billingManager, PLANS } = require('./billing');
const { analyticsManager } = require('./analytics');
const { llmOptimizer } = require('./llm-optimizer');
const { knowledgeBaseManager } = require('./knowledge-base');

/**
 * Configurar todas as novas rotas
 */
function setupRoutes(app) {
    
    // ===== ROTAS DE ANALYTICS =====
    
    /**
     * GET /api/analytics/:chatbotId
     * Obter analytics de um chatbot
     */
    app.get('/api/analytics/:chatbotId', async (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { days = 30 } = req.query;
            
            const summary = await analyticsManager.getSummary(chatbotId, parseInt(days));
            
            res.json({
                success: true,
                chatbotId,
                period: `${days} dias`,
                analytics: summary
            });
        } catch (error) {
            console.error('❌ Erro ao obter analytics:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter analytics'
            });
        }
    });

    /**
     * GET /api/analytics/:chatbotId/export
     * Exportar analytics para CSV
     */
    app.get('/api/analytics/:chatbotId/export', async (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { startDate, endDate } = req.query;
            
            if (!startDate || !endDate) {
                return res.status(400).json({
                    success: false,
                    error: 'startDate e endDate são obrigatórios'
                });
            }
            
            const csv = await analyticsManager.exportToCSV(chatbotId, startDate, endDate);
            
            if (!csv) {
                return res.status(404).json({
                    success: false,
                    error: 'Nenhum dado encontrado para o período'
                });
            }
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=analytics-${chatbotId}.csv`);
            res.send(csv);
        } catch (error) {
            console.error('❌ Erro ao exportar analytics:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao exportar analytics'
            });
        }
    });

    // ===== ROTAS DE WEBHOOKS =====
    
    /**
     * POST /api/webhooks/:chatbotId
     * Registrar novo webhook
     */
    app.post('/api/webhooks/:chatbotId', async (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { eventType, url, secret, headers } = req.body;
            
            if (!eventType || !url) {
                return res.status(400).json({
                    success: false,
                    error: 'eventType e url são obrigatórios'
                });
            }
            
            const webhook = webhookManager.registerWebhook(chatbotId, eventType, url, {
                secret,
                headers
            });
            
            res.json({
                success: true,
                webhook
            });
        } catch (error) {
            console.error('❌ Erro ao registrar webhook:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao registrar webhook'
            });
        }
    });

    /**
     * GET /api/webhooks/:chatbotId
     * Listar webhooks de um chatbot
     */
    app.get('/api/webhooks/:chatbotId', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const webhooks = webhookManager.listWebhooks(chatbotId);
            
            res.json({
                success: true,
                webhooks
            });
        } catch (error) {
            console.error('❌ Erro ao listar webhooks:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao listar webhooks'
            });
        }
    });

    /**
     * DELETE /api/webhooks/:chatbotId/:webhookId
     * Remover webhook
     */
    app.delete('/api/webhooks/:chatbotId/:webhookId', (req, res) => {
        try {
            const { chatbotId, webhookId } = req.params;
            const removed = webhookManager.removeWebhook(chatbotId, webhookId);
            
            if (removed) {
                res.json({
                    success: true,
                    message: 'Webhook removido com sucesso'
                });
            } else {
                res.status(404).json({
                    success: false,
                    error: 'Webhook não encontrado'
                });
            }
        } catch (error) {
            console.error('❌ Erro ao remover webhook:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao remover webhook'
            });
        }
    });

    /**
     * POST /api/webhooks/:chatbotId/:webhookId/test
     * Testar webhook
     */
    app.post('/api/webhooks/:chatbotId/:webhookId/test', async (req, res) => {
        try {
            const { chatbotId, webhookId } = req.params;
            const webhooks = webhookManager.listWebhooks(chatbotId);
            const webhook = webhooks.find(w => w.id === webhookId);
            
            if (!webhook) {
                return res.status(404).json({
                    success: false,
                    error: 'Webhook não encontrado'
                });
            }
            
            const result = await webhookManager.testWebhook(webhook);
            
            res.json({
                success: result.success,
                result
            });
        } catch (error) {
            console.error('❌ Erro ao testar webhook:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao testar webhook'
            });
        }
    });

    // ===== ROTAS DE BILLING =====
    
    /**
     * GET /api/plans
     * Listar todos os planos disponíveis
     */
    app.get('/api/plans', (req, res) => {
        try {
            const plans = billingManager.listPlans();
            
            res.json({
                success: true,
                plans
            });
        } catch (error) {
            console.error('❌ Erro ao listar planos:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao listar planos'
            });
        }
    });

    /**
     * GET /api/subscription/:userId
     * Obter assinatura de um usuário
     */
    app.get('/api/subscription/:userId', (req, res) => {
        try {
            const { userId } = req.params;
            const subscription = billingManager.getSubscription(userId);
            const usage = billingManager.getUsage(userId);
            const limits = billingManager.getRemainingLimits(userId);
            
            res.json({
                success: true,
                subscription,
                usage,
                limits
            });
        } catch (error) {
            console.error('❌ Erro ao obter assinatura:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter assinatura'
            });
        }
    });

    /**
     * POST /api/subscription/:userId/upgrade
     * Fazer upgrade de plano
     */
    app.post('/api/subscription/:userId/upgrade', async (req, res) => {
        try {
            const { userId } = req.params;
            const { planId } = req.body;
            
            if (!planId) {
                return res.status(400).json({
                    success: false,
                    error: 'planId é obrigatório'
                });
            }
            
            const subscription = await billingManager.upgradePlan(userId, planId);
            
            res.json({
                success: true,
                subscription
            });
        } catch (error) {
            console.error('❌ Erro ao fazer upgrade:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });

    /**
     * POST /api/subscription/:userId/checkout
     * Criar sessão de checkout
     */
    app.post('/api/subscription/:userId/checkout', async (req, res) => {
        try {
            const { userId } = req.params;
            const { planId, successUrl, cancelUrl } = req.body;
            
            if (!planId || !successUrl || !cancelUrl) {
                return res.status(400).json({
                    success: false,
                    error: 'planId, successUrl e cancelUrl são obrigatórios'
                });
            }
            
            const session = await billingManager.createCheckoutSession(
                userId,
                planId,
                successUrl,
                cancelUrl
            );
            
            res.json({
                success: true,
                sessionId: session.id,
                url: session.url
            });
        } catch (error) {
            console.error('❌ Erro ao criar checkout:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });

    /**
     * POST /api/webhooks/stripe
     * Webhook do Stripe
     */
    app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
        try {
            const sig = req.headers['stripe-signature'];
            const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
            
            if (!webhookSecret) {
                console.error('❌ STRIPE_WEBHOOK_SECRET não configurado');
                return res.status(500).send('Webhook secret not configured');
            }
            
            const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
            const event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
            
            await billingManager.handleStripeWebhook(event);
            
            res.json({ received: true });
        } catch (error) {
            console.error('❌ Erro no webhook Stripe:', error);
            res.status(400).send(`Webhook Error: ${error.message}`);
        }
    });

    // ===== ROTAS DE KNOWLEDGE BASE =====
    
    /**
     * POST /api/knowledge/:chatbotId/faq
     * Adicionar FAQ
     */
    app.post('/api/knowledge/:chatbotId/faq', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { question, answer, category } = req.body;
            
            if (!question || !answer) {
                return res.status(400).json({
                    success: false,
                    error: 'question e answer são obrigatórios'
                });
            }
            
            const faq = knowledgeBaseManager.addFAQ(chatbotId, question, answer, category);
            
            res.json({
                success: true,
                faq
            });
        } catch (error) {
            console.error('❌ Erro ao adicionar FAQ:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao adicionar FAQ'
            });
        }
    });

    /**
     * POST /api/knowledge/:chatbotId/faqs/bulk
     * Adicionar múltiplas FAQs
     */
    app.post('/api/knowledge/:chatbotId/faqs/bulk', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { faqs } = req.body;
            
            if (!Array.isArray(faqs)) {
                return res.status(400).json({
                    success: false,
                    error: 'faqs deve ser um array'
                });
            }
            
            const addedFaqs = knowledgeBaseManager.addMultipleFAQs(chatbotId, faqs);
            
            res.json({
                success: true,
                count: addedFaqs.length,
                faqs: addedFaqs
            });
        } catch (error) {
            console.error('❌ Erro ao adicionar FAQs:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao adicionar FAQs'
            });
        }
    });

    /**
     * POST /api/knowledge/:chatbotId/document
     * Adicionar documento
     */
    app.post('/api/knowledge/:chatbotId/document', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { title, content, metadata } = req.body;
            
            if (!title || !content) {
                return res.status(400).json({
                    success: false,
                    error: 'title e content são obrigatórios'
                });
            }
            
            const document = knowledgeBaseManager.addDocument(chatbotId, title, content, metadata);
            
            res.json({
                success: true,
                document
            });
        } catch (error) {
            console.error('❌ Erro ao adicionar documento:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao adicionar documento'
            });
        }
    });

    /**
     * GET /api/knowledge/:chatbotId
     * Obter base de conhecimento completa
     */
    app.get('/api/knowledge/:chatbotId', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const kb = knowledgeBaseManager.getKnowledgeBase(chatbotId);
            
            if (!kb) {
                return res.status(404).json({
                    success: false,
                    error: 'Base de conhecimento não encontrada'
                });
            }
            
            res.json({
                success: true,
                knowledgeBase: kb
            });
        } catch (error) {
            console.error('❌ Erro ao obter base de conhecimento:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter base de conhecimento'
            });
        }
    });

    /**
     * GET /api/knowledge/:chatbotId/stats
     * Obter estatísticas da base de conhecimento
     */
    app.get('/api/knowledge/:chatbotId/stats', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const stats = knowledgeBaseManager.getStats(chatbotId);
            
            res.json({
                success: true,
                stats
            });
        } catch (error) {
            console.error('❌ Erro ao obter estatísticas:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter estatísticas'
            });
        }
    });

    /**
     * DELETE /api/knowledge/:chatbotId/:entryType/:entryId
     * Remover entrada da base de conhecimento
     */
    app.delete('/api/knowledge/:chatbotId/:entryType/:entryId', (req, res) => {
        try {
            const { chatbotId, entryType, entryId } = req.params;
            const removed = knowledgeBaseManager.removeEntry(chatbotId, entryId, entryType);
            
            if (removed) {
                res.json({
                    success: true,
                    message: 'Entrada removida com sucesso'
                });
            } else {
                res.status(404).json({
                    success: false,
                    error: 'Entrada não encontrada'
                });
            }
        } catch (error) {
            console.error('❌ Erro ao remover entrada:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao remover entrada'
            });
        }
    });

    // ===== ROTAS DE OTIMIZAÇÃO LLM =====
    
    /**
     * GET /api/llm/stats/:chatbotId
     * Obter estatísticas de uso de LLM
     */
    app.get('/api/llm/stats/:chatbotId', (req, res) => {
        try {
            const { chatbotId } = req.params;
            const { days = 30 } = req.query;
            
            const stats = llmOptimizer.getUsageStats(chatbotId, parseInt(days));
            const savings = llmOptimizer.getSavingsSummary(chatbotId);
            const cacheStats = llmOptimizer.getCacheStats();
            
            res.json({
                success: true,
                usage: stats,
                savings,
                cache: cacheStats
            });
        } catch (error) {
            console.error('❌ Erro ao obter estatísticas LLM:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter estatísticas'
            });
        }
    });

    // ===== ROTAS DE CACHE =====
    
    /**
     * GET /api/cache/stats
     * Obter estatísticas do cache
     */
    app.get('/api/cache/stats', async (req, res) => {
        try {
            const stats = await CacheManager.getCacheStats();
            
            res.json({
                success: true,
                stats
            });
        } catch (error) {
            console.error('❌ Erro ao obter estatísticas do cache:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter estatísticas'
            });
        }
    });

    /**
     * POST /api/cache/clear
     * Limpar cache
     */
    app.post('/api/cache/clear', async (req, res) => {
        try {
            const { pattern } = req.body;
            
            let cleared;
            if (pattern) {
                cleared = await CacheManager.clearCacheByPattern(pattern);
            } else {
                cleared = await CacheManager.clearAllCache();
            }
            
            res.json({
                success: true,
                message: 'Cache limpo com sucesso',
                cleared
            });
        } catch (error) {
            console.error('❌ Erro ao limpar cache:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao limpar cache'
            });
        }
    });

    // ===== ROTA DE STATUS DO SISTEMA =====
    
    /**
     * GET /api/system/status
     * Obter status de todos os sistemas
     */
    app.get('/api/system/status', async (req, res) => {
        try {
            const status = {
                server: 'online',
                timestamp: new Date().toISOString(),
                database: {
                    type: USE_POSTGRES ? 'PostgreSQL' : 'SQLite',
                    connected: true
                },
                cache: {
                    type: isRedisConnected() ? 'Redis' : 'In-Memory',
                    connected: true,
                    stats: await CacheManager.getCacheStats()
                },
                webhooks: webhookManager.getStats(),
                features: {
                    billing: !!process.env.STRIPE_SECRET_KEY,
                    webhooks: true,
                    analytics: true,
                    llmOptimization: true,
                    knowledgeBase: true
                }
            };
            
            res.json({
                success: true,
                status
            });
        } catch (error) {
            console.error('❌ Erro ao obter status:', error);
            res.status(500).json({
                success: false,
                error: 'Erro ao obter status'
            });
        }
    });

    console.log('✅ Novas rotas de API configuradas');
}

module.exports = { setupRoutes };
