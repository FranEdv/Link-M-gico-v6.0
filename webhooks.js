/**
 * 🔗 SISTEMA DE WEBHOOKS - Link Mágico
 * Permite integração com sistemas externos via webhooks
 * 
 * Eventos suportados:
 * - conversation_started: Nova conversa iniciada
 * - conversation_ended: Conversa finalizada
 * - lead_captured: Lead capturado com sucesso
 * - keyword_detected: Palavra-chave específica detectada
 * - message_sent: Mensagem enviada pelo bot
 * - message_received: Mensagem recebida do usuário
 */

const axios = require('axios');
const crypto = require('crypto');

class WebhookManager {
    constructor() {
        this.webhooks = new Map();
        this.queue = [];
        this.processing = false;
        this.retryAttempts = 3;
        this.retryDelay = 1000; // 1 segundo
        
        console.log('🔗 Sistema de Webhooks inicializado');
    }

    /**
     * Registrar webhook para um chatbot
     */
    registerWebhook(chatbotId, eventType, url, config = {}) {
        const webhookId = crypto.randomBytes(8).toString('hex');
        
        const webhook = {
            id: webhookId,
            chatbotId,
            eventType,
            url,
            active: true,
            secret: config.secret || crypto.randomBytes(16).toString('hex'),
            headers: config.headers || {},
            createdAt: new Date().toISOString()
        };

        if (!this.webhooks.has(chatbotId)) {
            this.webhooks.set(chatbotId, []);
        }

        this.webhooks.get(chatbotId).push(webhook);
        
        console.log(`✅ Webhook registrado: ${eventType} para chatbot ${chatbotId}`);
        
        return webhook;
    }

    /**
     * Remover webhook
     */
    removeWebhook(chatbotId, webhookId) {
        const chatbotWebhooks = this.webhooks.get(chatbotId);
        
        if (chatbotWebhooks) {
            const index = chatbotWebhooks.findIndex(w => w.id === webhookId);
            if (index !== -1) {
                chatbotWebhooks.splice(index, 1);
                console.log(`🗑️ Webhook removido: ${webhookId}`);
                return true;
            }
        }
        
        return false;
    }

    /**
     * Listar webhooks de um chatbot
     */
    listWebhooks(chatbotId) {
        return this.webhooks.get(chatbotId) || [];
    }

    /**
     * Disparar evento de webhook
     */
    async triggerEvent(chatbotId, eventType, data) {
        const chatbotWebhooks = this.webhooks.get(chatbotId);
        
        if (!chatbotWebhooks || chatbotWebhooks.length === 0) {
            return;
        }

        const relevantWebhooks = chatbotWebhooks.filter(
            w => w.active && (w.eventType === eventType || w.eventType === '*')
        );

        if (relevantWebhooks.length === 0) {
            return;
        }

        console.log(`📤 Disparando ${relevantWebhooks.length} webhook(s) para evento: ${eventType}`);

        for (const webhook of relevantWebhooks) {
            this.queueWebhook(webhook, eventType, data);
        }

        // Processar fila se não estiver processando
        if (!this.processing) {
            this.processQueue();
        }
    }

    /**
     * Adicionar webhook à fila
     */
    queueWebhook(webhook, eventType, data) {
        this.queue.push({
            webhook,
            eventType,
            data,
            attempts: 0,
            queuedAt: Date.now()
        });
    }

    /**
     * Processar fila de webhooks
     */
    async processQueue() {
        if (this.processing || this.queue.length === 0) {
            return;
        }

        this.processing = true;

        while (this.queue.length > 0) {
            const item = this.queue.shift();
            await this.sendWebhook(item);
        }

        this.processing = false;
    }

    /**
     * Enviar webhook com retry
     */
    async sendWebhook(item) {
        const { webhook, eventType, data, attempts } = item;

        try {
            const payload = {
                event: eventType,
                chatbotId: webhook.chatbotId,
                timestamp: new Date().toISOString(),
                data: data
            };

            // Gerar assinatura HMAC
            const signature = this.generateSignature(payload, webhook.secret);

            const headers = {
                'Content-Type': 'application/json',
                'X-Webhook-Signature': signature,
                'X-Webhook-Event': eventType,
                'X-Webhook-Id': webhook.id,
                ...webhook.headers
            };

            const response = await axios.post(webhook.url, payload, {
                headers,
                timeout: 10000,
                validateStatus: (status) => status >= 200 && status < 300
            });

            console.log(`✅ Webhook enviado com sucesso: ${eventType} -> ${webhook.url}`);
            
            return {
                success: true,
                status: response.status,
                attempts: attempts + 1
            };

        } catch (error) {
            console.error(`❌ Erro ao enviar webhook (tentativa ${attempts + 1}):`, error.message);

            // Retry se não excedeu o limite
            if (attempts < this.retryAttempts) {
                console.log(`🔄 Reagendando webhook para retry...`);
                
                setTimeout(() => {
                    item.attempts = attempts + 1;
                    this.queue.push(item);
                    
                    if (!this.processing) {
                        this.processQueue();
                    }
                }, this.retryDelay * (attempts + 1));
            } else {
                console.error(`❌ Webhook falhou após ${this.retryAttempts} tentativas`);
            }

            return {
                success: false,
                error: error.message,
                attempts: attempts + 1
            };
        }
    }

    /**
     * Gerar assinatura HMAC para validação
     */
    generateSignature(payload, secret) {
        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(JSON.stringify(payload));
        return hmac.digest('hex');
    }

    /**
     * Validar assinatura de webhook (para endpoints que recebem webhooks)
     */
    validateSignature(payload, signature, secret) {
        const expectedSignature = this.generateSignature(payload, secret);
        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expectedSignature)
        );
    }

    /**
     * Testar webhook
     */
    async testWebhook(webhook) {
        const testData = {
            test: true,
            message: 'Este é um webhook de teste do Link Mágico',
            timestamp: new Date().toISOString()
        };

        return await this.sendWebhook({
            webhook,
            eventType: 'test',
            data: testData,
            attempts: 0
        });
    }

    /**
     * Obter estatísticas de webhooks
     */
    getStats() {
        let totalWebhooks = 0;
        let activeWebhooks = 0;

        for (const [chatbotId, webhooks] of this.webhooks.entries()) {
            totalWebhooks += webhooks.length;
            activeWebhooks += webhooks.filter(w => w.active).length;
        }

        return {
            totalWebhooks,
            activeWebhooks,
            queueSize: this.queue.length,
            processing: this.processing
        };
    }
}

// Instância global do gerenciador de webhooks
const webhookManager = new WebhookManager();

/**
 * 📡 Funções auxiliares para eventos comuns
 */
const WebhookEvents = {
    /**
     * Evento: Nova conversa iniciada
     */
    async conversationStarted(chatbotId, sessionId, metadata = {}) {
        await webhookManager.triggerEvent(chatbotId, 'conversation_started', {
            sessionId,
            startedAt: new Date().toISOString(),
            ...metadata
        });
    },

    /**
     * Evento: Conversa finalizada
     */
    async conversationEnded(chatbotId, sessionId, summary = {}) {
        await webhookManager.triggerEvent(chatbotId, 'conversation_ended', {
            sessionId,
            endedAt: new Date().toISOString(),
            messageCount: summary.messageCount || 0,
            duration: summary.duration || 0,
            resolved: summary.resolved || false,
            ...summary
        });
    },

    /**
     * Evento: Lead capturado
     */
    async leadCaptured(chatbotId, leadData) {
        await webhookManager.triggerEvent(chatbotId, 'lead_captured', {
            lead: leadData,
            capturedAt: new Date().toISOString()
        });
    },

    /**
     * Evento: Palavra-chave detectada
     */
    async keywordDetected(chatbotId, keyword, message, context = {}) {
        await webhookManager.triggerEvent(chatbotId, 'keyword_detected', {
            keyword,
            message,
            detectedAt: new Date().toISOString(),
            ...context
        });
    },

    /**
     * Evento: Mensagem enviada pelo bot
     */
    async messageSent(chatbotId, sessionId, message) {
        await webhookManager.triggerEvent(chatbotId, 'message_sent', {
            sessionId,
            message,
            sentAt: new Date().toISOString()
        });
    },

    /**
     * Evento: Mensagem recebida do usuário
     */
    async messageReceived(chatbotId, sessionId, message) {
        await webhookManager.triggerEvent(chatbotId, 'message_received', {
            sessionId,
            message,
            receivedAt: new Date().toISOString()
        });
    }
};

module.exports = {
    webhookManager,
    WebhookEvents
};
