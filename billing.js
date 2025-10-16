/**
 * 💳 SISTEMA DE BILLING E PAGAMENTOS - Link Mágico
 * Gerenciamento de planos, assinaturas e pagamentos
 * 
 * Integrações suportadas:
 * - Stripe
 * - PayPal (preparado para integração)
 * - PagSeguro (preparado para integração)
 */

const crypto = require('crypto');

/**
 * 📋 Definição de Planos
 */
const PLANS = {
    free: {
        id: 'free',
        name: 'Gratuito',
        price: 0,
        currency: 'BRL',
        interval: 'month',
        features: {
            maxChatbots: 1,
            maxMessagesPerMonth: 100,
            maxExtractions: 10,
            cacheEnabled: false,
            analyticsRetention: 7, // dias
            webhooksEnabled: false,
            apiAccess: false,
            customBranding: false,
            prioritySupport: false
        },
        limits: {
            requestsPerMinute: 10,
            requestsPerHour: 100,
            requestsPerDay: 500
        }
    },
    
    starter: {
        id: 'starter',
        name: 'Iniciante',
        price: 29.90,
        currency: 'BRL',
        interval: 'month',
        features: {
            maxChatbots: 3,
            maxMessagesPerMonth: 1000,
            maxExtractions: 50,
            cacheEnabled: true,
            analyticsRetention: 30,
            webhooksEnabled: true,
            maxWebhooks: 5,
            apiAccess: true,
            customBranding: false,
            prioritySupport: false
        },
        limits: {
            requestsPerMinute: 30,
            requestsPerHour: 500,
            requestsPerDay: 5000
        }
    },
    
    professional: {
        id: 'professional',
        name: 'Profissional',
        price: 79.90,
        currency: 'BRL',
        interval: 'month',
        features: {
            maxChatbots: 10,
            maxMessagesPerMonth: 5000,
            maxExtractions: 200,
            cacheEnabled: true,
            analyticsRetention: 90,
            webhooksEnabled: true,
            maxWebhooks: 20,
            apiAccess: true,
            customBranding: true,
            prioritySupport: true,
            advancedAnalytics: true,
            knowledgeBaseUpload: true
        },
        limits: {
            requestsPerMinute: 100,
            requestsPerHour: 2000,
            requestsPerDay: 20000
        }
    },
    
    enterprise: {
        id: 'enterprise',
        name: 'Empresarial',
        price: 299.90,
        currency: 'BRL',
        interval: 'month',
        features: {
            maxChatbots: -1, // ilimitado
            maxMessagesPerMonth: -1, // ilimitado
            maxExtractions: -1, // ilimitado
            cacheEnabled: true,
            analyticsRetention: 365,
            webhooksEnabled: true,
            maxWebhooks: -1, // ilimitado
            apiAccess: true,
            customBranding: true,
            prioritySupport: true,
            advancedAnalytics: true,
            knowledgeBaseUpload: true,
            dedicatedSupport: true,
            sla: true,
            whiteLabel: true
        },
        limits: {
            requestsPerMinute: -1, // ilimitado
            requestsPerHour: -1,
            requestsPerDay: -1
        }
    }
};

/**
 * 💼 Gerenciador de Billing
 */
class BillingManager {
    constructor() {
        this.subscriptions = new Map();
        this.usageTracking = new Map();
        this.stripeEnabled = !!process.env.STRIPE_SECRET_KEY;
        
        if (this.stripeEnabled) {
            this.initializeStripe();
        }
        
        console.log('💳 Sistema de Billing inicializado');
    }

    /**
     * Inicializar Stripe
     */
    initializeStripe() {
        try {
            const stripe = require('stripe');
            this.stripe = stripe(process.env.STRIPE_SECRET_KEY);
            console.log('✅ Stripe inicializado');
        } catch (error) {
            console.error('❌ Erro ao inicializar Stripe:', error.message);
            this.stripeEnabled = false;
        }
    }

    /**
     * Obter plano por ID
     */
    getPlan(planId) {
        return PLANS[planId] || PLANS.free;
    }

    /**
     * Listar todos os planos
     */
    listPlans() {
        return Object.values(PLANS);
    }

    /**
     * Criar assinatura
     */
    async createSubscription(userId, planId, paymentMethod = 'stripe') {
        const plan = this.getPlan(planId);
        
        if (!plan) {
            throw new Error('Plano não encontrado');
        }

        const subscription = {
            id: crypto.randomBytes(16).toString('hex'),
            userId,
            planId,
            plan,
            status: 'active',
            paymentMethod,
            currentPeriodStart: new Date(),
            currentPeriodEnd: this.calculatePeriodEnd(plan.interval),
            createdAt: new Date().toISOString(),
            cancelAtPeriodEnd: false
        };

        this.subscriptions.set(userId, subscription);
        
        // Inicializar tracking de uso
        this.initializeUsageTracking(userId, planId);
        
        console.log(`✅ Assinatura criada: ${userId} -> ${planId}`);
        
        return subscription;
    }

    /**
     * Calcular fim do período
     */
    calculatePeriodEnd(interval) {
        const now = new Date();
        
        switch (interval) {
            case 'month':
                return new Date(now.setMonth(now.getMonth() + 1));
            case 'year':
                return new Date(now.setFullYear(now.getFullYear() + 1));
            default:
                return new Date(now.setMonth(now.getMonth() + 1));
        }
    }

    /**
     * Obter assinatura do usuário
     */
    getSubscription(userId) {
        return this.subscriptions.get(userId) || {
            userId,
            planId: 'free',
            plan: PLANS.free,
            status: 'active'
        };
    }

    /**
     * Atualizar plano
     */
    async upgradePlan(userId, newPlanId) {
        const currentSubscription = this.getSubscription(userId);
        const newPlan = this.getPlan(newPlanId);

        if (!newPlan) {
            throw new Error('Plano não encontrado');
        }

        currentSubscription.planId = newPlanId;
        currentSubscription.plan = newPlan;
        currentSubscription.updatedAt = new Date().toISOString();

        this.subscriptions.set(userId, currentSubscription);
        
        console.log(`✅ Plano atualizado: ${userId} -> ${newPlanId}`);
        
        return currentSubscription;
    }

    /**
     * Cancelar assinatura
     */
    async cancelSubscription(userId, immediate = false) {
        const subscription = this.getSubscription(userId);

        if (immediate) {
            subscription.status = 'cancelled';
            subscription.cancelledAt = new Date().toISOString();
        } else {
            subscription.cancelAtPeriodEnd = true;
        }

        this.subscriptions.set(userId, subscription);
        
        console.log(`✅ Assinatura cancelada: ${userId}`);
        
        return subscription;
    }

    /**
     * Inicializar tracking de uso
     */
    initializeUsageTracking(userId, planId) {
        const now = new Date();
        const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

        if (!this.usageTracking.has(userId)) {
            this.usageTracking.set(userId, new Map());
        }

        const userUsage = this.usageTracking.get(userId);
        
        if (!userUsage.has(monthKey)) {
            userUsage.set(monthKey, {
                messages: 0,
                extractions: 0,
                apiCalls: 0,
                webhookCalls: 0,
                startDate: now.toISOString()
            });
        }
    }

    /**
     * Registrar uso
     */
    trackUsage(userId, type, amount = 1) {
        const now = new Date();
        const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

        if (!this.usageTracking.has(userId)) {
            this.initializeUsageTracking(userId, 'free');
        }

        const userUsage = this.usageTracking.get(userId);
        const monthUsage = userUsage.get(monthKey);

        if (monthUsage) {
            monthUsage[type] = (monthUsage[type] || 0) + amount;
        }
    }

    /**
     * Obter uso atual
     */
    getUsage(userId) {
        const now = new Date();
        const monthKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

        if (!this.usageTracking.has(userId)) {
            return {
                messages: 0,
                extractions: 0,
                apiCalls: 0,
                webhookCalls: 0
            };
        }

        const userUsage = this.usageTracking.get(userId);
        return userUsage.get(monthKey) || {
            messages: 0,
            extractions: 0,
            apiCalls: 0,
            webhookCalls: 0
        };
    }

    /**
     * Verificar se usuário pode usar recurso
     */
    canUseFeature(userId, feature, amount = 1) {
        const subscription = this.getSubscription(userId);
        const plan = subscription.plan;
        const usage = this.getUsage(userId);

        // Verificar limites do plano
        switch (feature) {
            case 'messages':
                if (plan.features.maxMessagesPerMonth === -1) return true;
                return usage.messages + amount <= plan.features.maxMessagesPerMonth;

            case 'extractions':
                if (plan.features.maxExtractions === -1) return true;
                return usage.extractions + amount <= plan.features.maxExtractions;

            case 'webhooks':
                return plan.features.webhooksEnabled;

            case 'api':
                return plan.features.apiAccess;

            case 'cache':
                return plan.features.cacheEnabled;

            case 'customBranding':
                return plan.features.customBranding;

            default:
                return true;
        }
    }

    /**
     * Obter limites restantes
     */
    getRemainingLimits(userId) {
        const subscription = this.getSubscription(userId);
        const plan = subscription.plan;
        const usage = this.getUsage(userId);

        return {
            messages: {
                used: usage.messages,
                limit: plan.features.maxMessagesPerMonth,
                remaining: plan.features.maxMessagesPerMonth === -1 
                    ? -1 
                    : plan.features.maxMessagesPerMonth - usage.messages
            },
            extractions: {
                used: usage.extractions,
                limit: plan.features.maxExtractions,
                remaining: plan.features.maxExtractions === -1 
                    ? -1 
                    : plan.features.maxExtractions - usage.extractions
            }
        };
    }

    /**
     * Criar sessão de checkout Stripe
     */
    async createCheckoutSession(userId, planId, successUrl, cancelUrl) {
        if (!this.stripeEnabled) {
            throw new Error('Stripe não está configurado');
        }

        const plan = this.getPlan(planId);

        if (!plan || plan.price === 0) {
            throw new Error('Plano inválido para checkout');
        }

        try {
            const session = await this.stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [
                    {
                        price_data: {
                            currency: plan.currency.toLowerCase(),
                            product_data: {
                                name: `Link Mágico - Plano ${plan.name}`,
                                description: `Assinatura ${plan.interval === 'month' ? 'mensal' : 'anual'}`
                            },
                            unit_amount: Math.round(plan.price * 100),
                            recurring: {
                                interval: plan.interval
                            }
                        },
                        quantity: 1
                    }
                ],
                mode: 'subscription',
                success_url: successUrl,
                cancel_url: cancelUrl,
                client_reference_id: userId,
                metadata: {
                    userId,
                    planId
                }
            });

            return session;
        } catch (error) {
            console.error('❌ Erro ao criar sessão de checkout:', error);
            throw error;
        }
    }

    /**
     * Webhook handler do Stripe
     */
    async handleStripeWebhook(event) {
        if (!this.stripeEnabled) {
            return;
        }

        try {
            switch (event.type) {
                case 'checkout.session.completed':
                    await this.handleCheckoutCompleted(event.data.object);
                    break;

                case 'customer.subscription.updated':
                    await this.handleSubscriptionUpdated(event.data.object);
                    break;

                case 'customer.subscription.deleted':
                    await this.handleSubscriptionDeleted(event.data.object);
                    break;

                case 'invoice.payment_succeeded':
                    await this.handlePaymentSucceeded(event.data.object);
                    break;

                case 'invoice.payment_failed':
                    await this.handlePaymentFailed(event.data.object);
                    break;

                default:
                    console.log(`⚠️ Evento Stripe não tratado: ${event.type}`);
            }
        } catch (error) {
            console.error('❌ Erro ao processar webhook Stripe:', error);
            throw error;
        }
    }

    /**
     * Handler: Checkout completado
     */
    async handleCheckoutCompleted(session) {
        const userId = session.client_reference_id;
        const planId = session.metadata.planId;

        await this.createSubscription(userId, planId, 'stripe');
        
        console.log(`✅ Checkout completado: ${userId} -> ${planId}`);
    }

    /**
     * Handler: Assinatura atualizada
     */
    async handleSubscriptionUpdated(subscription) {
        console.log('✅ Assinatura atualizada:', subscription.id);
    }

    /**
     * Handler: Assinatura deletada
     */
    async handleSubscriptionDeleted(subscription) {
        console.log('✅ Assinatura deletada:', subscription.id);
    }

    /**
     * Handler: Pagamento bem-sucedido
     */
    async handlePaymentSucceeded(invoice) {
        console.log('✅ Pagamento bem-sucedido:', invoice.id);
    }

    /**
     * Handler: Pagamento falhou
     */
    async handlePaymentFailed(invoice) {
        console.error('❌ Pagamento falhou:', invoice.id);
    }
}

// Instância global do gerenciador de billing
const billingManager = new BillingManager();

module.exports = {
    billingManager,
    PLANS
};
