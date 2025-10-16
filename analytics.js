/**
 * 📊 SISTEMA DE ANALYTICS AVANÇADO - Link Mágico
 * Coleta, processa e apresenta métricas detalhadas
 * 
 * Métricas rastreadas:
 * - Volume de mensagens
 * - Tempo de resposta
 * - Taxa de sucesso
 * - Satisfação do usuário
 * - Custos de API
 * - Conversões e leads
 */

const fs = require('fs');
const path = require('path');

class AnalyticsManager {
    constructor() {
        this.metricsBuffer = new Map();
        this.flushInterval = 60000; // 1 minuto
        this.dataPath = path.join(__dirname, 'data', 'analytics');
        
        this.ensureDataDirectory();
        this.startFlushTimer();
        
        console.log('📊 Sistema de Analytics inicializado');
    }

    /**
     * Garantir que o diretório de dados existe
     */
    ensureDataDirectory() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    /**
     * Iniciar timer de flush
     */
    startFlushTimer() {
        setInterval(() => {
            this.flushMetrics();
        }, this.flushInterval);
    }

    /**
     * Registrar evento
     */
    trackEvent(chatbotId, eventType, data = {}) {
        const key = `${chatbotId}:${this.getTodayKey()}`;
        
        if (!this.metricsBuffer.has(key)) {
            this.metricsBuffer.set(key, {
                chatbotId,
                date: new Date().toISOString().split('T')[0],
                events: [],
                metrics: this.initializeMetrics()
            });
        }

        const buffer = this.metricsBuffer.get(key);
        
        buffer.events.push({
            type: eventType,
            timestamp: new Date().toISOString(),
            data
        });

        // Atualizar métricas agregadas
        this.updateMetrics(buffer.metrics, eventType, data);
    }

    /**
     * Inicializar estrutura de métricas
     */
    initializeMetrics() {
        return {
            totalMessages: 0,
            userMessages: 0,
            botMessages: 0,
            totalConversations: 0,
            activeConversations: new Set(),
            avgResponseTime: 0,
            responseTimes: [],
            successCount: 0,
            errorCount: 0,
            apiCalls: {
                groq: 0,
                openai: 0,
                openrouter: 0,
                total: 0
            },
            tokensUsed: {
                groq: 0,
                openai: 0,
                openrouter: 0,
                total: 0
            },
            costs: {
                groq: 0,
                openai: 0,
                openrouter: 0,
                total: 0
            },
            leads: {
                captured: 0,
                emails: 0,
                phones: 0
            },
            satisfaction: {
                positive: 0,
                neutral: 0,
                negative: 0,
                total: 0
            },
            keywords: new Map(),
            topQuestions: new Map(),
            errorTypes: new Map()
        };
    }

    /**
     * Atualizar métricas agregadas
     */
    updateMetrics(metrics, eventType, data) {
        switch (eventType) {
            case 'message_received':
                metrics.totalMessages++;
                metrics.userMessages++;
                
                if (data.sessionId) {
                    metrics.activeConversations.add(data.sessionId);
                    metrics.totalConversations = metrics.activeConversations.size;
                }
                
                // Rastrear perguntas frequentes
                if (data.message) {
                    const question = data.message.toLowerCase().substring(0, 100);
                    metrics.topQuestions.set(
                        question,
                        (metrics.topQuestions.get(question) || 0) + 1
                    );
                }
                break;

            case 'message_sent':
                metrics.totalMessages++;
                metrics.botMessages++;
                
                // Calcular tempo de resposta
                if (data.responseTime) {
                    metrics.responseTimes.push(data.responseTime);
                    metrics.avgResponseTime = 
                        metrics.responseTimes.reduce((a, b) => a + b, 0) / 
                        metrics.responseTimes.length;
                }
                break;

            case 'api_call':
                const provider = data.provider || 'unknown';
                
                if (metrics.apiCalls[provider] !== undefined) {
                    metrics.apiCalls[provider]++;
                }
                metrics.apiCalls.total++;
                
                // Rastrear tokens
                if (data.tokensUsed) {
                    if (metrics.tokensUsed[provider] !== undefined) {
                        metrics.tokensUsed[provider] += data.tokensUsed;
                    }
                    metrics.tokensUsed.total += data.tokensUsed;
                }
                
                // Calcular custos
                if (data.cost) {
                    if (metrics.costs[provider] !== undefined) {
                        metrics.costs[provider] += data.cost;
                    }
                    metrics.costs.total += data.cost;
                }
                
                metrics.successCount++;
                break;

            case 'api_error':
                metrics.errorCount++;
                
                const errorType = data.errorType || 'unknown';
                metrics.errorTypes.set(
                    errorType,
                    (metrics.errorTypes.get(errorType) || 0) + 1
                );
                break;

            case 'lead_captured':
                metrics.leads.captured++;
                
                if (data.email) metrics.leads.emails++;
                if (data.phone) metrics.leads.phones++;
                break;

            case 'satisfaction':
                const rating = data.rating || 'neutral';
                
                if (metrics.satisfaction[rating] !== undefined) {
                    metrics.satisfaction[rating]++;
                }
                metrics.satisfaction.total++;
                break;

            case 'keyword_detected':
                if (data.keyword) {
                    metrics.keywords.set(
                        data.keyword,
                        (metrics.keywords.get(data.keyword) || 0) + 1
                    );
                }
                break;

            case 'conversation_ended':
                if (data.sessionId) {
                    metrics.activeConversations.delete(data.sessionId);
                }
                break;
        }
    }

    /**
     * Obter chave do dia atual
     */
    getTodayKey() {
        return new Date().toISOString().split('T')[0];
    }

    /**
     * Flush métricas para disco
     */
    async flushMetrics() {
        if (this.metricsBuffer.size === 0) {
            return;
        }

        console.log(`💾 Salvando ${this.metricsBuffer.size} buffer(s) de métricas...`);

        for (const [key, buffer] of this.metricsBuffer.entries()) {
            try {
                // Converter Maps para objetos
                const metricsToSave = {
                    ...buffer,
                    metrics: {
                        ...buffer.metrics,
                        activeConversations: Array.from(buffer.metrics.activeConversations),
                        keywords: Object.fromEntries(buffer.metrics.keywords),
                        topQuestions: Object.fromEntries(buffer.metrics.topQuestions),
                        errorTypes: Object.fromEntries(buffer.metrics.errorTypes)
                    }
                };

                const filename = `${buffer.chatbotId}_${buffer.date}.json`;
                const filepath = path.join(this.dataPath, filename);

                // Se arquivo já existe, mesclar dados
                if (fs.existsSync(filepath)) {
                    const existing = JSON.parse(fs.readFileSync(filepath, 'utf8'));
                    metricsToSave.events = [...existing.events, ...metricsToSave.events];
                    
                    // Mesclar métricas
                    metricsToSave.metrics = this.mergeMetrics(
                        existing.metrics,
                        metricsToSave.metrics
                    );
                }

                fs.writeFileSync(filepath, JSON.stringify(metricsToSave, null, 2));
                
            } catch (error) {
                console.error(`❌ Erro ao salvar métricas para ${key}:`, error);
            }
        }

        this.metricsBuffer.clear();
        console.log('✅ Métricas salvas com sucesso');
    }

    /**
     * Mesclar métricas
     */
    mergeMetrics(existing, current) {
        return {
            totalMessages: existing.totalMessages + current.totalMessages,
            userMessages: existing.userMessages + current.userMessages,
            botMessages: existing.botMessages + current.botMessages,
            totalConversations: Math.max(
                existing.totalConversations,
                current.totalConversations
            ),
            activeConversations: [
                ...new Set([
                    ...existing.activeConversations,
                    ...current.activeConversations
                ])
            ],
            avgResponseTime: (
                (existing.avgResponseTime * existing.botMessages +
                current.avgResponseTime * current.botMessages) /
                (existing.botMessages + current.botMessages)
            ) || 0,
            responseTimes: [
                ...(existing.responseTimes || []),
                ...(current.responseTimes || [])
            ],
            successCount: existing.successCount + current.successCount,
            errorCount: existing.errorCount + current.errorCount,
            apiCalls: {
                groq: existing.apiCalls.groq + current.apiCalls.groq,
                openai: existing.apiCalls.openai + current.apiCalls.openai,
                openrouter: existing.apiCalls.openrouter + current.apiCalls.openrouter,
                total: existing.apiCalls.total + current.apiCalls.total
            },
            tokensUsed: {
                groq: existing.tokensUsed.groq + current.tokensUsed.groq,
                openai: existing.tokensUsed.openai + current.tokensUsed.openai,
                openrouter: existing.tokensUsed.openrouter + current.tokensUsed.openrouter,
                total: existing.tokensUsed.total + current.tokensUsed.total
            },
            costs: {
                groq: existing.costs.groq + current.costs.groq,
                openai: existing.costs.openai + current.costs.openai,
                openrouter: existing.costs.openrouter + current.costs.openrouter,
                total: existing.costs.total + current.costs.total
            },
            leads: {
                captured: existing.leads.captured + current.leads.captured,
                emails: existing.leads.emails + current.leads.emails,
                phones: existing.leads.phones + current.leads.phones
            },
            satisfaction: {
                positive: existing.satisfaction.positive + current.satisfaction.positive,
                neutral: existing.satisfaction.neutral + current.satisfaction.neutral,
                negative: existing.satisfaction.negative + current.satisfaction.negative,
                total: existing.satisfaction.total + current.satisfaction.total
            },
            keywords: this.mergeMaps(existing.keywords, current.keywords),
            topQuestions: this.mergeMaps(existing.topQuestions, current.topQuestions),
            errorTypes: this.mergeMaps(existing.errorTypes, current.errorTypes)
        };
    }

    /**
     * Mesclar objetos (ex-Maps)
     */
    mergeMaps(obj1, obj2) {
        const merged = { ...obj1 };
        
        for (const [key, value] of Object.entries(obj2)) {
            merged[key] = (merged[key] || 0) + value;
        }
        
        return merged;
    }

    /**
     * Obter analytics de um chatbot
     */
    async getAnalytics(chatbotId, startDate, endDate) {
        const start = new Date(startDate);
        const end = new Date(endDate);
        const analytics = [];

        // Iterar sobre os dias
        for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
            const dateKey = d.toISOString().split('T')[0];
            const filename = `${chatbotId}_${dateKey}.json`;
            const filepath = path.join(this.dataPath, filename);

            if (fs.existsSync(filepath)) {
                try {
                    const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
                    analytics.push(data);
                } catch (error) {
                    console.error(`❌ Erro ao ler analytics de ${dateKey}:`, error);
                }
            }
        }

        return analytics;
    }

    /**
     * Obter resumo de analytics
     */
    async getSummary(chatbotId, days = 30) {
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - days);

        const analytics = await this.getAnalytics(
            chatbotId,
            startDate.toISOString().split('T')[0],
            endDate.toISOString().split('T')[0]
        );

        if (analytics.length === 0) {
            return this.initializeMetrics();
        }

        // Agregar todas as métricas
        let summary = this.initializeMetrics();
        
        for (const day of analytics) {
            summary = this.mergeMetrics(summary, day.metrics);
        }

        // Calcular médias e percentuais
        summary.avgMessagesPerDay = summary.totalMessages / days;
        summary.avgConversationsPerDay = summary.totalConversations / days;
        summary.successRate = summary.successCount / 
            (summary.successCount + summary.errorCount) * 100 || 0;
        
        if (summary.satisfaction.total > 0) {
            summary.satisfactionScore = (
                (summary.satisfaction.positive * 100 +
                summary.satisfaction.neutral * 50) /
                summary.satisfaction.total
            );
        } else {
            summary.satisfactionScore = 0;
        }

        // Top 10 perguntas
        summary.topQuestions = Object.entries(summary.topQuestions)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([question, count]) => ({ question, count }));

        // Top 10 keywords
        summary.topKeywords = Object.entries(summary.keywords)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([keyword, count]) => ({ keyword, count }));

        // Erros mais comuns
        summary.topErrors = Object.entries(summary.errorTypes)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([error, count]) => ({ error, count }));

        return summary;
    }

    /**
     * Exportar analytics para CSV
     */
    async exportToCSV(chatbotId, startDate, endDate) {
        const analytics = await this.getAnalytics(chatbotId, startDate, endDate);

        if (analytics.length === 0) {
            return null;
        }

        const headers = [
            'Data',
            'Total Mensagens',
            'Mensagens Usuário',
            'Mensagens Bot',
            'Conversas',
            'Tempo Resposta Médio (ms)',
            'Taxa Sucesso (%)',
            'Chamadas API',
            'Tokens Usados',
            'Custo Total (R$)',
            'Leads Capturados'
        ].join(',');

        const rows = analytics.map(day => {
            const m = day.metrics;
            const successRate = m.successCount / (m.successCount + m.errorCount) * 100 || 0;
            
            return [
                day.date,
                m.totalMessages,
                m.userMessages,
                m.botMessages,
                m.totalConversations,
                Math.round(m.avgResponseTime),
                successRate.toFixed(2),
                m.apiCalls.total,
                m.tokensUsed.total,
                m.costs.total.toFixed(2),
                m.leads.captured
            ].join(',');
        });

        return [headers, ...rows].join('\n');
    }

    /**
     * Limpar analytics antigos
     */
    async cleanOldAnalytics(daysToKeep = 90) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

        const files = fs.readdirSync(this.dataPath);
        let deletedCount = 0;

        for (const file of files) {
            if (!file.endsWith('.json')) continue;

            const match = file.match(/_(\d{4}-\d{2}-\d{2})\.json$/);
            if (match) {
                const fileDate = new Date(match[1]);
                
                if (fileDate < cutoffDate) {
                    fs.unlinkSync(path.join(this.dataPath, file));
                    deletedCount++;
                }
            }
        }

        console.log(`🧹 ${deletedCount} arquivo(s) de analytics antigos removidos`);
        return deletedCount;
    }
}

// Instância global do gerenciador de analytics
const analyticsManager = new AnalyticsManager();

module.exports = {
    analyticsManager
};
