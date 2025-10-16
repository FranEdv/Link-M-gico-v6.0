/**
 * 🎯 SISTEMA DE OTIMIZAÇÃO DE CUSTOS LLM - Link Mágico
 * Gerencia chamadas de API para minimizar custos
 * 
 * Estratégias:
 * - Cache de respostas similares
 * - Fallback inteligente entre provedores
 * - Modelos menores para perguntas simples
 * - Monitoramento de tokens
 */

const crypto = require('crypto');

/**
 * 💰 Tabela de custos por provedor (por 1M tokens)
 */
const PRICING = {
    groq: {
        input: 0.00, // Gratuito atualmente
        output: 0.00
    },
    openai: {
        'gpt-4': {
            input: 30.00,
            output: 60.00
        },
        'gpt-4-turbo': {
            input: 10.00,
            output: 30.00
        },
        'gpt-3.5-turbo': {
            input: 0.50,
            output: 1.50
        }
    },
    openrouter: {
        'anthropic/claude-3': {
            input: 3.00,
            output: 15.00
        },
        'meta-llama/llama-3': {
            input: 0.18,
            output: 0.18
        }
    }
};

/**
 * 🧠 Classificador de complexidade de perguntas
 */
class QuestionComplexityAnalyzer {
    constructor() {
        this.simplePatterns = [
            /^(oi|olá|ola|hey|hi|hello)/i,
            /^(tchau|adeus|até|bye|goodbye)/i,
            /^(obrigad|thank)/i,
            /^(sim|não|nao|yes|no)$/i,
            /^(quanto custa|preço|valor|price)/i,
            /^(horário|hora|quando|when)/i,
            /^(onde|where|endereço|endereco)/i,
            /^(como|how)/i
        ];

        this.complexPatterns = [
            /porque|por que|why/i,
            /explicar|explain|detalhar/i,
            /diferença|comparar|compare/i,
            /análise|analise|analysis/i,
            /estratégia|estrategia|strategy/i
        ];
    }

    /**
     * Analisar complexidade da pergunta
     */
    analyze(question) {
        const length = question.length;
        const words = question.split(/\s+/).length;

        // Perguntas muito curtas são simples
        if (length < 20 || words < 5) {
            return 'simple';
        }

        // Verificar padrões simples
        for (const pattern of this.simplePatterns) {
            if (pattern.test(question)) {
                return 'simple';
            }
        }

        // Verificar padrões complexos
        for (const pattern of this.complexPatterns) {
            if (pattern.test(question)) {
                return 'complex';
            }
        }

        // Perguntas médias
        if (length < 100 && words < 20) {
            return 'medium';
        }

        return 'complex';
    }

    /**
     * Recomendar modelo baseado na complexidade
     */
    recommendModel(complexity) {
        switch (complexity) {
            case 'simple':
                return {
                    provider: 'groq',
                    model: 'llama3-8b-8192',
                    maxTokens: 150
                };
            
            case 'medium':
                return {
                    provider: 'groq',
                    model: 'llama3-70b-8192',
                    maxTokens: 300
                };
            
            case 'complex':
                return {
                    provider: 'groq',
                    model: 'llama3-70b-8192',
                    maxTokens: 500
                };
            
            default:
                return {
                    provider: 'groq',
                    model: 'llama3-70b-8192',
                    maxTokens: 300
                };
        }
    }
}

/**
 * 💾 Sistema de cache de respostas similares
 */
class ResponseCache {
    constructor() {
        this.cache = new Map();
        this.maxCacheSize = 1000;
        this.similarityThreshold = 0.85;
    }

    /**
     * Gerar hash da pergunta
     */
    generateHash(question) {
        const normalized = question.toLowerCase().trim();
        return crypto.createHash('md5').update(normalized).digest('hex');
    }

    /**
     * Calcular similaridade entre strings (Levenshtein simplificado)
     */
    calculateSimilarity(str1, str2) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        
        if (longer.length === 0) return 1.0;
        
        const editDistance = this.levenshteinDistance(longer, shorter);
        return (longer.length - editDistance) / longer.length;
    }

    /**
     * Distância de Levenshtein
     */
    levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    /**
     * Buscar resposta similar no cache
     */
    findSimilar(question, chatbotId) {
        const normalizedQuestion = question.toLowerCase().trim();
        
        // Busca exata primeiro
        const exactHash = this.generateHash(question);
        const exactMatch = this.cache.get(`${chatbotId}:${exactHash}`);
        
        if (exactMatch) {
            console.log('✅ Cache HIT (exato)');
            return exactMatch.response;
        }

        // Busca por similaridade
        for (const [key, value] of this.cache.entries()) {
            if (!key.startsWith(`${chatbotId}:`)) continue;
            
            const similarity = this.calculateSimilarity(
                normalizedQuestion,
                value.question.toLowerCase().trim()
            );

            if (similarity >= this.similarityThreshold) {
                console.log(`✅ Cache HIT (similaridade: ${(similarity * 100).toFixed(1)}%)`);
                return value.response;
            }
        }

        console.log('❌ Cache MISS');
        return null;
    }

    /**
     * Adicionar resposta ao cache
     */
    set(chatbotId, question, response, metadata = {}) {
        const hash = this.generateHash(question);
        const key = `${chatbotId}:${hash}`;

        // Limpar cache se exceder tamanho máximo
        if (this.cache.size >= this.maxCacheSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, {
            question,
            response,
            metadata,
            timestamp: Date.now(),
            hits: 0
        });
    }

    /**
     * Obter estatísticas do cache
     */
    getStats() {
        return {
            size: this.cache.size,
            maxSize: this.maxCacheSize,
            utilizationPercent: (this.cache.size / this.maxCacheSize * 100).toFixed(1)
        };
    }

    /**
     * Limpar cache
     */
    clear() {
        this.cache.clear();
    }
}

/**
 * 🎯 Gerenciador de otimização de LLM
 */
class LLMOptimizer {
    constructor() {
        this.complexityAnalyzer = new QuestionComplexityAnalyzer();
        this.responseCache = new ResponseCache();
        this.usageStats = new Map();
        
        console.log('🎯 Sistema de Otimização LLM inicializado');
    }

    /**
     * Otimizar chamada de LLM
     */
    async optimizeCall(chatbotId, question, context = {}) {
        // 1. Verificar cache primeiro
        const cachedResponse = this.responseCache.findSimilar(question, chatbotId);
        
        if (cachedResponse) {
            this.trackUsage(chatbotId, 'cache', 0, 0);
            return {
                response: cachedResponse,
                source: 'cache',
                cost: 0,
                tokens: 0
            };
        }

        // 2. Analisar complexidade
        const complexity = this.complexityAnalyzer.analyze(question);
        const recommendation = this.complexityAnalyzer.recommendModel(complexity);

        console.log(`📊 Complexidade: ${complexity} | Modelo: ${recommendation.model}`);

        return {
            recommendation,
            complexity,
            shouldCache: complexity === 'simple' || complexity === 'medium'
        };
    }

    /**
     * Calcular custo da chamada
     */
    calculateCost(provider, model, inputTokens, outputTokens) {
        let pricing = PRICING[provider];
        
        if (!pricing) {
            return 0;
        }

        // Para OpenAI e OpenRouter, buscar pricing do modelo específico
        if (typeof pricing === 'object' && !pricing.input) {
            pricing = pricing[model] || { input: 0, output: 0 };
        }

        const inputCost = (inputTokens / 1000000) * pricing.input;
        const outputCost = (outputTokens / 1000000) * pricing.output;

        return inputCost + outputCost;
    }

    /**
     * Rastrear uso
     */
    trackUsage(chatbotId, provider, inputTokens, outputTokens, model = null) {
        const key = `${chatbotId}:${this.getTodayKey()}`;
        
        if (!this.usageStats.has(key)) {
            this.usageStats.set(key, {
                chatbotId,
                date: new Date().toISOString().split('T')[0],
                providers: {},
                totalCalls: 0,
                totalTokens: 0,
                totalCost: 0,
                cacheHits: 0
            });
        }

        const stats = this.usageStats.get(key);
        
        if (provider === 'cache') {
            stats.cacheHits++;
        } else {
            if (!stats.providers[provider]) {
                stats.providers[provider] = {
                    calls: 0,
                    inputTokens: 0,
                    outputTokens: 0,
                    cost: 0
                };
            }

            const providerStats = stats.providers[provider];
            providerStats.calls++;
            providerStats.inputTokens += inputTokens;
            providerStats.outputTokens += outputTokens;

            const cost = this.calculateCost(provider, model, inputTokens, outputTokens);
            providerStats.cost += cost;

            stats.totalCalls++;
            stats.totalTokens += inputTokens + outputTokens;
            stats.totalCost += cost;
        }
    }

    /**
     * Obter chave do dia
     */
    getTodayKey() {
        return new Date().toISOString().split('T')[0];
    }

    /**
     * Obter estatísticas de uso
     */
    getUsageStats(chatbotId, days = 30) {
        const stats = [];
        
        for (const [key, value] of this.usageStats.entries()) {
            if (key.startsWith(`${chatbotId}:`)) {
                stats.push(value);
            }
        }

        // Ordenar por data
        stats.sort((a, b) => new Date(b.date) - new Date(a.date));

        // Limitar aos últimos N dias
        return stats.slice(0, days);
    }

    /**
     * Obter resumo de economia
     */
    getSavingsSummary(chatbotId) {
        const stats = this.getUsageStats(chatbotId);
        
        let totalCalls = 0;
        let cacheHits = 0;
        let totalCost = 0;

        for (const day of stats) {
            totalCalls += day.totalCalls;
            cacheHits += day.cacheHits;
            totalCost += day.totalCost;
        }

        // Estimar custo sem cache (assumindo custo médio por chamada)
        const avgCostPerCall = totalCalls > 0 ? totalCost / totalCalls : 0;
        const estimatedCostWithoutCache = (totalCalls + cacheHits) * avgCostPerCall;
        const savings = estimatedCostWithoutCache - totalCost;
        const savingsPercent = estimatedCostWithoutCache > 0 
            ? (savings / estimatedCostWithoutCache * 100) 
            : 0;

        return {
            totalCalls: totalCalls + cacheHits,
            cacheHits,
            cacheHitRate: totalCalls + cacheHits > 0 
                ? (cacheHits / (totalCalls + cacheHits) * 100).toFixed(1)
                : 0,
            totalCost: totalCost.toFixed(2),
            estimatedCostWithoutCache: estimatedCostWithoutCache.toFixed(2),
            savings: savings.toFixed(2),
            savingsPercent: savingsPercent.toFixed(1)
        };
    }

    /**
     * Adicionar resposta ao cache
     */
    cacheResponse(chatbotId, question, response, metadata = {}) {
        this.responseCache.set(chatbotId, question, response, metadata);
    }

    /**
     * Obter estatísticas do cache
     */
    getCacheStats() {
        return this.responseCache.getStats();
    }
}

// Instância global do otimizador
const llmOptimizer = new LLMOptimizer();

module.exports = {
    llmOptimizer,
    QuestionComplexityAnalyzer,
    ResponseCache
};
