/**
 * 🚀 SISTEMA DE CACHE INTELIGENTE - Link Mágico
 * Suporta Redis (produção) e In-Memory (desenvolvimento)
 * 
 * Funcionalidades:
 * - Cache de dados extraídos (24h)
 * - Cache de respostas comuns (1h)
 * - Rate limiting por API Key
 * - Queue para processamento assíncrono
 */

const USE_REDIS = process.env.REDIS_URL || process.env.USE_REDIS === 'true';

let cacheClient;
let isRedisConnected = false;

/**
 * 🔌 Inicializar cliente de cache
 */
async function initializeCache() {
    if (USE_REDIS) {
        try {
            const redis = require('redis');
            
            cacheClient = redis.createClient({
                url: process.env.REDIS_URL,
                socket: {
                    reconnectStrategy: (retries) => {
                        if (retries > 10) {
                            console.error('❌ Redis: Máximo de tentativas atingido');
                            return new Error('Redis connection failed');
                        }
                        return Math.min(retries * 100, 3000);
                    }
                }
            });

            cacheClient.on('error', (err) => {
                console.error('❌ Redis Error:', err);
                isRedisConnected = false;
            });

            cacheClient.on('connect', () => {
                console.log('🔄 Redis conectando...');
            });

            cacheClient.on('ready', () => {
                console.log('✅ Redis conectado e pronto!');
                isRedisConnected = true;
            });

            await cacheClient.connect();
            
            return cacheClient;
        } catch (error) {
            console.error('❌ Erro ao conectar Redis, usando cache in-memory:', error.message);
            return initializeInMemoryCache();
        }
    } else {
        return initializeInMemoryCache();
    }
}

/**
 * 💾 Cache In-Memory (fallback)
 */
function initializeInMemoryCache() {
    console.log('✅ Cache In-Memory inicializado');
    
    const cache = new Map();
    const expirations = new Map();

    // Limpar cache expirado a cada minuto
    setInterval(() => {
        const now = Date.now();
        for (const [key, expireTime] of expirations.entries()) {
            if (expireTime < now) {
                cache.delete(key);
                expirations.delete(key);
            }
        }
    }, 60000);

    cacheClient = {
        async get(key) {
            const expireTime = expirations.get(key);
            if (expireTime && expireTime < Date.now()) {
                cache.delete(key);
                expirations.delete(key);
                return null;
            }
            return cache.get(key) || null;
        },

        async set(key, value, options = {}) {
            cache.set(key, value);
            if (options.EX) {
                expirations.set(key, Date.now() + options.EX * 1000);
            }
            return 'OK';
        },

        async setEx(key, seconds, value) {
            cache.set(key, value);
            expirations.set(key, Date.now() + seconds * 1000);
            return 'OK';
        },

        async del(key) {
            cache.delete(key);
            expirations.delete(key);
            return 1;
        },

        async exists(key) {
            return cache.has(key) ? 1 : 0;
        },

        async incr(key) {
            const current = parseInt(cache.get(key) || '0');
            const newValue = current + 1;
            cache.set(key, newValue.toString());
            return newValue;
        },

        async expire(key, seconds) {
            if (cache.has(key)) {
                expirations.set(key, Date.now() + seconds * 1000);
                return 1;
            }
            return 0;
        },

        async ttl(key) {
            const expireTime = expirations.get(key);
            if (!expireTime) return -1;
            const remaining = Math.floor((expireTime - Date.now()) / 1000);
            return remaining > 0 ? remaining : -2;
        },

        async keys(pattern) {
            const regex = new RegExp(pattern.replace('*', '.*'));
            return Array.from(cache.keys()).filter(key => regex.test(key));
        },

        async flushAll() {
            cache.clear();
            expirations.clear();
            return 'OK';
        }
    };

    isRedisConnected = false;
    return cacheClient;
}

/**
 * 🎯 Funções de Cache Inteligente
 */
const CacheManager = {
    /**
     * Cache de extração de dados (24 horas)
     */
    async cacheExtraction(url, data) {
        const key = `extraction:${url}`;
        try {
            await cacheClient.setEx(key, 24 * 60 * 60, JSON.stringify(data));
            console.log('✅ Extração cacheada:', url);
        } catch (error) {
            console.error('❌ Erro ao cachear extração:', error);
        }
    },

    async getExtractionCache(url) {
        const key = `extraction:${url}`;
        try {
            const cached = await cacheClient.get(key);
            if (cached) {
                console.log('✅ Cache HIT - Extração:', url);
                return JSON.parse(cached);
            }
            console.log('❌ Cache MISS - Extração:', url);
            return null;
        } catch (error) {
            console.error('❌ Erro ao buscar cache:', error);
            return null;
        }
    },

    /**
     * Cache de respostas comuns (1 hora)
     */
    async cacheResponse(chatbotId, question, response) {
        const crypto = require('crypto');
        const questionHash = crypto.createHash('md5').update(question.toLowerCase()).digest('hex');
        const key = `response:${chatbotId}:${questionHash}`;
        
        try {
            await cacheClient.setEx(key, 60 * 60, JSON.stringify(response));
            console.log('✅ Resposta cacheada');
        } catch (error) {
            console.error('❌ Erro ao cachear resposta:', error);
        }
    },

    async getResponseCache(chatbotId, question) {
        const crypto = require('crypto');
        const questionHash = crypto.createHash('md5').update(question.toLowerCase()).digest('hex');
        const key = `response:${chatbotId}:${questionHash}`;
        
        try {
            const cached = await cacheClient.get(key);
            if (cached) {
                console.log('✅ Cache HIT - Resposta');
                return JSON.parse(cached);
            }
            return null;
        } catch (error) {
            console.error('❌ Erro ao buscar cache de resposta:', error);
            return null;
        }
    },

    /**
     * Rate Limiting por API Key
     */
    async checkRateLimit(apiKey, maxRequests = 100, windowSeconds = 60) {
        const key = `ratelimit:${apiKey}`;
        
        try {
            const current = await cacheClient.incr(key);
            
            if (current === 1) {
                await cacheClient.expire(key, windowSeconds);
            }

            if (current > maxRequests) {
                const ttl = await cacheClient.ttl(key);
                console.log(`⚠️ Rate limit excedido para ${apiKey}`);
                return {
                    allowed: false,
                    remaining: 0,
                    resetIn: ttl
                };
            }

            return {
                allowed: true,
                remaining: maxRequests - current,
                resetIn: await cacheClient.ttl(key)
            };
        } catch (error) {
            console.error('❌ Erro no rate limiting:', error);
            // Em caso de erro, permitir a requisição
            return { allowed: true, remaining: maxRequests, resetIn: windowSeconds };
        }
    },

    /**
     * Armazenar sessão de conversa
     */
    async saveConversationSession(sessionId, messages, ttl = 3600) {
        const key = `session:${sessionId}`;
        try {
            await cacheClient.setEx(key, ttl, JSON.stringify(messages));
        } catch (error) {
            console.error('❌ Erro ao salvar sessão:', error);
        }
    },

    async getConversationSession(sessionId) {
        const key = `session:${sessionId}`;
        try {
            const cached = await cacheClient.get(key);
            return cached ? JSON.parse(cached) : [];
        } catch (error) {
            console.error('❌ Erro ao buscar sessão:', error);
            return [];
        }
    },

    /**
     * Estatísticas de cache
     */
    async getCacheStats() {
        try {
            const extractionKeys = await cacheClient.keys('extraction:*');
            const responseKeys = await cacheClient.keys('response:*');
            const sessionKeys = await cacheClient.keys('session:*');

            return {
                extractions: extractionKeys.length,
                responses: responseKeys.length,
                sessions: sessionKeys.length,
                total: extractionKeys.length + responseKeys.length + sessionKeys.length,
                redisConnected: isRedisConnected
            };
        } catch (error) {
            console.error('❌ Erro ao obter stats:', error);
            return { error: error.message };
        }
    },

    /**
     * Limpar todo o cache
     */
    async clearAllCache() {
        try {
            await cacheClient.flushAll();
            console.log('🧹 Cache limpo completamente');
            return true;
        } catch (error) {
            console.error('❌ Erro ao limpar cache:', error);
            return false;
        }
    },

    /**
     * Limpar cache específico
     */
    async clearCacheByPattern(pattern) {
        try {
            const keys = await cacheClient.keys(pattern);
            if (keys.length > 0) {
                for (const key of keys) {
                    await cacheClient.del(key);
                }
                console.log(`🧹 ${keys.length} chaves removidas do cache`);
            }
            return keys.length;
        } catch (error) {
            console.error('❌ Erro ao limpar cache por padrão:', error);
            return 0;
        }
    }
};

/**
 * 📊 Middleware de Rate Limiting para Express
 */
function rateLimitMiddleware(options = {}) {
    const {
        maxRequests = 100,
        windowSeconds = 60,
        keyGenerator = (req) => req.headers['x-api-key'] || req.ip
    } = options;

    return async (req, res, next) => {
        const key = keyGenerator(req);
        const result = await CacheManager.checkRateLimit(key, maxRequests, windowSeconds);

        res.setHeader('X-RateLimit-Limit', maxRequests);
        res.setHeader('X-RateLimit-Remaining', result.remaining);
        res.setHeader('X-RateLimit-Reset', result.resetIn);

        if (!result.allowed) {
            return res.status(429).json({
                error: 'Rate limit exceeded',
                message: `Limite de ${maxRequests} requisições por ${windowSeconds}s excedido`,
                retryAfter: result.resetIn
            });
        }

        next();
    };
}

module.exports = {
    initializeCache,
    CacheManager,
    rateLimitMiddleware,
    getCacheClient: () => cacheClient,
    isRedisConnected: () => isRedisConnected
};
