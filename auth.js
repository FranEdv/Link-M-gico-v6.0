// auth.js - Middleware de autenticação para LinkMágico v6.0
const crypto = require('crypto');

// Simulação de banco de dados de API keys (em produção, usar banco real)
const API_KEYS = new Map([
    // Formato: [hash_da_key, { cliente, status, criado, usado }]
    ['a1b2c3d4e5f6g7h8i9j0', { 
        cliente: 'Cliente Demo', 
        status: 'ativo', 
        criado: '2024-01-01', 
        ultimoUso: null,
        usos: 0,
        limite: 1000 // limite de usos mensais
    }],
    ['demo123456789abcdef', { 
        cliente: 'Demo User', 
        status: 'ativo', 
        criado: '2024-01-01', 
        ultimoUso: null,
        usos: 0,
        limite: 500
    }]
]);

// Cache de keys válidas (evita consulta constante)
const keyCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutos

/**
 * Gera uma nova API key
 */
function generateAPIKey() {
    return crypto.randomBytes(16).toString('hex');
}

/**
 * Valida formato da API key
 */
function isValidKeyFormat(key) {
    return typeof key === 'string' && 
           key.length >= 16 && 
           key.length <= 64 && 
           /^[a-zA-Z0-9]+$/.test(key);
}

/**
 * Verifica se a API key é válida
 */
function validateAPIKey(apiKey) {
    if (!apiKey || !isValidKeyFormat(apiKey)) {
        return { valid: false, reason: 'Formato de chave inválido' };
    }

    // Verifica cache primeiro
    const cached = keyCache.get(apiKey);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
        return { valid: true, cliente: cached.cliente };
    }

    // Verifica na "base de dados"
    const keyData = API_KEYS.get(apiKey);
    if (!keyData) {
        return { valid: false, reason: 'Chave não encontrada' };
    }

    if (keyData.status !== 'ativo') {
        return { valid: false, reason: 'Chave inativa' };
    }

    // Atualiza cache
    keyCache.set(apiKey, {
        cliente: keyData.cliente,
        timestamp: Date.now()
    });

    // Atualiza estatísticas de uso
    keyData.ultimoUso = new Date().toISOString();
    keyData.usos += 1;

    return { 
        valid: true, 
        cliente: keyData.cliente,
        usos: keyData.usos,
        limite: keyData.limite 
    };
}

/**
 * Middleware de autenticação
 */
function authMiddleware(req, res, next) {
    // Rotas que não precisam de autenticação
    const publicRoutes = [
        '/',
        '/health',
        '/privacy.html',
        '/excluir-dados',
        '/privacy-policy',
        '/delete-data',
        '/data-deletion'
    ];

    // Arquivos estáticos públicos
    const publicAssets = [
        '.css', '.js', '.ico', '.png', '.jpg', '.jpeg', '.gif', '.svg'
    ];

    const path = req.path;
    
    // Verifica se é rota pública
    if (publicRoutes.includes(path) || path.startsWith('/api/log-consent') || path.startsWith('/api/data-deletion')) {
        return next();
    }

    // Verifica se é arquivo estático público
    if (publicAssets.some(ext => path.endsWith(ext))) {
        return next();
    }

    // Extrai API key do header, query param ou body
    let apiKey = req.headers['x-api-key'] || 
                 req.headers['authorization']?.replace('Bearer ', '') ||
                 req.query.api_key ||
                 req.body?.api_key;

    // Para o widget, pode vir como parâmetro na URL
    if (!apiKey && path === '/widget.js') {
        apiKey = req.query.key;
    }

    if (!apiKey) {
        return res.status(401).json({
            success: false,
            error: 'API key obrigatória',
            message: 'Forneça sua chave de acesso via header X-API-Key, Authorization Bearer, ou parâmetro api_key',
            help: 'Adquira sua licença em: https://link-magico.com/pricing'
        });
    }

    // Valida a API key
    const validation = validateAPIKey(apiKey);
    
    if (!validation.valid) {
        return res.status(403).json({
            success: false,
            error: 'Chave de acesso inválida',
            reason: validation.reason,
            message: 'Verifique sua chave de acesso ou renove sua licença',
            help: 'Suporte: https://link-magico.com/suporte'
        });
    }

    // Adiciona informações do cliente ao request
    req.cliente = {
        nome: validation.cliente,
        apiKey: apiKey,
        usos: validation.usos,
        limite: validation.limite
    };

    // Log de uso (opcional)
    if (process.env.NODE_ENV !== 'production') {
        console.log(`✅ Acesso autorizado: ${validation.cliente} (${path})`);
    }

    next();
}

/**
 * Middleware para páginas HTML protegidas
 */
function htmlAuthMiddleware(req, res, next) {
    const protectedPages = ['/chat.html', '/chatbot'];
    
    if (!protectedPages.some(page => req.path.startsWith(page))) {
        return next();
    }

    // Verifica API key na URL
    const apiKey = req.query.api_key || req.query.key;
    
    if (!apiKey) {
        return res.status(401).send(generateUnauthorizedPage());
    }

    const validation = validateAPIKey(apiKey);
    
    if (!validation.valid) {
        return res.status(403).send(generateForbiddenPage(validation.reason));
    }

    req.cliente = {
        nome: validation.cliente,
        apiKey: apiKey
    };

    next();
}

/**
 * Página de erro não autorizado
 */
function generateUnauthorizedPage() {
    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acesso Restrito - LinkMágico</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; color: white; }
        .container { text-align: center; background: rgba(255,255,255,0.1); padding: 3rem; border-radius: 20px; backdrop-filter: blur(20px); max-width: 500px; }
        h1 { font-size: 2.5rem; margin-bottom: 1rem; }
        p { font-size: 1.1rem; margin-bottom: 2rem; opacity: 0.9; }
        .cta { background: #10b981; color: white; padding: 1rem 2rem; border: none; border-radius: 10px; font-size: 1rem; font-weight: 600; text-decoration: none; display: inline-block; transition: all 0.3s ease; }
        .cta:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(16, 185, 129, 0.4); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Acesso Restrito</h1>
        <p>Esta ferramenta requer uma licença válida do LinkMágico para funcionar.</p>
        <p>Forneça sua chave de acesso como parâmetro: <code>?api_key=SUA_CHAVE</code></p>
        <a href="https://link-magico.com/pricing" class="cta">Adquirir Licença</a>
    </div>
</body>
</html>`;
}

/**
 * Página de erro proibido
 */
function generateForbiddenPage(reason) {
    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acesso Negado - LinkMágico</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; color: white; }
        .container { text-align: center; background: rgba(255,255,255,0.1); padding: 3rem; border-radius: 20px; backdrop-filter: blur(20px); max-width: 500px; }
        h1 { font-size: 2.5rem; margin-bottom: 1rem; }
        p { font-size: 1.1rem; margin-bottom: 1rem; opacity: 0.9; }
        .reason { background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 10px; margin: 1.5rem 0; font-family: monospace; }
        .cta { background: #f59e0b; color: white; padding: 1rem 2rem; border: none; border-radius: 10px; font-size: 1rem; font-weight: 600; text-decoration: none; display: inline-block; transition: all 0.3s ease; }
        .cta:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(245, 158, 11, 0.4); }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Chave Inválida</h1>
        <p>Sua chave de acesso não é válida ou está inativa.</p>
        <div class="reason">Motivo: ${reason}</div>
        <p>Entre em contato com o suporte para resolver este problema.</p>
        <a href="https://link-magico.com/suporte" class="cta">Falar com Suporte</a>
    </div>
</body>
</html>`;
}

/**
 * Rota para validar API key (opcional)
 */
function createValidationRoute(app) {
    app.get('/api/validate-key', authMiddleware, (req, res) => {
        res.json({
            success: true,
            valid: true,
            cliente: req.cliente.nome,
            usos: req.cliente.usos,
            limite: req.cliente.limite,
            message: 'Chave válida e ativa'
        });
    });
}

/**
 * Adiciona chave à base de dados (função administrativa)
 */
function addAPIKey(cliente, limite = 1000) {
    const apiKey = generateAPIKey();
    API_KEYS.set(apiKey, {
        cliente: cliente,
        status: 'ativo',
        criado: new Date().toISOString(),
        ultimoUso: null,
        usos: 0,
        limite: limite
    });
    return apiKey;
}

/**
 * Remove chave da base de dados
 */
function removeAPIKey(apiKey) {
    const removed = API_KEYS.delete(apiKey);
    keyCache.delete(apiKey);
    return removed;
}

/**
 * Lista todas as chaves (função administrativa)
 */
function listAPIKeys() {
    const keys = [];
    for (const [key, data] of API_KEYS.entries()) {
        keys.push({
            key: key.substring(0, 8) + '...',
            cliente: data.cliente,
            status: data.status,
            criado: data.criado,
            usos: data.usos,
            limite: data.limite
        });
    }
    return keys;
}

module.exports = {
    authMiddleware,
    htmlAuthMiddleware,
    createValidationRoute,
    generateAPIKey,
    addAPIKey,
    removeAPIKey,
    listAPIKeys,
    validateAPIKey
};
