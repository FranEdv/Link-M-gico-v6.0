#!/usr/bin/env python3
"""
Script para integrar as melhorias no server.js mantendo toda funcionalidade existente
"""

import re

print("🔧 Integrando melhorias no server.js...")

# Ler server original
with open('server.js.original', 'r', encoding='utf-8') as f:
    original = f.read()

# Encontrar a linha do dotenv
dotenv_match = re.search(r'require\("dotenv"\)\.config\(\);', original)
if not dotenv_match:
    print("❌ Não foi possível encontrar require('dotenv').config()")
    exit(1)

dotenv_pos = dotenv_match.end()

# Parte antes do dotenv
before_dotenv = original[:dotenv_pos]

# Parte depois do dotenv
after_dotenv = original[dotenv_pos:]

# Imports dos novos módulos
new_imports = '''

// ===== NOVOS MÓDULOS - MELHORIAS IMPLEMENTADAS =====
const { db, initializeDatabase, DatabaseHelpers, USE_POSTGRES } = require('./database');
const { initializeCache, CacheManager, rateLimitMiddleware, isRedisConnected } = require('./cache');
const { webhookManager, WebhookEvents } = require('./webhooks');
const { billingManager, PLANS } = require('./billing');
const { analyticsManager } = require('./analytics');
const { llmOptimizer } = require('./llm-optimizer');
const { knowledgeBaseManager } = require('./knowledge-base');
const { setupRoutes } = require('./routes');
const { initialize } = require('./init');

console.log('✅ Módulos de melhorias carregados');
'''

# Encontrar onde está app.listen
listen_match = re.search(r'app\.listen\(PORT.*?\);', after_dotenv, re.DOTALL)
if not listen_match:
    listen_match = re.search(r'const PORT.*?app\.listen.*?\);', after_dotenv, re.DOTALL)

if listen_match:
    before_listen = after_dotenv[:listen_match.start()]
    listen_code = after_dotenv[listen_match.start():listen_match.end()]
    after_listen = after_dotenv[listen_match.end():]
    
    # Adicionar inicialização e novas rotas antes do listen
    init_code = '''

// ===== CONFIGURAR NOVAS ROTAS =====
setupRoutes(app);

// ===== INICIALIZAR SISTEMAS =====
(async () => {
    await initialize();
    
    // Iniciar servidor
    '''
    
    # Fechar a função async
    close_async = '''
    
    console.log(`🌐 Servidor rodando em http://localhost:${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/api/system/status`);
})();
'''
    
    # Montar o novo server.js
    new_server = (
        before_dotenv +
        new_imports +
        before_listen +
        init_code +
        listen_code +
        close_async +
        after_listen
    )
else:
    # Se não encontrar app.listen, apenas adicionar os imports
    new_server = before_dotenv + new_imports + after_dotenv

# Salvar novo server.js
with open('server-melhorado.js', 'w', encoding='utf-8') as f:
    f.write(new_server)

print(f"✅ server-melhorado.js criado com sucesso!")
print(f"📝 Total de linhas: {len(new_server.splitlines())}")
print(f"📦 Tamanho: {len(new_server)} bytes")
