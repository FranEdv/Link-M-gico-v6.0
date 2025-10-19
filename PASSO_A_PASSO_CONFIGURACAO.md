# 🎯 Link Mágico - Passo a Passo de Configuração

## 📋 Índice de Configurações

1. [Sistema de Banco de Dados](#1-sistema-de-banco-de-dados)
2. [Sistema de Cache](#2-sistema-de-cache)
3. [Sistema de Analytics](#3-sistema-de-analytics)
4. [Sistema de Webhooks](#4-sistema-de-webhooks)
5. [Sistema de Billing](#5-sistema-de-billing)
6. [Sistema de Knowledge Base](#6-sistema-de-knowledge-base)
7. [Sistema de Otimização LLM](#7-sistema-de-otimização-llm)
8. [Configuração Completa para Produção](#8-configuração-completa-para-produção)

---

## 1. Sistema de Banco de Dados

### 📊 O que faz:
- Armazena chatbots, conversas e analytics
- Suporta PostgreSQL (produção) e SQLite (desenvolvimento)
- Cache de extrações de URLs

### ⚙️ Configuração Desenvolvimento (SQLite):

```env
# .env
USE_POSTGRES=false
```

**Pronto!** O SQLite é criado automaticamente em `data/linkmagico.db`

### ⚙️ Configuração Produção (PostgreSQL):

#### Opção A: ElephantSQL (Gratuito)

1. Acesse https://www.elephantsql.com/
2. Crie conta e faça login
3. Clique em "Create New Instance"
4. Escolha plano "Tiny Turtle" (gratuito)
5. Dê um nome e escolha região
6. Copie a URL de conexão

```env
# .env
USE_POSTGRES=true
DATABASE_URL=postgres://usuario:senha@host/database
```

#### Opção B: Render PostgreSQL

1. No Render Dashboard, clique em "New +"
2. Selecione "PostgreSQL"
3. Escolha plano Free
4. Após criado, copie "Internal Database URL"

```env
# .env
USE_POSTGRES=true
DATABASE_URL=postgresql://...
```

### ✅ Testar:

```bash
# Iniciar servidor
npm start

# Criar um chatbot via API
curl -X POST http://localhost:3000/api/chatbots \
  -H "Content-Type: application/json" \
  -d '{"name": "Teste", "url": "https://example.com"}'

# Reiniciar servidor e verificar se o chatbot ainda existe
```

---

## 2. Sistema de Cache

### 📊 O que faz:
- Cache de extrações de URLs (24h)
- Cache de respostas comuns (1h)
- Rate limiting por API key
- Economia de 70% em scraping e 40% em LLM

### ⚙️ Configuração Desenvolvimento (In-Memory):

```env
# .env
USE_REDIS=false
```

**Pronto!** Cache funciona na memória do servidor.

### ⚙️ Configuração Produção (Redis):

#### Opção A: Redis Cloud (Gratuito)

1. Acesse https://redis.com/try-free/
2. Crie conta e faça login
3. Clique em "New Database"
4. Escolha plano gratuito (30MB)
5. Após criado, clique em "Configuration"
6. Copie "Public endpoint"

```env
# .env
USE_REDIS=true
REDIS_URL=redis://default:senha@host:port
```

#### Opção B: Upstash (Gratuito)

1. Acesse https://upstash.com/
2. Crie conta e faça login
3. Crie novo Redis database
4. Copie a URL de conexão

```env
# .env
USE_REDIS=true
REDIS_URL=redis://...
```

### ⚙️ Configurar Tempos de Cache:

```env
# .env
EXTRACTION_CACHE_TTL=24        # Horas para cache de extração
RESPONSE_CACHE_TTL=60          # Minutos para cache de respostas
MAX_CACHE_SIZE=1000            # Tamanho máximo do cache in-memory
```

### ✅ Testar:

```bash
# Extrair URL pela primeira vez (vai fazer scraping)
curl http://localhost:3000/api/extract?url=https://example.com

# Extrair mesma URL novamente (deve usar cache)
curl http://localhost:3000/api/extract?url=https://example.com

# Ver estatísticas do cache
curl http://localhost:3000/api/cache/stats
```

---

## 3. Sistema de Analytics

### 📊 O que faz:
- Rastreia todas as métricas de uso
- Exporta para CSV
- Calcula custos e ROI
- Limpeza automática de dados antigos

### ⚙️ Configuração:

```env
# .env
ANALYTICS_RETENTION_DAYS=90      # Manter dados por 90 dias
ANALYTICS_FLUSH_INTERVAL=60000   # Salvar a cada 60 segundos
```

**Pronto!** Analytics funciona automaticamente.

### 📊 Como Usar:

#### Obter Analytics de um Chatbot:

```bash
# Últimos 30 dias
curl http://localhost:3000/api/analytics/CHATBOT_ID?days=30

# Últimos 7 dias
curl http://localhost:3000/api/analytics/CHATBOT_ID?days=7
```

#### Exportar para CSV:

```bash
curl "http://localhost:3000/api/analytics/CHATBOT_ID/export?startDate=2024-01-01&endDate=2024-12-31" \
  -o analytics.csv
```

### ✅ Testar:

```bash
# Fazer algumas conversas com o chatbot
# Depois consultar analytics
curl http://localhost:3000/api/analytics/CHATBOT_ID?days=1
```

---

## 4. Sistema de Webhooks

### 📊 O que faz:
- Notifica sistemas externos sobre eventos
- 6 tipos de eventos disponíveis
- Retry automático em caso de falha
- Assinatura HMAC para segurança

### ⚙️ Configuração:

```env
# .env
ENABLE_WEBHOOKS=true
WEBHOOK_RETRY_ATTEMPTS=3
WEBHOOK_RETRY_DELAY=1000
```

### 📊 Como Usar:

#### 1. Registrar Webhook:

```bash
curl -X POST http://localhost:3000/api/webhooks/CHATBOT_ID \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "lead_captured",
    "url": "https://seu-sistema.com/webhook",
    "secret": "chave_secreta_opcional",
    "headers": {
      "Authorization": "Bearer seu_token"
    }
  }'
```

#### 2. Listar Webhooks:

```bash
curl http://localhost:3000/api/webhooks/CHATBOT_ID
```

#### 3. Testar Webhook:

```bash
curl -X POST http://localhost:3000/api/webhooks/CHATBOT_ID/WEBHOOK_ID/test
```

#### 4. Remover Webhook:

```bash
curl -X DELETE http://localhost:3000/api/webhooks/CHATBOT_ID/WEBHOOK_ID
```

### 📋 Eventos Disponíveis:

- `conversation_started` - Nova conversa iniciada
- `conversation_ended` - Conversa finalizada
- `lead_captured` - Lead capturado (email/telefone)
- `keyword_detected` - Palavra-chave detectada
- `message_sent` - Mensagem enviada pelo bot
- `message_received` - Mensagem recebida do usuário

### 🔒 Validar Assinatura HMAC:

No seu endpoint, valide a assinatura:

```javascript
const crypto = require('crypto');

function validateWebhook(payload, signature, secret) {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(JSON.stringify(payload));
    const expectedSignature = hmac.digest('hex');
    
    return signature === expectedSignature;
}
```

### ✅ Testar:

Use https://webhook.site/ para testar:

1. Acesse webhook.site e copie a URL
2. Registre webhook com essa URL
3. Faça uma conversa e capture um lead
4. Veja a requisição no webhook.site

---

## 5. Sistema de Billing

### 📊 O que faz:
- 4 planos (Free, Starter, Professional, Enterprise)
- Integração com Stripe
- Controle de limites e uso
- Checkout e assinaturas

### ⚙️ Configuração Stripe:

#### 1. Criar Conta Stripe:

1. Acesse https://stripe.com/
2. Crie uma conta
3. Vá em "Developers" > "API keys"

#### 2. Configurar Chaves (Modo Teste):

```env
# .env
STRIPE_SECRET_KEY=sk_test_sua_chave_secreta
STRIPE_PUBLISHABLE_KEY=pk_test_sua_chave_publica
```

#### 3. Configurar Webhook:

1. No Stripe, vá em "Developers" > "Webhooks"
2. Clique em "Add endpoint"
3. URL: `https://seu-dominio.com/api/webhooks/stripe`
4. Eventos: Selecione:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.paid`
   - `invoice.payment_failed`

5. Copie o "Signing secret":

```env
# .env
STRIPE_WEBHOOK_SECRET=whsec_sua_chave_webhook
```

### 📊 Como Usar:

#### 1. Listar Planos:

```bash
curl http://localhost:3000/api/plans
```

#### 2. Ver Assinatura de um Usuário:

```bash
curl http://localhost:3000/api/subscription/USER_ID
```

#### 3. Criar Sessão de Checkout:

```bash
curl -X POST http://localhost:3000/api/subscription/USER_ID/checkout \
  -H "Content-Type: application/json" \
  -d '{
    "planId": "professional",
    "successUrl": "https://seu-site.com/success",
    "cancelUrl": "https://seu-site.com/cancel"
  }'
```

Resposta:
```json
{
  "success": true,
  "sessionId": "cs_test_...",
  "url": "https://checkout.stripe.com/..."
}
```

Redirecione o usuário para a `url` retornada.

#### 4. Fazer Upgrade Manual:

```bash
curl -X POST http://localhost:3000/api/subscription/USER_ID/upgrade \
  -H "Content-Type: application/json" \
  -d '{"planId": "professional"}'
```

### 🔄 Modo Produção:

Quando estiver pronto para produção:

1. No Stripe, ative sua conta
2. Vá em "Developers" > "API keys"
3. Copie as chaves **live** (começam com `sk_live_` e `pk_live_`)
4. Atualize o .env:

```env
STRIPE_SECRET_KEY=sk_live_sua_chave_live
STRIPE_PUBLISHABLE_KEY=pk_live_sua_chave_live
```

5. Reconfigure o webhook com as chaves live

### ✅ Testar:

```bash
# 1. Listar planos
curl http://localhost:3000/api/plans

# 2. Criar checkout
curl -X POST http://localhost:3000/api/subscription/teste123/checkout \
  -H "Content-Type: application/json" \
  -d '{
    "planId": "starter",
    "successUrl": "http://localhost:3000/success",
    "cancelUrl": "http://localhost:3000/cancel"
  }'

# 3. Abrir a URL retornada no navegador
# 4. Usar cartão de teste: 4242 4242 4242 4242
# 5. Verificar assinatura
curl http://localhost:3000/api/subscription/teste123
```

---

## 6. Sistema de Knowledge Base

### 📊 O que faz:
- Múltiplas fontes de conhecimento
- FAQs estruturadas
- Documentos e textos
- Busca inteligente

### 📊 Como Usar:

#### 1. Adicionar FAQ Individual:

```bash
curl -X POST http://localhost:3000/api/knowledge/CHATBOT_ID/faq \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Qual o horário de funcionamento?",
    "answer": "Funcionamos de segunda a sexta, das 9h às 18h",
    "category": "atendimento"
  }'
```

#### 2. Adicionar Múltiplas FAQs:

```bash
curl -X POST http://localhost:3000/api/knowledge/CHATBOT_ID/faqs/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "faqs": [
      {
        "question": "Aceitam cartão?",
        "answer": "Sim, aceitamos todas as bandeiras",
        "category": "pagamento"
      },
      {
        "question": "Fazem entrega?",
        "answer": "Sim, entregamos em toda a cidade",
        "category": "entrega"
      },
      {
        "question": "Qual o prazo de entrega?",
        "answer": "O prazo é de 2 a 5 dias úteis",
        "category": "entrega"
      }
    ]
  }'
```

#### 3. Adicionar Documento:

```bash
curl -X POST http://localhost:3000/api/knowledge/CHATBOT_ID/document \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Política de Devolução",
    "content": "Você pode devolver produtos em até 7 dias...",
    "metadata": {
      "type": "policy",
      "version": "1.0"
    }
  }'
```

#### 4. Ver Base de Conhecimento:

```bash
curl http://localhost:3000/api/knowledge/CHATBOT_ID
```

#### 5. Ver Estatísticas:

```bash
curl http://localhost:3000/api/knowledge/CHATBOT_ID/stats
```

#### 6. Remover Entrada:

```bash
# Remover FAQ
curl -X DELETE http://localhost:3000/api/knowledge/CHATBOT_ID/faq/FAQ_ID

# Remover documento
curl -X DELETE http://localhost:3000/api/knowledge/CHATBOT_ID/document/DOC_ID
```

### 📋 Importar FAQs de CSV:

Crie um arquivo `faqs.csv`:

```csv
pergunta,resposta,categoria
"Qual o horário?","9h às 18h","atendimento"
"Aceitam cartão?","Sim, todas as bandeiras","pagamento"
"Fazem entrega?","Sim, toda a cidade","entrega"
```

Depois importe via código ou API.

### ✅ Testar:

```bash
# 1. Adicionar FAQs
curl -X POST http://localhost:3000/api/knowledge/CHATBOT_ID/faqs/bulk \
  -H "Content-Type: application/json" \
  -d '{"faqs": [{"question": "Teste?", "answer": "Resposta teste"}]}'

# 2. Ver estatísticas
curl http://localhost:3000/api/knowledge/CHATBOT_ID/stats

# 3. Fazer pergunta ao chatbot relacionada à FAQ
# 4. Verificar se o bot usa a informação da FAQ
```

---

## 7. Sistema de Otimização LLM

### 📊 O que faz:
- Cache de respostas similares
- Análise de complexidade de perguntas
- Recomendação de modelo adequado
- Economia de 40-60% nos custos

### ⚙️ Configuração:

```env
# .env
ENABLE_LLM_OPTIMIZATION=true
```

**Pronto!** Funciona automaticamente.

### 📊 Como Funciona:

1. **Perguntas Simples** (ex: "Oi", "Quanto custa?")
   - Usa modelo menor (llama3-8b)
   - Resposta mais rápida
   - Menor custo

2. **Perguntas Médias** (ex: "Como funciona o produto?")
   - Usa modelo padrão (llama3-70b)
   - Equilíbrio custo/qualidade

3. **Perguntas Complexas** (ex: "Explique a diferença entre...")
   - Usa modelo avançado
   - Máxima qualidade

4. **Cache de Similaridade**
   - Se pergunta é 85%+ similar a outra
   - Retorna resposta do cache
   - Custo zero

### 📊 Ver Estatísticas:

```bash
curl http://localhost:3000/api/llm/stats/CHATBOT_ID?days=30
```

Resposta:
```json
{
  "success": true,
  "usage": [...],
  "savings": {
    "totalCalls": 1000,
    "cacheHits": 400,
    "cacheHitRate": "40.0",
    "totalCost": "15.50",
    "estimatedCostWithoutCache": "25.80",
    "savings": "10.30",
    "savingsPercent": "39.9"
  },
  "cache": {
    "size": 250,
    "maxSize": 1000,
    "utilizationPercent": "25.0"
  }
}
```

### ✅ Testar:

```bash
# 1. Fazer várias perguntas ao chatbot
# 2. Fazer perguntas similares
# 3. Ver estatísticas
curl http://localhost:3000/api/llm/stats/CHATBOT_ID

# Você deve ver:
# - cacheHits > 0
# - savings > 0
# - savingsPercent > 0
```

---

## 8. Configuração Completa para Produção

### 📋 Checklist Completo:

#### 1. Variáveis de Ambiente:

```env
# ===== SERVIDOR =====
PORT=3000
NODE_ENV=production

# ===== APIs DE LLM =====
GROQ_API_KEY=sua_chave_groq
OPENAI_API_KEY=sua_chave_openai
OPENROUTER_API_KEY=sua_chave_openrouter

# ===== BANCO DE DADOS =====
USE_POSTGRES=true
DATABASE_URL=postgresql://usuario:senha@host/database

# ===== CACHE =====
USE_REDIS=true
REDIS_URL=redis://default:senha@host:port

# ===== PAGAMENTOS =====
STRIPE_SECRET_KEY=sk_live_sua_chave
STRIPE_PUBLISHABLE_KEY=pk_live_sua_chave
STRIPE_WEBHOOK_SECRET=whsec_sua_chave

# ===== SEGURANÇA =====
SESSION_SECRET=chave_aleatoria_minimo_32_caracteres
ALLOWED_ORIGINS=https://seu-dominio.com,https://app.seu-dominio.com

# ===== RATE LIMITING =====
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# ===== ANALYTICS =====
ANALYTICS_RETENTION_DAYS=90
ANALYTICS_FLUSH_INTERVAL=60000

# ===== CACHE =====
EXTRACTION_CACHE_TTL=24
RESPONSE_CACHE_TTL=60
MAX_CACHE_SIZE=1000

# ===== WEBHOOKS =====
WEBHOOK_RETRY_ATTEMPTS=3
WEBHOOK_RETRY_DELAY=1000

# ===== FEATURES =====
ENABLE_BILLING=true
ENABLE_WEBHOOKS=true
ENABLE_ADVANCED_ANALYTICS=true
ENABLE_LLM_OPTIMIZATION=true
```

#### 2. Deploy no Render:

1. **Preparar Repositório:**
```bash
git add .
git commit -m "Link Mágico Melhorado - Versão 2.0"
git push origin main
```

2. **Criar Web Service:**
   - Acesse https://dashboard.render.com/
   - New + > Web Service
   - Conecte seu repositório
   - Configure:
     - **Name:** linkmagico
     - **Environment:** Node
     - **Build Command:** `npm install`
     - **Start Command:** `npm start`
     - **Plan:** Free (ou Starter para produção)

3. **Adicionar Variáveis de Ambiente:**
   - Copie todas as variáveis do .env
   - Cole no Render em "Environment"

4. **Deploy:**
   - Clique em "Create Web Service"
   - Aguarde 5-10 minutos
   - Acesse a URL fornecida

#### 3. Configurar PostgreSQL no Render:

1. New + > PostgreSQL
2. Escolha plano Free
3. Após criado, copie "Internal Database URL"
4. No Web Service, adicione:
   - `USE_POSTGRES=true`
   - `DATABASE_URL=<URL copiada>`
5. Faça redeploy

#### 4. Configurar Redis:

1. Crie Redis no Redis Cloud ou Upstash
2. Copie URL de conexão
3. No Web Service, adicione:
   - `USE_REDIS=true`
   - `REDIS_URL=<URL copiada>`
4. Faça redeploy

#### 5. Configurar Stripe:

1. Ative sua conta Stripe
2. Copie chaves live
3. Configure webhook:
   - URL: `https://seu-app.onrender.com/api/webhooks/stripe`
   - Eventos: checkout, subscription, invoice
4. Copie signing secret
5. Atualize variáveis no Render

#### 6. Testar Tudo:

```bash
# Status geral
curl https://seu-app.onrender.com/api/system/status

# Criar chatbot
curl -X POST https://seu-app.onrender.com/api/chatbots \
  -H "Content-Type: application/json" \
  -d '{"name": "Teste Produção", "url": "https://example.com"}'

# Testar conversa
curl -X POST https://seu-app.onrender.com/api/chat \
  -H "Content-Type: application/json" \
  -d '{"chatbotId": "...", "message": "Olá"}'

# Ver analytics
curl https://seu-app.onrender.com/api/analytics/CHATBOT_ID

# Ver planos
curl https://seu-app.onrender.com/api/plans
```

---

## 🎉 Conclusão

Parabéns! Você configurou todos os sistemas:

- ✅ Banco de dados persistente
- ✅ Cache inteligente
- ✅ Analytics profissional
- ✅ Webhooks funcionando
- ✅ Billing com Stripe
- ✅ Knowledge Base
- ✅ Otimização LLM
- ✅ Deploy em produção

**Seu Link Mágico está pronto para escalar!** 🚀

---

**Versão:** 2.0.0  
**Data:** Outubro 2025  
**Suporte:** Ver GUIA_CONFIGURACAO.md para troubleshooting
