# Documentação de Segurança e Configuração para LinkMágico v7.0 no Render

Este documento detalha as melhorias de segurança implementadas na plataforma LinkMágico v7.0 e fornece instruções passo a passo para configurar as variáveis de ambiente e ajustes necessários no ambiente de hospedagem Render. O objetivo é proteger a aplicação contra ataques cibernéticos, como SQL Injection, exposição de chaves de API e vulnerabilidades de Cross-Site Scripting (XSS).

## 1. Correção de Vulnerabilidade de SQL Injection (`database.js`)

### 1.1. Vulnerabilidade Original

Foi identificada uma vulnerabilidade de SQL Injection na função `getChatbotAnalytics` no arquivo `database.js`. A construção da query para PostgreSQL e SQLite utilizava a variável `days` diretamente na string da consulta (`INTERVAL '${days} days'` e `date('now', '-${days} days')`) sem validação rigorosa. Isso permitia que um atacante injetasse código SQL malicioso ao manipular o valor de `days`.

### 1.2. Solução Implementada

A correção envolveu a validação rigorosa da variável `days` para garantir que seja um número inteiro e a utilização de consultas parametrizadas, onde o valor de `days` é passado como um parâmetro seguro para a query. Isso impede a injeção de código SQL, pois o banco de dados trata o valor como um dado, e não como parte da instrução SQL.

**Exemplo da correção (trecho de `database.js`):**

```javascript
// Antes (vulnerável):
// const query = `SELECT ... WHERE timestamp >= NOW() - INTERVAL '${days} days'`;

// Depois (seguro):
// const daysInt = parseInt(days); // Validação
// if (isNaN(daysInt)) throw new Error('Invalid days parameter');
// const query = `SELECT ... WHERE timestamp >= NOW() - INTERVAL '$1 days'`;
// const params = [daysInt];
// await client.query(query, params);
```

### 1.3. Configuração no Render

Esta correção é uma alteração no código-fonte e **não requer nenhuma configuração específica de variável de ambiente** no Render. Basta garantir que o código atualizado seja implantado.

## 2. Tratamento Seguro de Chaves de API

### 2.1. Vulnerabilidades Originais

Foram identificadas as seguintes vulnerabilidades relacionadas ao tratamento de chaves de API:

*   **Chave de API Hardcoded:** A chave de API `linkmagico-api-key-2024` estava hardcoded no arquivo `public/index_app.html`, expondo-a diretamente no lado do cliente. Isso permitia que qualquer pessoa inspecionasse o código-fonte e obtivesse acesso irrestrito às funcionalidades administrativas.
*   **Exposição de API Key em URL/Body:** O middleware `requireApiKey` no `server.js` permitia que a chave de API fosse passada via parâmetros de URL (`req.query.apiKey`) ou corpo da requisição (`req.body.apiKey`). Chaves em URLs são facilmente logadas e expostas em históricos de navegador, proxies e logs de servidor.
*   **Armazenamento de `api_keys.json`:** A aplicação tentava carregar chaves de API de um arquivo `data/api_keys.json`. Embora houvesse uma preferência por variáveis de ambiente, a existência do arquivo local representava um risco de exposição acidental.

### 2.2. Soluções Implementadas

As seguintes soluções foram implementadas para garantir um tratamento mais seguro das chaves de API:

*   **Chaves de API Apenas via Variável de Ambiente:** O método `loadApiKeys` no `server.js` foi modificado para carregar chaves de API **exclusivamente** da variável de ambiente `API_KEYS_JSON`. A opção de carregar de `data/api_keys.json` foi removida.
*   **API Key Apenas no Cabeçalho `Authorization`:** O middleware `requireApiKey` no `server.js` foi ajustado para aceitar a chave de API **apenas** via cabeçalho `Authorization` no formato `Bearer <apiKey>`. Requisições que tentarem passar a chave via URL ou corpo serão rejeitadas.
*   **Injeção Segura da API Key no Frontend:**
    *   O arquivo `public/index_app.html` foi modificado para remover a chave de API hardcoded e incluir um placeholder `window.LINKMAGICO_API_KEY = 'YOUR_API_KEY_PLACEHOLDER';`.
    *   A rota `/app` no `server.js` agora lê o `index_app.html`, substitui o placeholder pela `apiKey` validada (armazenada na sessão `req.session.validatedApiKey`) e injeta o script do widget (`/public/script.js`) dinamicamente antes de servir a página.
    *   Todas as chamadas `fetch` no `public/index_app.html` (para endpoints administrativos) foram atualizadas para usar `Authorization: 'Bearer ' + window.LINKMAGICO_API_KEY`.
*   **Widget do Chatbot Atualizado:** O `public/script.js` (widget do chatbot) foi modificado para aceitar uma `apiKey` em sua configuração de inicialização (`LinkMagicoWidget.init({ apiKey: 'sua_chave_aqui' })`) e a envia no cabeçalho `Authorization` para as chamadas de API (`/chat-universal`).

### 2.3. Configuração no Render para Chaves de API

Você precisará configurar uma variável de ambiente no Render chamada `API_KEYS_JSON`. Esta variável deve conter um objeto JSON com suas chaves de API e seus respectivos dados (nome, plano, etc.).

**Passo a passo para configurar `API_KEYS_JSON` no Render:**

1.  Acesse o painel de controle do seu serviço LinkMágico no Render.
2.  Vá para a seção **Environment** (ou **Variáveis de Ambiente**).
3.  Adicione uma nova variável de ambiente com os seguintes detalhes:
    *   **Key:** `API_KEYS_JSON`
    *   **Value:** Um objeto JSON contendo suas chaves de API. Exemplo:
        ```json
        {
            "sua_api_key_aqui_1": {
                "nome": "Cliente A",
                "plano": "premium",
                "active": true
            },
            "sua_api_key_aqui_2": {
                "nome": "Cliente B",
                "plano": "basic",
                "active": true
            }
        }
        ```
        **Importante:** Substitua `

`sua_api_key_aqui_1` e `sua_api_key_aqui_2` por chaves de API fortes e únicas que você gerará. Certifique-se de que o JSON esteja formatado corretamente.
4.  Salve as alterações.

**Observação:** O arquivo `data/api_keys.json` deve ser removido do seu repositório ou ignorado pelo `.gitignore` para evitar exposição acidental.

## 3. Configuração de Segurança com Helmet (CSP, COEP, COOP, CORP)

### 3.1. Vulnerabilidade Original

Embora o Helmet estivesse em uso, as políticas `contentSecurityPolicy` e `crossOriginEmbedderPolicy` estavam desabilitadas (`false`). Isso reduzia a proteção contra ataques comuns baseados em injeção de conteúdo, como Cross-Site Scripting (XSS) e clickjacking.

### 3.2. Soluções Implementadas

As configurações do Helmet no `server.js` foram atualizadas para habilitar e configurar as seguintes políticas de segurança:

*   **Content Security Policy (CSP):** Uma política inicial foi definida para controlar quais recursos (scripts, estilos, imagens, etc.) podem ser carregados pela aplicação. Isso ajuda a mitigar ataques XSS ao restringir as fontes de conteúdo.
    *   `defaultSrc: [

"'self'"],`
    *   `scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://kit.fontawesome.com", "https://ka-f.fontawesome.com"],` (Nota: `'unsafe-inline'` e `'unsafe-eval'` foram incluídos temporariamente para compatibilidade e devem ser refinados).
    *   `styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://ka-f.fontawesome.com"],`
    *   `imgSrc: ["'self'", "data:", "https://*"],`
    *   `fontSrc: ["'self'", "https://fonts.gstatic.com", "https://ka-f.fontawesome.com"],`
    *   `connectSrc: ["'self'", "https://linkmagico-comercial.onrender.com", "https://link-m-gico-v6-0-hmpl.onrender.com"],` (Adicionar domínios da API)
    *   `frameSrc: ["'self'"],`
    *   `objectSrc: ["'none'"],`
    *   `baseUri: ["'self'"],`
    *   `formAction: ["'self'"],`
    *   `upgradeInsecureRequests: [],`
    *   `reportUri: "/report-csp-violation"` (Endpoint para relatar violações de CSP).
*   **Cross-Origin Embedder Policy (COEP):** Habilitado com `crossOriginEmbedderPolicy: true`. Ajuda a isolar o documento de recursos não confiáveis.
*   **Cross-Origin Opener Policy (COOP):** Configurado com `crossOriginOpenerPolicy: { policy: "same-origin" }`. Impede que documentos de origem cruzada abram sua janela com acesso total.
*   **Cross-Origin Resource Policy (CORP):** Configurado com `crossOriginResourcePolicy: { policy: "cross-origin" }`. Impede que recursos sejam carregados por documentos de origem cruzada.
*   **Endpoint de Relatório de CSP:** Um novo endpoint `/report-csp-violation` foi adicionado no `server.js` para receber e logar as violações do CSP. Isso é crucial para monitorar e refinar sua política de segurança.

### 3.3. Configuração no Render para Helmet/CSP

As configurações do Helmet são feitas diretamente no código `server.js` e **não requerem variáveis de ambiente específicas** no Render para sua ativação. No entanto, é fundamental que você monitore o endpoint `/report-csp-violation` para ajustar o CSP.

**Passo a passo para refinar o CSP:**

1.  **Monitore os Logs:** Após a implantação, observe os logs da sua aplicação no Render. Qualquer violação do CSP será registrada no endpoint `/report-csp-violation` e aparecerá nos logs como `CSP Violation: {detalhes_da_violacao}`.
2.  **Identifique Recursos Bloqueados:** Analise os detalhes da violação para identificar quais scripts, estilos, imagens ou outras fontes estão sendo bloqueadas indevidamente.
3.  **Atualize as Diretivas do CSP:** Edite o `server.js` para adicionar as fontes necessárias às diretivas apropriadas (ex: `scriptSrc`, `styleSrc`, `imgSrc`, `connectSrc`).
4.  **Remova `unsafe-inline` e `unsafe-eval`:** O objetivo final é remover essas diretivas, pois elas reduzem a eficácia do CSP. Isso pode exigir a refatoração de código inline ou o uso de hashes/nonces para scripts e estilos inline.
5.  **Reimplante e Repita:** Após cada ajuste, reimplemente a aplicação e continue monitorando os logs até que não haja mais violações legítimas.

## 4. Inicialização do Widget LinkMágico com API Key

Para que o widget do chatbot funcione corretamente com as novas medidas de segurança, ele precisa ser inicializado com a API Key correta.

### 4.1. Como o Widget é Inicializado

O widget é inicializado na página `index_app.html` (servida pela rota `/app` do seu backend) da seguinte forma:

```javascript
<script>
    // Placeholder para a API Key, será substituído pelo servidor
    window.LINKMAGICO_API_KEY = 'YOUR_API_KEY_PLACEHOLDER';

    // Inicializar o widget LinkMágico com a API Key
    if (window.LinkMagicoWidget && window.LINKMAGICO_API_KEY) {
        window.LinkMagicoWidget.init({
            apiKey: window.LINKMAGICO_API_KEY
        });
    }
</script>
<!-- WIDGET_SCRIPT_PLACEHOLDER -->
```

O `server.js` injeta a API Key validada no `window.LINKMAGICO_API_KEY` e o script do widget (`/public/script.js`) no `<!-- WIDGET_SCRIPT_PLACEHOLDER -->`.

### 4.2. Como Usar o Widget em Outras Páginas (Embed)

Se você pretende incorporar o widget em outras páginas (fora do seu domínio LinkMágico), você precisará garantir que a `apiKey` seja fornecida durante a inicialização. O script de incorporação deve ser semelhante a este:

```html
<script src="https://linkmagico-comercial.onrender.com/public/script.js"></script>
<script>
    LinkMagicoWidget.init({
        apiKey: 'SUA_API_KEY_DO_CHATBOT_AQUI',
        // Outras configurações do widget, se houver
        robotName: 'Meu Assistente Personalizado',
        welcomeMessage: 'Olá! Como posso ajudar você hoje?'
    });
</script>
```

**Importante:** Substitua `'SUA_API_KEY_DO_CHATBOT_AQUI'` pela chave de API específica do chatbot que você deseja incorporar. Esta chave deve ser uma das chaves configuradas na variável de ambiente `API_KEYS_JSON` no Render.

## 5. Recomendações Adicionais de Segurança

Além das implementações acima, considere as seguintes recomendações para fortalecer ainda mais a segurança da sua plataforma:

*   **HTTPS Obrigatório:** Certifique-se de que toda a comunicação com a plataforma seja feita exclusivamente via HTTPS. O Render geralmente configura isso automaticamente, mas é bom verificar.
*   **Atualizações de Dependências:** Mantenha todas as dependências do seu projeto (`package.json`) atualizadas para as versões mais recentes. Vulnerabilidades são frequentemente descobertas e corrigidas em novas versões de bibliotecas.
*   **Validação de Entrada em Todos os Endpoints:** Revise todos os endpoints da API para garantir que todas as entradas do usuário sejam rigorosamente validadas e sanitizadas para prevenir ataques como XSS, injeção de comandos e outras vulnerabilidades.
*   **Rate Limiting:** Implemente rate limiting em endpoints críticos (como login, validação de API Key, envio de mensagens para o chatbot) para mitigar ataques de força bruta e Denial of Service (DoS).
*   **Logs de Auditoria:** Mantenha logs detalhados de eventos de segurança (tentativas de login falhas, validações de API Key, etc.) para auxiliar na detecção e resposta a incidentes.
*   **Backup Regular:** Continue com a prática de backups regulares dos dados, especialmente dos leads, para garantir a recuperação em caso de perda de dados.
*   **Segurança da Sessão:** Revise as configurações de sessão (`express-session`) para garantir que cookies de sessão sejam seguros (HttpOnly, Secure, SameSite=Lax/Strict).

## Conclusão

As medidas implementadas e as recomendações fornecidas visam proteger sua plataforma LinkMágico v7.0 contra uma série de ataques cibernéticos. A segurança é um processo contínuo, e a vigilância constante, juntamente com a aplicação das melhores práticas, é essencial para manter a integridade e a confidencialidade dos seus dados e da sua aplicação.

---
