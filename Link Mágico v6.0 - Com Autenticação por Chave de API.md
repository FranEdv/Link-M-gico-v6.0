# Link Mágico v6.0 - Com Autenticação por Chave de API

Este repositório contém a versão 6.0 do Link Mágico, uma ferramenta poderosa para extração de dados e interação via chatbot, agora aprimorada com um sistema de autenticação básico por chave de API. Esta implementação visa permitir a comercialização da ferramenta, garantindo que apenas usuários autorizados possam acessar suas funcionalidades principais.

## O que é a ferramenta Link Mágico?

O Link Mágico v6.0 é uma solução robusta baseada em Node.js que oferece duas funcionalidades principais:

1.  **Extração de Dados de Páginas Web (`/extract`):** Utiliza tecnologias como `axios`, `cheerio` e `puppeteer` para extrair informações relevantes de URLs fornecidas. Ele pode coletar títulos, descrições, resumos, bônus detectados e outras informações de texto limpo de páginas web, lidando com conteúdo estático e dinâmico.
2.  **Chatbot Universal (`/chat-universal`):** Integra-se com modelos de linguagem (LLMs) como o Groq para fornecer um chatbot interativo. Ele pode responder a perguntas, fornecer informações e interagir com os usuários com base nos dados extraídos ou em seu conhecimento geral.

Além disso, a ferramenta inclui um **Widget JavaScript (`widjet.js`)** que pode ser facilmente incorporado em qualquer página web para fornecer uma interface de chatbot aos visitantes, permitindo que eles interajam diretamente com o Link Mágico.

## Novas Implementações de Segurança e Acesso

Para tornar o Link Mágico um produto comercialmente viável, foi adicionado um sistema de autenticação por chave de API. As principais alterações são:

1.  **Middleware de Autenticação (`server.js`):** Um middleware foi implementado no `server.js` para proteger as rotas `/extract` e `/chat-universal`. Todas as requisições para essas rotas agora exigem um cabeçalho `X-API-KEY` válido ou um parâmetro de consulta `api_key` com a chave de API correta.
2.  **Injeção de Chave de API no Widget (`server.js`):** O arquivo `widjet.js` agora é servido dinamicamente pelo `server.js`. Isso permite que o servidor injete a chave de API configurada no ambiente (`process.env.API_KEY`) diretamente no código JavaScript do widget antes de enviá-lo ao navegador. Dessa forma, o widget automaticamente inclui a chave de API em suas requisições para o backend, sem a necessidade de o cliente configurá-la manualmente no frontend.
3.  **Uso da Chave de API no Widget (`widjet.js`):** O código JavaScript do widget foi modificado para incluir a chave de API injetada em todas as suas requisições para as rotas protegidas do backend, utilizando o cabeçalho `X-API-KEY`.
4.  **Geração de Chaves de API (`generate-api-key.js`):** Um script simples foi criado para gerar novas chaves de API de forma segura, facilitando a criação de chaves individuais para cada cliente.

Essas mudanças garantem que apenas clientes com uma chave de API válida e autorizada possam utilizar as funcionalidades principais do Link Mágico, tornando-o um produto seguro para comercialização.

## Pré-requisitos

Antes de começar, certifique-se de ter o seguinte instalado:

*   **Node.js** (versão 18 ou superior)
*   **npm** (gerenciador de pacotes do Node.js)
*   **Git**

## Configuração e Instalação (Ambiente de Desenvolvimento)

Siga os passos abaixo para configurar e executar o Link Mágico em seu ambiente local:

1.  **Clone o Repositório:**
    ```bash
    git clone https://github.com/FranEdv/Link-M-gico-v6.0.git
    cd Link-M-gico-v6.0
    ```

2.  **Instale as Dependências:**
    ```bash
    npm install
    ```

3.  **Configure as Variáveis de Ambiente:**
    Crie um arquivo `.env` na raiz do projeto com o seguinte conteúdo:
    ```
    API_KEY=sua_chave_secreta_aqui
    GROQ_API_KEY=sua_chave_api_groq_aqui
    GROQ_MODEL=llama-3.1-70b-versatile # Ou outro modelo Groq de sua preferência
    LOG_LEVEL=info
    ```
    **Importante:** Substitua `sua_chave_secreta_aqui` pela chave de API que você deseja usar para autenticar as requisições. Substitua `sua_chave_api_groq_aqui` pela sua chave de API do Groq (necessária para o chatbot).

4.  **Gere uma Chave de API (Opcional, para clientes):**
    Para gerar chaves de API para seus clientes, você pode usar o script `generate-api-key.js`:
    ```bash
    node generate-api-key.js
    ```
    Este comando irá imprimir uma nova chave de API no console. Você pode usar essa chave para um cliente específico e adicioná-la ao `.env` do seu servidor de produção.

5.  **Inicie o Servidor:**
    ```bash
    npm start
    ```
    O servidor estará rodando em `http://localhost:3000`.

## Uso da Ferramenta

### 1. Extração de Dados (API)

Para extrair dados de uma URL, faça uma requisição `POST` para `/extract` com a URL e sua chave de API.

**Exemplo com `curl`:**

```bash
curl -X POST http://localhost:3000/extract \
     -H "Content-Type: application/json" \
     -H "X-API-KEY: sua_chave_secreta_aqui" \
     -d '{"url": "https://www.example.com"}'
```

Substitua `sua_chave_secreta_aqui` pela chave configurada no seu `.env` e `https://www.example.com` pela URL que deseja extrair.

### 2. Chatbot Universal (API)

Para interagir com o chatbot, faça uma requisição `POST` para `/chat-universal` com sua mensagem e chave de API.

**Exemplo com `curl`:**

```bash
curl -X POST http://localhost:3000/chat-universal \
     -H "Content-Type: application/json" \
     -H "X-API-KEY: sua_chave_secreta_aqui" \
     -d '{"message": "Olá, qual é a capital da França?", "conversationId": "user123"}'
```

Substitua `sua_chave_secreta_aqui` pela chave configurada no seu `.env`.

### 3. Widget de Chatbot (Frontend)

Para incorporar o widget de chatbot em seu site, adicione o seguinte script ao final do `<body>` da sua página HTML:

```html
<script src="http://SEU_DOMINIO:3000/widget.js"></script>
```

**Importante:**
*   Substitua `http://SEU_DOMINIO:3000` pelo endereço do seu servidor Link Mágico (em produção, será o domínio do Render).
*   O `server.js` irá automaticamente injetar a `API_KEY` configurada no seu `.env` dentro do `widjet.js` antes de servi-lo. Isso significa que o widget já estará configurado com a chave de API correta para se comunicar com o backend.

## Configuração para Implantação em Produção (Render.com)

Para implantar o Link Mágico em um ambiente de produção como o Render.com, siga estes passos:

1.  **Crie um Repositório GitHub:**
    Se você ainda não tem, crie um novo repositório no GitHub e faça o upload do seu projeto Link Mágico (incluindo as alterações de segurança e o arquivo `.env` - **certifique-se de que o `.env` não está no `.gitignore` para que o Render possa lê-lo, ou configure as variáveis de ambiente diretamente no Render**).

2.  **Conecte ao Render:**
    *   Faça login na sua conta Render.com.
    *   Clique em "New Web Service".
    *   Conecte sua conta GitHub e selecione o repositório do Link Mágico.

3.  **Configure o Web Service:**
    *   **Name:** Escolha um nome para o seu serviço (ex: `link-magico-api`).
    *   **Region:** Selecione a região mais próxima dos seus usuários.
    *   **Branch:** `main` (ou a branch que você usa para produção).
    *   **Root Directory:** Deixe em branco se o `package.json` estiver na raiz do repositório.
    *   **Runtime:** `Node`.
    *   **Build Command:** `npm install`.
    *   **Start Command:** `npm start`.

4.  **Variáveis de Ambiente (Environment Variables):**
    Esta é a parte **CRÍTICA** para a segurança e funcionamento da sua API Key.
    *   No Render, vá para a seção "Environment" do seu serviço.
    *   Adicione as seguintes variáveis:
        *   `API_KEY`: `sua_chave_secreta_aqui` (Use a chave que você gerou ou uma nova para produção).
        *   `GROQ_API_KEY`: `sua_chave_api_groq_aqui` (Sua chave de API do Groq).
        *   `LOG_LEVEL`: `info` (ou `debug`, `warn`, `error`).
    *   **Recomendação de Segurança:** Para a `API_KEY` principal do seu serviço, use uma chave forte e única. Para as chaves que você distribuirá aos seus clientes, você pode gerar chaves individuais e gerenciá-las de alguma forma (por exemplo, armazenando-as em um banco de dados e validando-as no middleware, embora isso seja mais complexo do que o escopo atual).

5.  **Deploy:**
    *   Clique em "Create Web Service".
    *   O Render irá construir e implantar seu serviço. Uma vez que esteja ativo, você terá uma URL pública (ex: `https://seu-servico.onrender.com`).

## Comercialização para o Público Alvo

Para comercializar o Link Mágico com autenticação por chave de API, considere os seguintes pontos:

1.  **Geração e Gerenciamento de Chaves:**
    *   Para cada cliente que adquirir sua ferramenta, gere uma chave de API única usando o script `generate-api-key.js`.
    *   Você precisará de um mecanismo para armazenar e validar essas chaves. A implementação atual usa uma única `API_KEY` do `.env`. Para múltiplos clientes, você pode expandir isso para um array de chaves no `.env` ou, para uma solução mais robusta, um banco de dados simples que armazene as chaves e seus respectivos clientes.
    *   **Exemplo de `.env` com múltiplas chaves (para validação simples):**
        ```
        API_KEYS=chave_cliente_1,chave_cliente_2,chave_cliente_3
        ```
        E no `server.js`, você adaptaria o middleware para verificar se a chave fornecida está presente na lista de `API_KEYS`.

2.  **Distribuição do Widget:**
    *   Forneça aos seus clientes a linha de código HTML para incorporar o widget em seus sites, instruindo-os a substituir `SEU_DOMINIO` pelo domínio do seu serviço Link Mágico hospedado no Render.
    *   Como a chave de API é injetada dinamicamente, o cliente não precisa se preocupar em configurá-la no frontend, apenas em usar o script correto.

3.  **Documentação para Clientes:**
    *   Crie uma documentação clara e concisa para seus clientes sobre como usar o widget e, se aplicável, como fazer requisições diretas à API (caso você ofereça essa opção).
    *   Explique a importância de manter a chave de API segura.

4.  **Monitoramento e Suporte:**
    *   Monitore o uso da API e do chatbot para garantir a estabilidade do serviço.
    *   Ofereça suporte aos seus clientes para quaisquer dúvidas ou problemas de integração.

Com esta estrutura, você tem uma base sólida para comercializar o Link Mágico, oferecendo acesso controlado e seguro aos seus clientes.

