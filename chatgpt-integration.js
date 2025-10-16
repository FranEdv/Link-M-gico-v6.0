// ===== CHATGPT INTEGRATION MODULE =====
// Módulo para integrar ChatGPT (GPT-4, GPT-4-turbo, GPT-3.5-turbo) como opção de LLM

const axios = require('axios');

class ChatGPTIntegration {
    constructor() {
        this.apiKey = null;
        this.baseURL = 'https://api.openai.com/v1';
        this.isConfigured = false;
        this.models = {
            'gpt-4': {
                name: 'GPT-4',
                maxTokens: 8192,
                costPer1kTokens: 0.03,
                description: 'Modelo mais avançado, melhor qualidade'
            },
            'gpt-4-turbo': {
                name: 'GPT-4 Turbo',
                maxTokens: 128000,
                costPer1kTokens: 0.01,
                description: 'GPT-4 mais rápido e barato'
            },
            'gpt-3.5-turbo': {
                name: 'GPT-3.5 Turbo',
                maxTokens: 16385,
                costPer1kTokens: 0.0015,
                description: 'Rápido e econômico'
            }
        };
        this.defaultModel = 'gpt-4-turbo';
    }

    // Configurar API Key
    configure(apiKey) {
        if (!apiKey || !apiKey.startsWith('sk-')) {
            console.log('⚠️  ChatGPT API Key inválida');
            return false;
        }

        this.apiKey = apiKey;
        this.isConfigured = true;
        console.log('✅ ChatGPT configurado');
        return true;
    }

    // Verificar se está configurado
    isReady() {
        return this.isConfigured && this.apiKey !== null;
    }

    // Gerar resposta do ChatGPT
    async generateResponse(prompt, options = {}) {
        if (!this.isReady()) {
            throw new Error('ChatGPT não configurado');
        }

        const {
            model = this.defaultModel,
            temperature = 0.7,
            maxTokens = 1000,
            systemPrompt = 'Você é um assistente virtual prestativo e amigável.',
            conversationHistory = []
        } = options;

        try {
            const messages = [
                { role: 'system', content: systemPrompt },
                ...conversationHistory,
                { role: 'user', content: prompt }
            ];

            const response = await axios.post(
                `${this.baseURL}/chat/completions`,
                {
                    model: model,
                    messages: messages,
                    temperature: temperature,
                    max_tokens: maxTokens
                },
                {
                    headers: {
                        'Authorization': `Bearer ${this.apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    timeout: 30000
                }
            );

            const completion = response.data.choices[0].message.content;
            const usage = response.data.usage;

            return {
                success: true,
                response: completion,
                model: model,
                usage: {
                    promptTokens: usage.prompt_tokens,
                    completionTokens: usage.completion_tokens,
                    totalTokens: usage.total_tokens,
                    estimatedCost: this.calculateCost(usage.total_tokens, model)
                }
            };
        } catch (error) {
            console.error('❌ Erro ao chamar ChatGPT:', error.response?.data || error.message);
            
            return {
                success: false,
                error: error.response?.data?.error?.message || error.message,
                errorType: error.response?.data?.error?.type || 'unknown'
            };
        }
    }

    // Gerar resposta com contexto de página web
    async generateResponseWithContext(prompt, pageContent, options = {}) {
        const systemPrompt = `Você é um assistente virtual especializado em responder perguntas sobre o seguinte conteúdo:

${pageContent}

Responda às perguntas do usuário com base APENAS nas informações fornecidas acima. Se a informação não estiver disponível, diga educadamente que não tem essa informação.`;

        return await this.generateResponse(prompt, {
            ...options,
            systemPrompt
        });
    }

    // Gerar resposta com histórico de conversa
    async continueConversation(newMessage, conversationHistory, pageContent, options = {}) {
        const systemPrompt = `Você é um assistente virtual prestativo. Use o seguinte contexto para responder:

${pageContent}

Mantenha a conversa natural e amigável. Responda com base no contexto fornecido.`;

        return await this.generateResponse(newMessage, {
            ...options,
            systemPrompt,
            conversationHistory
        });
    }

    // Calcular custo estimado
    calculateCost(tokens, model) {
        const modelInfo = this.models[model];
        if (!modelInfo) return 0;

        const costPer1k = modelInfo.costPer1kTokens;
        const cost = (tokens / 1000) * costPer1k;
        
        return parseFloat(cost.toFixed(6));
    }

    // Listar modelos disponíveis
    getAvailableModels() {
        return this.models;
    }

    // Obter informações de um modelo específico
    getModelInfo(modelName) {
        return this.models[modelName] || null;
    }

    // Definir modelo padrão
    setDefaultModel(modelName) {
        if (!this.models[modelName]) {
            console.log(`⚠️  Modelo ${modelName} não existe`);
            return false;
        }

        this.defaultModel = modelName;
        console.log(`✅ Modelo padrão alterado para ${modelName}`);
        return true;
    }

    // Testar conexão
    async testConnection() {
        if (!this.isReady()) {
            return { success: false, error: 'ChatGPT não configurado' };
        }

        try {
            const result = await this.generateResponse('Diga apenas "OK" se você está funcionando.', {
                maxTokens: 10,
                temperature: 0
            });

            if (result.success) {
                console.log('✅ Conexão ChatGPT testada com sucesso');
                return { 
                    success: true, 
                    message: 'Conexão OK',
                    model: result.model,
                    response: result.response
                };
            } else {
                return result;
            }
        } catch (error) {
            console.error('❌ Erro ao testar ChatGPT:', error.message);
            return { success: false, error: error.message };
        }
    }

    // Obter status da configuração
    getStatus() {
        return {
            configured: this.isConfigured,
            ready: this.isReady(),
            defaultModel: this.defaultModel,
            availableModels: Object.keys(this.models)
        };
    }

    // Comparar custo entre modelos
    compareCosts(tokens) {
        const comparison = {};
        
        for (const [modelName, modelInfo] of Object.entries(this.models)) {
            comparison[modelName] = {
                name: modelInfo.name,
                cost: this.calculateCost(tokens, modelName),
                costPer1k: modelInfo.costPer1kTokens
            };
        }

        return comparison;
    }

    // Recomendar modelo baseado em requisitos
    recommendModel(requirements = {}) {
        const {
            priority = 'balanced', // 'cost', 'quality', 'balanced'
            maxBudget = null,
            needsLongContext = false
        } = requirements;

        if (needsLongContext) {
            return {
                recommended: 'gpt-4-turbo',
                reason: 'Suporta contexto muito longo (128k tokens)'
            };
        }

        if (priority === 'cost') {
            return {
                recommended: 'gpt-3.5-turbo',
                reason: 'Mais econômico'
            };
        }

        if (priority === 'quality') {
            return {
                recommended: 'gpt-4',
                reason: 'Melhor qualidade de resposta'
            };
        }

        // balanced
        return {
            recommended: 'gpt-4-turbo',
            reason: 'Melhor custo-benefício'
        };
    }
}

// Singleton instance
const chatgptIntegration = new ChatGPTIntegration();

// Configurar automaticamente se variável de ambiente existir
if (process.env.CHATGPT_API_KEY) {
    chatgptIntegration.configure(process.env.CHATGPT_API_KEY);
}

module.exports = {
    chatgptIntegration,
    ChatGPTIntegration
};

