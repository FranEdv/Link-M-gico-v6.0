// ===== WHATSAPP BUSINESS API INTEGRATION =====
// Módulo para enviar mensagens via WhatsApp usando Twilio ou Evolution API

const axios = require('axios');

class WhatsAppIntegration {
    constructor() {
        this.provider = null; // 'twilio' ou 'evolution'
        this.isConfigured = false;
        this.config = {};
        this.messageTemplates = {
            newLead: `🎉 *Novo Lead Capturado!*

📋 *Informações:*
• Nome: {{leadName}}
• Email: {{leadEmail}}
• Telefone: {{leadPhone}}
• Chatbot: {{chatbotName}}

⏰ {{timestamp}}

Acesse o painel para mais detalhes!`,
            
            highIntent: `🔥 *Lead com Alta Intenção!*

Um cliente demonstrou muito interesse!

📋 *Dados:*
• Nome: {{leadName}}
• Interesse: {{interest}}
• Chatbot: {{chatbotName}}

💡 *Sugestão:* Entre em contato AGORA!`,
            
            dailySummary: `📊 *Resumo Diário - {{date}}*

Seu chatbot {{chatbotName}} teve:

• {{totalMessages}} mensagens
• {{totalConversations}} conversas
• {{totalLeads}} leads capturados
• {{successRate}}% taxa de sucesso

Continue assim! 🚀`
        };
    }

    // Configurar Twilio
    configureTwilio(config) {
        try {
            const { accountSid, authToken, fromNumber } = config;

            if (!accountSid || !authToken || !fromNumber) {
                console.log('⚠️  Twilio não configurado (credenciais ausentes)');
                return false;
            }

            this.provider = 'twilio';
            this.config = {
                accountSid,
                authToken,
                fromNumber
            };
            this.isConfigured = true;

            console.log('✅ Twilio WhatsApp configurado');
            return true;
        } catch (error) {
            console.error('❌ Erro ao configurar Twilio:', error.message);
            return false;
        }
    }

    // Configurar Evolution API
    configureEvolution(config) {
        try {
            const { apiUrl, apiKey, instanceName } = config;

            if (!apiUrl || !apiKey || !instanceName) {
                console.log('⚠️  Evolution API não configurada (credenciais ausentes)');
                return false;
            }

            this.provider = 'evolution';
            this.config = {
                apiUrl,
                apiKey,
                instanceName
            };
            this.isConfigured = true;

            console.log('✅ Evolution API WhatsApp configurada');
            return true;
        } catch (error) {
            console.error('❌ Erro ao configurar Evolution API:', error.message);
            return false;
        }
    }

    // Verificar se está configurado
    isReady() {
        return this.isConfigured && this.provider !== null;
    }

    // Substituir variáveis no template
    replaceVariables(template, variables) {
        let result = template;
        for (const [key, value] of Object.entries(variables)) {
            const regex = new RegExp(`{{${key}}}`, 'g');
            result = result.replace(regex, value || 'N/A');
        }
        return result;
    }

    // Formatar número de telefone (adicionar código do país se necessário)
    formatPhoneNumber(phone) {
        // Remove caracteres não numéricos
        let cleaned = phone.replace(/\D/g, '');
        
        // Se não tem código do país, adiciona +55 (Brasil)
        if (!cleaned.startsWith('55') && cleaned.length <= 11) {
            cleaned = '55' + cleaned;
        }
        
        // Adiciona + no início
        if (!cleaned.startsWith('+')) {
            cleaned = '+' + cleaned;
        }
        
        return cleaned;
    }

    // Enviar mensagem via Twilio
    async sendViaTwilio(to, message) {
        try {
            const { accountSid, authToken, fromNumber } = this.config;
            
            const url = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
            
            const formattedTo = this.formatPhoneNumber(to);
            const formattedFrom = `whatsapp:${fromNumber}`;
            const formattedToWhatsApp = `whatsapp:${formattedTo}`;

            const response = await axios.post(url, 
                new URLSearchParams({
                    To: formattedToWhatsApp,
                    From: formattedFrom,
                    Body: message
                }), 
                {
                    auth: {
                        username: accountSid,
                        password: authToken
                    },
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            console.log(`✅ WhatsApp enviado via Twilio para ${to}`);
            return { success: true, messageId: response.data.sid };
        } catch (error) {
            console.error('❌ Erro ao enviar via Twilio:', error.response?.data || error.message);
            return { success: false, error: error.message };
        }
    }

    // Enviar mensagem via Evolution API
    async sendViaEvolution(to, message) {
        try {
            const { apiUrl, apiKey, instanceName } = this.config;
            
            const url = `${apiUrl}/message/sendText/${instanceName}`;
            
            const formattedTo = this.formatPhoneNumber(to);

            const response = await axios.post(url, {
                number: formattedTo,
                textMessage: {
                    text: message
                }
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'apikey': apiKey
                }
            });

            console.log(`✅ WhatsApp enviado via Evolution para ${to}`);
            return { success: true, messageId: response.data.key?.id };
        } catch (error) {
            console.error('❌ Erro ao enviar via Evolution:', error.response?.data || error.message);
            return { success: false, error: error.message };
        }
    }

    // Enviar mensagem (detecta provider automaticamente)
    async sendMessage(to, message) {
        if (!this.isReady()) {
            console.log('⚠️  WhatsApp não configurado, mensagem não enviada');
            return { success: false, error: 'WhatsApp não configurado' };
        }

        if (this.provider === 'twilio') {
            return await this.sendViaTwilio(to, message);
        } else if (this.provider === 'evolution') {
            return await this.sendViaEvolution(to, message);
        } else {
            return { success: false, error: 'Provider desconhecido' };
        }
    }

    // Notificar novo lead
    async notifyNewLead(leadData, chatbotData, ownerPhone) {
        if (!this.isReady() || !ownerPhone) {
            return { success: false, error: 'WhatsApp não configurado ou telefone ausente' };
        }

        const template = this.messageTemplates.newLead;
        const variables = {
            leadName: leadData.name || 'Não informado',
            leadEmail: leadData.email || 'Não informado',
            leadPhone: leadData.phone || 'Não informado',
            chatbotName: chatbotData.name || 'Chatbot',
            timestamp: new Date().toLocaleString('pt-BR')
        };

        const message = this.replaceVariables(template, variables);
        return await this.sendMessage(ownerPhone, message);
    }

    // Notificar alta intenção de compra
    async notifyHighIntent(leadData, chatbotData, ownerPhone) {
        if (!this.isReady() || !ownerPhone) {
            return { success: false, error: 'WhatsApp não configurado ou telefone ausente' };
        }

        const template = this.messageTemplates.highIntent;
        const variables = {
            leadName: leadData.name || 'Cliente',
            interest: leadData.interest || 'Produto/Serviço',
            chatbotName: chatbotData.name || 'Chatbot'
        };

        const message = this.replaceVariables(template, variables);
        return await this.sendMessage(ownerPhone, message);
    }

    // Enviar resumo diário
    async sendDailySummary(analytics, chatbotData, ownerPhone) {
        if (!this.isReady() || !ownerPhone) {
            return { success: false, error: 'WhatsApp não configurado ou telefone ausente' };
        }

        const template = this.messageTemplates.dailySummary;
        const variables = {
            date: new Date().toLocaleDateString('pt-BR'),
            chatbotName: chatbotData.name || 'Chatbot',
            totalMessages: analytics.totalMessages || 0,
            totalConversations: analytics.totalConversations || 0,
            totalLeads: analytics.totalLeads || 0,
            successRate: analytics.successRate || 0
        };

        const message = this.replaceVariables(template, variables);
        return await this.sendMessage(ownerPhone, message);
    }

    // Enviar mensagem customizada
    async sendCustomMessage(to, content, variables = {}) {
        if (!this.isReady()) {
            return { success: false, error: 'WhatsApp não configurado' };
        }

        const message = this.replaceVariables(content, variables);
        return await this.sendMessage(to, message);
    }

    // Adicionar template customizado
    addTemplate(name, template) {
        this.messageTemplates[name] = template;
        console.log(`✅ Template WhatsApp '${name}' adicionado`);
    }

    // Listar templates disponíveis
    getTemplates() {
        return Object.keys(this.messageTemplates);
    }

    // Testar conexão
    async testConnection(testPhone) {
        if (!this.isReady()) {
            return { success: false, error: 'WhatsApp não configurado' };
        }

        const testMessage = `✅ Teste de conexão WhatsApp\n\nSua integração está funcionando corretamente!\n\nProvider: ${this.provider}`;
        
        return await this.sendMessage(testPhone, testMessage);
    }

    // Obter status da configuração
    getStatus() {
        return {
            configured: this.isConfigured,
            provider: this.provider,
            ready: this.isReady()
        };
    }
}

// Singleton instance
const whatsappIntegration = new WhatsAppIntegration();

// Configurar automaticamente se variáveis de ambiente existirem
if (process.env.WHATSAPP_PROVIDER === 'twilio') {
    whatsappIntegration.configureTwilio({
        accountSid: process.env.TWILIO_ACCOUNT_SID,
        authToken: process.env.TWILIO_AUTH_TOKEN,
        fromNumber: process.env.TWILIO_WHATSAPP_NUMBER
    });
} else if (process.env.WHATSAPP_PROVIDER === 'evolution') {
    whatsappIntegration.configureEvolution({
        apiUrl: process.env.EVOLUTION_API_URL,
        apiKey: process.env.EVOLUTION_API_KEY,
        instanceName: process.env.EVOLUTION_INSTANCE_NAME
    });
}

module.exports = {
    whatsappIntegration,
    WhatsAppIntegration
};

