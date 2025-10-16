// ===== GMAIL INTEGRATION MODULE =====
// Módulo para enviar emails automáticos via Gmail/SMTP

const nodemailer = require('nodemailer');

class GmailIntegration {
    constructor() {
        this.transporter = null;
        this.isConfigured = false;
        this.emailTemplates = {
            leadCaptured: {
                subject: '🎉 Novo Lead Capturado - {{chatbotName}}',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #3b82f6;">🎉 Novo Lead Capturado!</h2>
                        <p>Um novo lead foi capturado através do chatbot <strong>{{chatbotName}}</strong>.</p>
                        
                        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="margin-top: 0;">📋 Informações do Lead:</h3>
                            <p><strong>Nome:</strong> {{leadName}}</p>
                            <p><strong>Email:</strong> {{leadEmail}}</p>
                            <p><strong>Telefone:</strong> {{leadPhone}}</p>
                            <p><strong>Data/Hora:</strong> {{timestamp}}</p>
                        </div>
                        
                        <div style="background: #eff6ff; padding: 15px; border-left: 4px solid #3b82f6; margin: 20px 0;">
                            <h4 style="margin-top: 0;">💬 Última Mensagem:</h4>
                            <p>{{lastMessage}}</p>
                        </div>
                        
                        <p style="color: #6b7280; font-size: 14px;">
                            Este email foi enviado automaticamente pelo Link Mágico.
                        </p>
                    </div>
                `
            },
            welcomeLead: {
                subject: 'Bem-vindo! Obrigado pelo contato',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #3b82f6;">Olá, {{leadName}}! 👋</h2>
                        <p>Obrigado por entrar em contato conosco através do nosso chatbot!</p>
                        
                        <p>Recebemos suas informações e em breve entraremos em contato.</p>
                        
                        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
                            <h3 style="margin-top: 0;">📋 Seus Dados:</h3>
                            <p><strong>Nome:</strong> {{leadName}}</p>
                            <p><strong>Email:</strong> {{leadEmail}}</p>
                            <p><strong>Telefone:</strong> {{leadPhone}}</p>
                        </div>
                        
                        <p>Se você tiver alguma dúvida urgente, pode responder este email diretamente.</p>
                        
                        <p style="margin-top: 30px;">
                            Atenciosamente,<br>
                            <strong>{{companyName}}</strong>
                        </p>
                        
                        <p style="color: #6b7280; font-size: 12px; margin-top: 30px;">
                            Este é um email automático. Por favor, não responda se não for necessário.
                        </p>
                    </div>
                `
            }
        };
    }

    // Configurar transporter do Gmail
    configure(config) {
        try {
            const {
                service = 'gmail',
                user,
                password,
                from
            } = config;

            if (!user || !password) {
                console.log('⚠️  Gmail não configurado (user/password ausentes)');
                return false;
            }

            this.transporter = nodemailer.createTransporter({
                service: service,
                auth: {
                    user: user,
                    pass: password
                }
            });

            this.fromEmail = from || user;
            this.isConfigured = true;

            console.log('✅ Gmail configurado com sucesso');
            return true;
        } catch (error) {
            console.error('❌ Erro ao configurar Gmail:', error.message);
            return false;
        }
    }

    // Verificar se está configurado
    isReady() {
        return this.isConfigured && this.transporter !== null;
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

    // Enviar email genérico
    async sendEmail(options) {
        if (!this.isReady()) {
            console.log('⚠️  Gmail não configurado, email não enviado');
            return { success: false, error: 'Gmail não configurado' };
        }

        try {
            const mailOptions = {
                from: this.fromEmail,
                to: options.to,
                subject: options.subject,
                html: options.html || options.text,
                text: options.text
            };

            const info = await this.transporter.sendMail(mailOptions);
            
            console.log(`✅ Email enviado para ${options.to}`);
            return { success: true, messageId: info.messageId };
        } catch (error) {
            console.error('❌ Erro ao enviar email:', error.message);
            return { success: false, error: error.message };
        }
    }

    // Enviar notificação de novo lead (para você)
    async notifyNewLead(leadData, chatbotData) {
        if (!this.isReady()) {
            return { success: false, error: 'Gmail não configurado' };
        }

        const template = this.emailTemplates.leadCaptured;
        const variables = {
            chatbotName: chatbotData.name || 'Chatbot',
            leadName: leadData.name || 'Não informado',
            leadEmail: leadData.email || 'Não informado',
            leadPhone: leadData.phone || 'Não informado',
            timestamp: new Date().toLocaleString('pt-BR'),
            lastMessage: leadData.lastMessage || 'Nenhuma mensagem'
        };

        const subject = this.replaceVariables(template.subject, variables);
        const html = this.replaceVariables(template.html, variables);

        return await this.sendEmail({
            to: chatbotData.ownerEmail || process.env.OWNER_EMAIL,
            subject: subject,
            html: html
        });
    }

    // Enviar email de boas-vindas para o lead
    async sendWelcomeEmail(leadData, chatbotData) {
        if (!this.isReady()) {
            return { success: false, error: 'Gmail não configurado' };
        }

        if (!leadData.email) {
            return { success: false, error: 'Lead não tem email' };
        }

        const template = this.emailTemplates.welcomeLead;
        const variables = {
            leadName: leadData.name || 'Cliente',
            leadEmail: leadData.email,
            leadPhone: leadData.phone || 'Não informado',
            companyName: chatbotData.companyName || 'Nossa Empresa'
        };

        const subject = this.replaceVariables(template.subject, variables);
        const html = this.replaceVariables(template.html, variables);

        return await this.sendEmail({
            to: leadData.email,
            subject: subject,
            html: html
        });
    }

    // Enviar email customizado
    async sendCustomEmail(to, subject, content, variables = {}) {
        if (!this.isReady()) {
            return { success: false, error: 'Gmail não configurado' };
        }

        const finalSubject = this.replaceVariables(subject, variables);
        const finalContent = this.replaceVariables(content, variables);

        return await this.sendEmail({
            to: to,
            subject: finalSubject,
            html: finalContent
        });
    }

    // Adicionar template customizado
    addTemplate(name, template) {
        this.emailTemplates[name] = template;
        console.log(`✅ Template '${name}' adicionado`);
    }

    // Listar templates disponíveis
    getTemplates() {
        return Object.keys(this.emailTemplates);
    }

    // Testar configuração
    async testConnection() {
        if (!this.isReady()) {
            return { success: false, error: 'Gmail não configurado' };
        }

        try {
            await this.transporter.verify();
            console.log('✅ Conexão Gmail testada com sucesso');
            return { success: true, message: 'Conexão OK' };
        } catch (error) {
            console.error('❌ Erro ao testar Gmail:', error.message);
            return { success: false, error: error.message };
        }
    }
}

// Singleton instance
const gmailIntegration = new GmailIntegration();

// Configurar automaticamente se variáveis de ambiente existirem
if (process.env.GMAIL_USER && process.env.GMAIL_PASSWORD) {
    gmailIntegration.configure({
        user: process.env.GMAIL_USER,
        password: process.env.GMAIL_PASSWORD,
        from: process.env.GMAIL_FROM || process.env.GMAIL_USER
    });
}

module.exports = {
    gmailIntegration,
    GmailIntegration
};

