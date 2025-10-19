// ===== WHITELABEL MODULE =====
// Módulo para personalização de marca nos planos pagos

const { db, DatabaseHelpers } = require('./database');

class WhitelabelManager {
    constructor() {
        this.defaultBranding = {
            companyName: 'Link Mágico',
            logo: null,
            primaryColor: '#3b82f6',
            secondaryColor: '#8b5cf6',
            poweredByText: 'Powered by Link Mágico',
            showPoweredBy: true,
            customDomain: null,
            favicon: null
        };
    }

    // Inicializar tabela de whitelabel
    async initialize() {
        try {
            const query = `
                CREATE TABLE IF NOT EXISTS whitelabel_settings (
                    id TEXT PRIMARY KEY,
                    chatbot_id TEXT NOT NULL,
                    plan_type TEXT NOT NULL,
                    company_name TEXT,
                    logo_url TEXT,
                    primary_color TEXT DEFAULT '#3b82f6',
                    secondary_color TEXT DEFAULT '#8b5cf6',
                    powered_by_text TEXT,
                    show_powered_by BOOLEAN DEFAULT true,
                    custom_domain TEXT,
                    favicon_url TEXT,
                    custom_css TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `;

            await DatabaseHelpers.run(query);
            console.log('✅ Tabela whitelabel_settings criada/verificada');
            return true;
        } catch (error) {
            console.error('❌ Erro ao criar tabela whitelabel:', error);
            return false;
        }
    }

    // Verificar se plano permite whitelabel
    canUseWhitelabel(planType) {
        const allowedPlans = ['professional', 'empresarial'];
        return allowedPlans.includes(planType.toLowerCase());
    }

    // Salvar configurações de whitelabel
    async saveSettings(chatbotId, settings, planType) {
        if (!this.canUseWhitelabel(planType)) {
            return {
                success: false,
                error: 'Whitelabel disponível apenas nos planos Profissional e Empresarial'
            };
        }

        try {
            const id = `wl_${chatbotId}_${Date.now()}`;
            
            const query = `
                INSERT OR REPLACE INTO whitelabel_settings (
                    id, chatbot_id, plan_type, company_name, logo_url,
                    primary_color, secondary_color, powered_by_text,
                    show_powered_by, custom_domain, favicon_url, custom_css,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            `;

            await DatabaseHelpers.run(query, [
                id,
                chatbotId,
                planType,
                settings.companyName || null,
                settings.logoUrl || null,
                settings.primaryColor || '#3b82f6',
                settings.secondaryColor || '#8b5cf6',
                settings.poweredByText || null,
                settings.showPoweredBy !== undefined ? settings.showPoweredBy : true,
                settings.customDomain || null,
                settings.faviconUrl || null,
                settings.customCss || null
            ]);

            console.log(`✅ Whitelabel configurado para chatbot ${chatbotId}`);
            
            return {
                success: true,
                id: id,
                message: 'Configurações de whitelabel salvas com sucesso'
            };
        } catch (error) {
            console.error('❌ Erro ao salvar whitelabel:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Obter configurações de whitelabel
    async getSettings(chatbotId) {
        try {
            const query = `
                SELECT * FROM whitelabel_settings 
                WHERE chatbot_id = ? 
                ORDER BY created_at DESC 
                LIMIT 1
            `;

            const settings = await DatabaseHelpers.get(query, [chatbotId]);

            if (!settings) {
                return {
                    success: true,
                    settings: this.defaultBranding,
                    isDefault: true
                };
            }

            return {
                success: true,
                settings: {
                    companyName: settings.company_name,
                    logoUrl: settings.logo_url,
                    primaryColor: settings.primary_color,
                    secondaryColor: settings.secondary_color,
                    poweredByText: settings.powered_by_text,
                    showPoweredBy: settings.show_powered_by === 1,
                    customDomain: settings.custom_domain,
                    faviconUrl: settings.favicon_url,
                    customCss: settings.custom_css
                },
                isDefault: false
            };
        } catch (error) {
            console.error('❌ Erro ao buscar whitelabel:', error);
            return {
                success: true,
                settings: this.defaultBranding,
                isDefault: true
            };
        }
    }

    // Gerar CSS customizado baseado nas configurações
    generateCustomCSS(settings) {
        const css = `
            /* Whitelabel Custom CSS */
            :root {
                --primary-color: ${settings.primaryColor || '#3b82f6'};
                --secondary-color: ${settings.secondaryColor || '#8b5cf6'};
            }

            .chatbot-container {
                --chatbot-primary: var(--primary-color);
                --chatbot-secondary: var(--secondary-color);
            }

            .chatbot-header {
                background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            }

            .chatbot-button {
                background: var(--primary-color);
            }

            .chatbot-button:hover {
                background: var(--secondary-color);
            }

            .message-user {
                background: var(--primary-color);
            }

            .message-bot {
                background: #f3f4f6;
            }

            ${settings.customCss || ''}
        `;

        return css;
    }

    // Gerar HTML do widget com whitelabel aplicado
    generateWidgetHTML(chatbotId, settings) {
        const showPoweredBy = settings.showPoweredBy !== false;
        const poweredByText = settings.poweredByText || 'Powered by Link Mágico';
        const companyName = settings.companyName || 'Assistente Virtual';
        const logoUrl = settings.logoUrl;

        const poweredByHTML = showPoweredBy ? `
            <div class="chatbot-powered-by" style="text-align: center; font-size: 11px; color: #9ca3af; margin-top: 10px;">
                ${poweredByText}
            </div>
        ` : '';

        const logoHTML = logoUrl ? `
            <img src="${logoUrl}" alt="${companyName}" class="chatbot-logo" style="height: 30px; margin-right: 10px;">
        ` : '';

        return `
            <div id="linkmagico-chatbot-${chatbotId}" class="chatbot-container">
                <div class="chatbot-header">
                    ${logoHTML}
                    <span class="chatbot-title">${companyName}</span>
                </div>
                <div class="chatbot-messages" id="chatbot-messages-${chatbotId}"></div>
                <div class="chatbot-input-container">
                    <input type="text" class="chatbot-input" placeholder="Digite sua mensagem..." />
                    <button class="chatbot-send-button">Enviar</button>
                </div>
                ${poweredByHTML}
            </div>
        `;
    }

    // Remover configurações de whitelabel
    async removeSettings(chatbotId) {
        try {
            const query = `DELETE FROM whitelabel_settings WHERE chatbot_id = ?`;
            await DatabaseHelpers.run(query, [chatbotId]);

            console.log(`✅ Whitelabel removido para chatbot ${chatbotId}`);
            return {
                success: true,
                message: 'Configurações de whitelabel removidas'
            };
        } catch (error) {
            console.error('❌ Erro ao remover whitelabel:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Listar todos os whitelabels
    async listAll() {
        try {
            const query = `
                SELECT chatbot_id, company_name, plan_type, show_powered_by, created_at
                FROM whitelabel_settings
                ORDER BY created_at DESC
            `;

            const settings = await DatabaseHelpers.all(query);

            return {
                success: true,
                count: settings.length,
                settings: settings
            };
        } catch (error) {
            console.error('❌ Erro ao listar whitelabels:', error);
            return {
                success: false,
                error: error.message,
                settings: []
            };
        }
    }

    // Validar URL de logo
    isValidLogoUrl(url) {
        if (!url) return false;
        
        const validExtensions = ['.png', '.jpg', '.jpeg', '.svg', '.webp'];
        const lowerUrl = url.toLowerCase();
        
        return validExtensions.some(ext => lowerUrl.includes(ext));
    }

    // Validar cor hexadecimal
    isValidColor(color) {
        if (!color) return false;
        return /^#[0-9A-F]{6}$/i.test(color);
    }

    // Validar configurações antes de salvar
    validateSettings(settings) {
        const errors = [];

        if (settings.logoUrl && !this.isValidLogoUrl(settings.logoUrl)) {
            errors.push('URL do logo inválida. Use PNG, JPG, SVG ou WebP');
        }

        if (settings.primaryColor && !this.isValidColor(settings.primaryColor)) {
            errors.push('Cor primária inválida. Use formato hexadecimal (#RRGGBB)');
        }

        if (settings.secondaryColor && !this.isValidColor(settings.secondaryColor)) {
            errors.push('Cor secundária inválida. Use formato hexadecimal (#RRGGBB)');
        }

        if (settings.companyName && settings.companyName.length > 50) {
            errors.push('Nome da empresa muito longo (máximo 50 caracteres)');
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    }

    // Obter estatísticas de uso de whitelabel
    async getStats() {
        try {
            const query = `
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN show_powered_by = 0 THEN 1 ELSE 0 END) as without_powered_by,
                    COUNT(DISTINCT plan_type) as unique_plans
                FROM whitelabel_settings
            `;

            const stats = await DatabaseHelpers.get(query);

            return {
                success: true,
                stats: {
                    total: stats.total || 0,
                    withoutPoweredBy: stats.without_powered_by || 0,
                    uniquePlans: stats.unique_plans || 0
                }
            };
        } catch (error) {
            console.error('❌ Erro ao obter estatísticas:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// Singleton instance
const whitelabelManager = new WhitelabelManager();

// Inicializar automaticamente
(async () => {
    await whitelabelManager.initialize();
})();

module.exports = {
    whitelabelManager,
    WhitelabelManager
};

