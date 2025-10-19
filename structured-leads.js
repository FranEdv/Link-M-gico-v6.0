// ===== STRUCTURED LEADS MODULE =====
// Módulo para captura estruturada de leads com validação e exportação

const { db, DatabaseHelpers } = require('./database');
const fs = require('fs').promises;
const path = require('path');

class StructuredLeadsManager {
    constructor() {
        this.leadFields = {
            required: ['name', 'email'],
            optional: ['phone', 'company', 'position', 'website', 'notes'],
            custom: []
        };
    }

    // Inicializar tabela de leads estruturados
    async initialize() {
        try {
            const query = `
                CREATE TABLE IF NOT EXISTS structured_leads (
                    id TEXT PRIMARY KEY,
                    chatbot_id TEXT NOT NULL,
                    session_id TEXT,
                    
                    -- Campos básicos
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT,
                    
                    -- Campos profissionais
                    company TEXT,
                    position TEXT,
                    website TEXT,
                    
                    -- Campos de interesse
                    interest_product TEXT,
                    interest_level TEXT,
                    budget_range TEXT,
                    
                    -- Campos de origem
                    source_url TEXT,
                    source_page TEXT,
                    utm_source TEXT,
                    utm_medium TEXT,
                    utm_campaign TEXT,
                    
                    -- Campos de conversa
                    first_message TEXT,
                    last_message TEXT,
                    total_messages INTEGER DEFAULT 0,
                    conversation_duration INTEGER,
                    
                    -- Campos de qualificação
                    lead_score INTEGER DEFAULT 0,
                    lead_status TEXT DEFAULT 'new',
                    lead_tags TEXT,
                    
                    -- Campos customizados (JSON)
                    custom_fields TEXT,
                    
                    -- Metadados
                    notes TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    
                    -- Timestamps
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    contacted_at TIMESTAMP,
                    converted_at TIMESTAMP,
                    
                    -- Índices
                    UNIQUE(chatbot_id, email)
                )
            `;

            await DatabaseHelpers.run(query);
            console.log('✅ Tabela structured_leads criada/verificada');
            return true;
        } catch (error) {
            console.error('❌ Erro ao criar tabela structured_leads:', error);
            return false;
        }
    }

    // Validar email
    validateEmail(email) {
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return regex.test(email);
    }

    // Validar telefone (formato brasileiro)
    validatePhone(phone) {
        if (!phone) return true; // Opcional
        
        // Remove caracteres não numéricos
        const cleaned = phone.replace(/\D/g, '');
        
        // Aceita: 11 dígitos (celular com DDD) ou 10 dígitos (fixo com DDD)
        return cleaned.length === 10 || cleaned.length === 11;
    }

    // Validar URL
    validateUrl(url) {
        if (!url) return true; // Opcional
        
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    // Validar dados do lead
    validateLeadData(data) {
        const errors = [];

        // Campos obrigatórios
        if (!data.name || data.name.trim().length < 2) {
            errors.push('Nome é obrigatório e deve ter pelo menos 2 caracteres');
        }

        if (!data.email || !this.validateEmail(data.email)) {
            errors.push('Email inválido');
        }

        // Campos opcionais com validação
        if (data.phone && !this.validatePhone(data.phone)) {
            errors.push('Telefone inválido. Use formato: (11) 98765-4321');
        }

        if (data.website && !this.validateUrl(data.website)) {
            errors.push('Website inválido. Use formato: https://exemplo.com');
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    }

    // Calcular score do lead
    calculateLeadScore(data) {
        let score = 0;

        // Pontos por campos preenchidos
        if (data.name) score += 10;
        if (data.email) score += 10;
        if (data.phone) score += 15;
        if (data.company) score += 10;
        if (data.position) score += 10;
        if (data.website) score += 5;

        // Pontos por interesse
        if (data.interestProduct) score += 15;
        if (data.interestLevel === 'high') score += 20;
        else if (data.interestLevel === 'medium') score += 10;

        // Pontos por orçamento
        if (data.budgetRange) score += 10;

        // Pontos por engajamento
        if (data.totalMessages > 5) score += 10;
        if (data.conversationDuration > 120) score += 10; // Mais de 2 minutos

        return Math.min(score, 100); // Máximo 100
    }

    // Determinar status do lead baseado no score
    determineLeadStatus(score) {
        if (score >= 70) return 'hot';
        if (score >= 40) return 'warm';
        return 'cold';
    }

    // Salvar lead estruturado
    async saveLead(chatbotId, leadData, metadata = {}) {
        // Validar dados
        const validation = this.validateLeadData(leadData);
        if (!validation.valid) {
            return {
                success: false,
                errors: validation.errors
            };
        }

        try {
            const id = `lead_${chatbotId}_${Date.now()}`;
            const score = this.calculateLeadScore(leadData);
            const status = this.determineLeadStatus(score);

            const query = `
                INSERT OR REPLACE INTO structured_leads (
                    id, chatbot_id, session_id,
                    name, email, phone,
                    company, position, website,
                    interest_product, interest_level, budget_range,
                    source_url, source_page, utm_source, utm_medium, utm_campaign,
                    first_message, last_message, total_messages, conversation_duration,
                    lead_score, lead_status, lead_tags,
                    custom_fields, notes,
                    ip_address, user_agent,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            `;

            await DatabaseHelpers.run(query, [
                id,
                chatbotId,
                metadata.sessionId || null,
                leadData.name,
                leadData.email,
                leadData.phone || null,
                leadData.company || null,
                leadData.position || null,
                leadData.website || null,
                leadData.interestProduct || null,
                leadData.interestLevel || null,
                leadData.budgetRange || null,
                metadata.sourceUrl || null,
                metadata.sourcePage || null,
                metadata.utmSource || null,
                metadata.utmMedium || null,
                metadata.utmCampaign || null,
                leadData.firstMessage || null,
                leadData.lastMessage || null,
                leadData.totalMessages || 0,
                leadData.conversationDuration || 0,
                score,
                status,
                leadData.tags ? JSON.stringify(leadData.tags) : null,
                leadData.customFields ? JSON.stringify(leadData.customFields) : null,
                leadData.notes || null,
                metadata.ipAddress || null,
                metadata.userAgent || null
            ]);

            console.log(`✅ Lead estruturado salvo: ${leadData.email}`);

            return {
                success: true,
                id: id,
                score: score,
                status: status,
                message: 'Lead salvo com sucesso'
            };
        } catch (error) {
            console.error('❌ Erro ao salvar lead:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Buscar leads por chatbot
    async getLeads(chatbotId, filters = {}) {
        try {
            let query = `SELECT * FROM structured_leads WHERE chatbot_id = ?`;
            const params = [chatbotId];

            // Filtros opcionais
            if (filters.status) {
                query += ` AND lead_status = ?`;
                params.push(filters.status);
            }

            if (filters.minScore) {
                query += ` AND lead_score >= ?`;
                params.push(filters.minScore);
            }

            if (filters.fromDate) {
                query += ` AND created_at >= ?`;
                params.push(filters.fromDate);
            }

            query += ` ORDER BY created_at DESC`;

            if (filters.limit) {
                query += ` LIMIT ?`;
                params.push(filters.limit);
            }

            const leads = await DatabaseHelpers.all(query, params);

            return {
                success: true,
                count: leads.length,
                leads: leads.map(lead => ({
                    ...lead,
                    customFields: lead.custom_fields ? JSON.parse(lead.custom_fields) : null,
                    tags: lead.lead_tags ? JSON.parse(lead.lead_tags) : null
                }))
            };
        } catch (error) {
            console.error('❌ Erro ao buscar leads:', error);
            return {
                success: false,
                error: error.message,
                leads: []
            };
        }
    }

    // Exportar leads para CSV
    async exportToCSV(chatbotId, filters = {}) {
        try {
            const result = await this.getLeads(chatbotId, filters);
            
            if (!result.success || result.leads.length === 0) {
                return {
                    success: false,
                    error: 'Nenhum lead encontrado para exportar'
                };
            }

            // Cabeçalhos CSV
            const headers = [
                'ID', 'Nome', 'Email', 'Telefone', 'Empresa', 'Cargo', 'Website',
                'Produto de Interesse', 'Nível de Interesse', 'Faixa de Orçamento',
                'Score', 'Status', 'Total de Mensagens', 'Duração da Conversa (s)',
                'Origem URL', 'UTM Source', 'UTM Medium', 'UTM Campaign',
                'Data de Criação', 'Notas'
            ];

            // Linhas CSV
            const rows = result.leads.map(lead => [
                lead.id,
                lead.name,
                lead.email,
                lead.phone || '',
                lead.company || '',
                lead.position || '',
                lead.website || '',
                lead.interest_product || '',
                lead.interest_level || '',
                lead.budget_range || '',
                lead.lead_score,
                lead.lead_status,
                lead.total_messages,
                lead.conversation_duration || 0,
                lead.source_url || '',
                lead.utm_source || '',
                lead.utm_medium || '',
                lead.utm_campaign || '',
                new Date(lead.created_at).toLocaleString('pt-BR'),
                lead.notes || ''
            ]);

            // Gerar CSV
            const csvContent = [
                headers.join(','),
                ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
            ].join('\n');

            // Salvar arquivo
            const filename = `leads_${chatbotId}_${Date.now()}.csv`;
            const filepath = path.join('/tmp', filename);
            
            await fs.writeFile(filepath, csvContent, 'utf8');

            console.log(`✅ CSV exportado: ${filename}`);

            return {
                success: true,
                filename: filename,
                filepath: filepath,
                count: result.leads.length
            };
        } catch (error) {
            console.error('❌ Erro ao exportar CSV:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Atualizar status do lead
    async updateLeadStatus(leadId, newStatus) {
        try {
            const validStatuses = ['new', 'contacted', 'qualified', 'converted', 'lost'];
            
            if (!validStatuses.includes(newStatus)) {
                return {
                    success: false,
                    error: 'Status inválido'
                };
            }

            const query = `
                UPDATE structured_leads 
                SET lead_status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `;

            await DatabaseHelpers.run(query, [newStatus, leadId]);

            console.log(`✅ Status do lead ${leadId} atualizado para ${newStatus}`);

            return {
                success: true,
                message: 'Status atualizado com sucesso'
            };
        } catch (error) {
            console.error('❌ Erro ao atualizar status:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Obter estatísticas de leads
    async getStats(chatbotId) {
        try {
            const query = `
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN lead_status = 'hot' THEN 1 ELSE 0 END) as hot_leads,
                    SUM(CASE WHEN lead_status = 'warm' THEN 1 ELSE 0 END) as warm_leads,
                    SUM(CASE WHEN lead_status = 'cold' THEN 1 ELSE 0 END) as cold_leads,
                    AVG(lead_score) as avg_score,
                    SUM(CASE WHEN converted_at IS NOT NULL THEN 1 ELSE 0 END) as converted
                FROM structured_leads
                WHERE chatbot_id = ?
            `;

            const stats = await DatabaseHelpers.get(query, [chatbotId]);

            return {
                success: true,
                stats: {
                    total: stats.total || 0,
                    hot: stats.hot_leads || 0,
                    warm: stats.warm_leads || 0,
                    cold: stats.cold_leads || 0,
                    avgScore: parseFloat((stats.avg_score || 0).toFixed(2)),
                    converted: stats.converted || 0,
                    conversionRate: stats.total > 0 
                        ? parseFloat(((stats.converted / stats.total) * 100).toFixed(2))
                        : 0
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

    // Adicionar nota ao lead
    async addNote(leadId, note) {
        try {
            const query = `
                UPDATE structured_leads 
                SET notes = COALESCE(notes || '\n\n', '') || ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `;

            await DatabaseHelpers.run(query, [
                `[${new Date().toLocaleString('pt-BR')}] ${note}`,
                leadId
            ]);

            return {
                success: true,
                message: 'Nota adicionada com sucesso'
            };
        } catch (error) {
            console.error('❌ Erro ao adicionar nota:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// Singleton instance
const structuredLeadsManager = new StructuredLeadsManager();

// Inicializar automaticamente
(async () => {
    await structuredLeadsManager.initialize();
})();

module.exports = {
    structuredLeadsManager,
    StructuredLeadsManager
};

