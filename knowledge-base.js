/**
 * 📚 SISTEMA DE GESTÃO DE CONHECIMENTO - Link Mágico
 * Permite adicionar múltiplas fontes de conhecimento além de URLs
 * 
 * Fontes suportadas:
 * - URLs (web scraping)
 * - PDFs (upload)
 * - FAQs (CSV/JSON)
 * - Texto manual
 * - Documentos (TXT, MD)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class KnowledgeBaseManager {
    constructor() {
        this.knowledgeBases = new Map();
        this.dataPath = path.join(__dirname, 'data', 'knowledge');
        
        this.ensureDataDirectory();
        this.loadKnowledgeBases();
        
        console.log('📚 Sistema de Gestão de Conhecimento inicializado');
    }

    /**
     * Garantir que o diretório existe
     */
    ensureDataDirectory() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    /**
     * Carregar bases de conhecimento salvas
     */
    loadKnowledgeBases() {
        try {
            const files = fs.readdirSync(this.dataPath);
            
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const filepath = path.join(this.dataPath, file);
                    const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
                    const chatbotId = file.replace('.json', '');
                    this.knowledgeBases.set(chatbotId, data);
                }
            }
            
            console.log(`📥 ${this.knowledgeBases.size} base(s) de conhecimento carregadas`);
        } catch (error) {
            console.error('❌ Erro ao carregar bases de conhecimento:', error);
        }
    }

    /**
     * Salvar base de conhecimento
     */
    saveKnowledgeBase(chatbotId) {
        try {
            const kb = this.knowledgeBases.get(chatbotId);
            
            if (!kb) return;

            const filepath = path.join(this.dataPath, `${chatbotId}.json`);
            fs.writeFileSync(filepath, JSON.stringify(kb, null, 2));
            
            console.log(`💾 Base de conhecimento salva: ${chatbotId}`);
        } catch (error) {
            console.error('❌ Erro ao salvar base de conhecimento:', error);
        }
    }

    /**
     * Inicializar base de conhecimento para um chatbot
     */
    initializeKnowledgeBase(chatbotId, initialData = {}) {
        if (!this.knowledgeBases.has(chatbotId)) {
            this.knowledgeBases.set(chatbotId, {
                chatbotId,
                sources: [],
                faqs: [],
                documents: [],
                manualEntries: [],
                lastUpdated: new Date().toISOString(),
                totalEntries: 0
            });
        }

        // Adicionar dados iniciais se fornecidos
        if (initialData.url) {
            this.addUrlSource(chatbotId, initialData.url, initialData.extractedData);
        }

        this.saveKnowledgeBase(chatbotId);
        return this.knowledgeBases.get(chatbotId);
    }

    /**
     * Adicionar fonte de URL
     */
    addUrlSource(chatbotId, url, extractedData) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            this.initializeKnowledgeBase(chatbotId);
            return this.addUrlSource(chatbotId, url, extractedData);
        }

        const sourceId = crypto.randomBytes(8).toString('hex');
        
        const source = {
            id: sourceId,
            type: 'url',
            url,
            data: extractedData,
            addedAt: new Date().toISOString(),
            lastUpdated: new Date().toISOString(),
            active: true
        };

        kb.sources.push(source);
        kb.totalEntries++;
        kb.lastUpdated = new Date().toISOString();

        this.saveKnowledgeBase(chatbotId);
        
        console.log(`✅ URL adicionada à base de conhecimento: ${url}`);
        
        return source;
    }

    /**
     * Adicionar FAQ
     */
    addFAQ(chatbotId, question, answer, category = 'geral') {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            this.initializeKnowledgeBase(chatbotId);
            return this.addFAQ(chatbotId, question, answer, category);
        }

        const faqId = crypto.randomBytes(8).toString('hex');
        
        const faq = {
            id: faqId,
            question,
            answer,
            category,
            addedAt: new Date().toISOString(),
            active: true,
            hits: 0
        };

        kb.faqs.push(faq);
        kb.totalEntries++;
        kb.lastUpdated = new Date().toISOString();

        this.saveKnowledgeBase(chatbotId);
        
        console.log(`✅ FAQ adicionada: ${question.substring(0, 50)}...`);
        
        return faq;
    }

    /**
     * Adicionar múltiplas FAQs de uma vez
     */
    addMultipleFAQs(chatbotId, faqs) {
        const addedFaqs = [];
        
        for (const faq of faqs) {
            const added = this.addFAQ(
                chatbotId,
                faq.question,
                faq.answer,
                faq.category || 'geral'
            );
            addedFaqs.push(added);
        }

        console.log(`✅ ${addedFaqs.length} FAQs adicionadas`);
        
        return addedFaqs;
    }

    /**
     * Adicionar documento de texto
     */
    addDocument(chatbotId, title, content, metadata = {}) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            this.initializeKnowledgeBase(chatbotId);
            return this.addDocument(chatbotId, title, content, metadata);
        }

        const docId = crypto.randomBytes(8).toString('hex');
        
        const document = {
            id: docId,
            type: metadata.type || 'text',
            title,
            content,
            metadata,
            addedAt: new Date().toISOString(),
            active: true
        };

        kb.documents.push(document);
        kb.totalEntries++;
        kb.lastUpdated = new Date().toISOString();

        this.saveKnowledgeBase(chatbotId);
        
        console.log(`✅ Documento adicionado: ${title}`);
        
        return document;
    }

    /**
     * Adicionar entrada manual
     */
    addManualEntry(chatbotId, title, content, tags = []) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            this.initializeKnowledgeBase(chatbotId);
            return this.addManualEntry(chatbotId, title, content, tags);
        }

        const entryId = crypto.randomBytes(8).toString('hex');
        
        const entry = {
            id: entryId,
            title,
            content,
            tags,
            addedAt: new Date().toISOString(),
            active: true
        };

        kb.manualEntries.push(entry);
        kb.totalEntries++;
        kb.lastUpdated = new Date().toISOString();

        this.saveKnowledgeBase(chatbotId);
        
        console.log(`✅ Entrada manual adicionada: ${title}`);
        
        return entry;
    }

    /**
     * Processar arquivo CSV de FAQs
     */
    parseFAQsFromCSV(csvContent) {
        const lines = csvContent.split('\n');
        const faqs = [];

        // Pular cabeçalho
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            
            if (!line) continue;

            // Parse CSV simples (assumindo formato: pergunta,resposta,categoria)
            const parts = line.split(',');
            
            if (parts.length >= 2) {
                faqs.push({
                    question: parts[0].trim().replace(/^"|"$/g, ''),
                    answer: parts[1].trim().replace(/^"|"$/g, ''),
                    category: parts[2] ? parts[2].trim().replace(/^"|"$/g, '') : 'geral'
                });
            }
        }

        return faqs;
    }

    /**
     * Processar arquivo JSON de FAQs
     */
    parseFAQsFromJSON(jsonContent) {
        try {
            const data = JSON.parse(jsonContent);
            
            if (Array.isArray(data)) {
                return data;
            } else if (data.faqs && Array.isArray(data.faqs)) {
                return data.faqs;
            }
            
            return [];
        } catch (error) {
            console.error('❌ Erro ao parsear JSON:', error);
            return [];
        }
    }

    /**
     * Buscar na base de conhecimento
     */
    search(chatbotId, query, limit = 5) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            return [];
        }

        const results = [];
        const queryLower = query.toLowerCase();

        // Buscar em FAQs
        for (const faq of kb.faqs) {
            if (!faq.active) continue;

            const questionLower = faq.question.toLowerCase();
            const answerLower = faq.answer.toLowerCase();

            if (questionLower.includes(queryLower) || answerLower.includes(queryLower)) {
                results.push({
                    type: 'faq',
                    score: this.calculateRelevanceScore(queryLower, questionLower),
                    data: faq
                });
            }
        }

        // Buscar em documentos
        for (const doc of kb.documents) {
            if (!doc.active) continue;

            const titleLower = doc.title.toLowerCase();
            const contentLower = doc.content.toLowerCase();

            if (titleLower.includes(queryLower) || contentLower.includes(queryLower)) {
                results.push({
                    type: 'document',
                    score: this.calculateRelevanceScore(queryLower, titleLower + ' ' + contentLower),
                    data: doc
                });
            }
        }

        // Buscar em entradas manuais
        for (const entry of kb.manualEntries) {
            if (!entry.active) continue;

            const titleLower = entry.title.toLowerCase();
            const contentLower = entry.content.toLowerCase();

            if (titleLower.includes(queryLower) || contentLower.includes(queryLower)) {
                results.push({
                    type: 'manual',
                    score: this.calculateRelevanceScore(queryLower, titleLower + ' ' + contentLower),
                    data: entry
                });
            }
        }

        // Ordenar por relevância e limitar resultados
        results.sort((a, b) => b.score - a.score);
        
        return results.slice(0, limit);
    }

    /**
     * Calcular score de relevância (simplificado)
     */
    calculateRelevanceScore(query, text) {
        const queryWords = query.split(/\s+/);
        let score = 0;

        for (const word of queryWords) {
            if (word.length < 3) continue;

            const regex = new RegExp(word, 'gi');
            const matches = text.match(regex);
            
            if (matches) {
                score += matches.length;
            }
        }

        return score;
    }

    /**
     * Obter toda a base de conhecimento
     */
    getKnowledgeBase(chatbotId) {
        return this.knowledgeBases.get(chatbotId) || null;
    }

    /**
     * Compilar contexto para o chatbot
     */
    compileContext(chatbotId, maxLength = 4000) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            return '';
        }

        let context = '';

        // Adicionar FAQs
        if (kb.faqs.length > 0) {
            context += '📋 PERGUNTAS FREQUENTES:\n\n';
            
            for (const faq of kb.faqs.filter(f => f.active)) {
                const entry = `P: ${faq.question}\nR: ${faq.answer}\n\n`;
                
                if (context.length + entry.length > maxLength) break;
                
                context += entry;
            }
        }

        // Adicionar documentos
        if (kb.documents.length > 0 && context.length < maxLength) {
            context += '\n📄 DOCUMENTOS:\n\n';
            
            for (const doc of kb.documents.filter(d => d.active)) {
                const entry = `${doc.title}:\n${doc.content}\n\n`;
                
                if (context.length + entry.length > maxLength) break;
                
                context += entry;
            }
        }

        // Adicionar entradas manuais
        if (kb.manualEntries.length > 0 && context.length < maxLength) {
            context += '\n📝 INFORMAÇÕES ADICIONAIS:\n\n';
            
            for (const entry of kb.manualEntries.filter(e => e.active)) {
                const entryText = `${entry.title}:\n${entry.content}\n\n`;
                
                if (context.length + entryText.length > maxLength) break;
                
                context += entryText;
            }
        }

        // Adicionar dados de URLs
        if (kb.sources.length > 0 && context.length < maxLength) {
            context += '\n🌐 INFORMAÇÕES DO SITE:\n\n';
            
            for (const source of kb.sources.filter(s => s.active && s.type === 'url')) {
                if (source.data && source.data.textos) {
                    const textos = source.data.textos.slice(0, 10).join('\n');
                    
                    if (context.length + textos.length > maxLength) break;
                    
                    context += textos + '\n\n';
                }
            }
        }

        return context.substring(0, maxLength);
    }

    /**
     * Remover entrada
     */
    removeEntry(chatbotId, entryId, entryType) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) return false;

        let removed = false;

        switch (entryType) {
            case 'faq':
                const faqIndex = kb.faqs.findIndex(f => f.id === entryId);
                if (faqIndex !== -1) {
                    kb.faqs.splice(faqIndex, 1);
                    removed = true;
                }
                break;

            case 'document':
                const docIndex = kb.documents.findIndex(d => d.id === entryId);
                if (docIndex !== -1) {
                    kb.documents.splice(docIndex, 1);
                    removed = true;
                }
                break;

            case 'manual':
                const entryIndex = kb.manualEntries.findIndex(e => e.id === entryId);
                if (entryIndex !== -1) {
                    kb.manualEntries.splice(entryIndex, 1);
                    removed = true;
                }
                break;

            case 'source':
                const sourceIndex = kb.sources.findIndex(s => s.id === entryId);
                if (sourceIndex !== -1) {
                    kb.sources.splice(sourceIndex, 1);
                    removed = true;
                }
                break;
        }

        if (removed) {
            kb.totalEntries--;
            kb.lastUpdated = new Date().toISOString();
            this.saveKnowledgeBase(chatbotId);
            console.log(`🗑️ Entrada removida: ${entryId}`);
        }

        return removed;
    }

    /**
     * Obter estatísticas
     */
    getStats(chatbotId) {
        const kb = this.knowledgeBases.get(chatbotId);
        
        if (!kb) {
            return {
                totalEntries: 0,
                sources: 0,
                faqs: 0,
                documents: 0,
                manualEntries: 0
            };
        }

        return {
            totalEntries: kb.totalEntries,
            sources: kb.sources.filter(s => s.active).length,
            faqs: kb.faqs.filter(f => f.active).length,
            documents: kb.documents.filter(d => d.active).length,
            manualEntries: kb.manualEntries.filter(e => e.active).length,
            lastUpdated: kb.lastUpdated
        };
    }
}

// Instância global do gerenciador de conhecimento
const knowledgeBaseManager = new KnowledgeBaseManager();

module.exports = {
    knowledgeBaseManager
};
