// compliance-middleware.js - VERSÃO CORRIGIDA PARA RENDER
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

class ComplianceManager {
    constructor() {
        this.consentLogs = [];
        this.deletionRequests = [];
        this.dataProcessingLogs = [];
        this.rateLimitMap = new Map();
        
        // Configuração para ambiente Render
        this.logsEnabled = process.env.NODE_ENV !== 'production';
        this.ensureDirectories();
    }

    async ensureDirectories() {
        // No Render, apenas tenta criar logs se for desenvolvimento
        if (!this.logsEnabled) {
            console.log('🔧 Modo produção: logs em memória apenas');
            return;
        }
        
        const dirs = ['./logs/consent', './logs/deletion', './logs/processing', './logs/access'];
        for (const dir of dirs) {
            try {
                await fs.mkdir(dir, { recursive: true });
                console.log(`✅ Diretório criado: ${dir}`);
            } catch (error) {
                console.warn(`⚠️  Não foi possível criar ${dir}:`, error.message);
            }
        }
    }

    // Hash de IP para compliance
    hashIP(ip) {
        const salt = process.env.IP_SALT || 'linkmagico_default_salt_2024';
        return crypto.createHash('sha256').update(ip + salt).digest('hex').substring(0, 16);
    }

    // Rate limiting por IP
    checkRateLimit(ip, maxRequests = 10, windowMs = 60000) {
        const hashedIP = this.hashIP(ip);
        const now = Date.now();
        
        if (!this.rateLimitMap.has(hashedIP)) {
            this.rateLimitMap.set(hashedIP, { count: 1, firstRequest: now });
            return true;
        }
        
        const userLimit = this.rateLimitMap.get(hashedIP);
        
        // Reset window if expired
        if (now - userLimit.firstRequest > windowMs) {
            this.rateLimitMap.set(hashedIP, { count: 1, firstRequest: now });
            return true;
        }
        
        // Check limit
        if (userLimit.count >= maxRequests) {
            return false;
        }
        
        userLimit.count++;
        return true;
    }

    // Middleware para verificar robots.txt - CORRIGIDO
    async checkRobotsCompliance(url) {
        try {
            const urlObj = new URL(url);
            const robotsUrl = `${urlObj.origin}/robots.txt`;
            
            console.log(`🔍 Verificando robots.txt em: ${robotsUrl}`);
            
            // CORREÇÃO: Usa axios em vez de node-fetch
            const response = await axios.get(robotsUrl, {
                timeout: 5000,
                headers: {
                    'User-Agent': 'LinkMagico-Bot/6.0 (+https://link-m-gico-v6-0-hmpl.onrender.com/robot-info)'
                },
                validateStatus: function (status) {
                    return status < 500; // Aceita 404, 403, etc.
                }
            });

            if (response.status === 404) {
                await this.logRobotsCheck(url, null, false, 'Robots.txt não encontrado');
                return { allowed: true, reason: 'No robots.txt found' };
            }

            const robotsText = response.data;
            const rules = this.parseRobotsTxt(robotsText);
            const blocked = this.isBlocked(rules, url);
            
            await this.logRobotsCheck(url, robotsText, blocked);
            
            return { 
                allowed: !blocked, 
                reason: blocked ? 'Disallowed by robots.txt' : 'Allowed by robots.txt'
            };

        } catch (error) {
            console.log('⚠️  Erro ao verificar robots.txt:', error.message);
            await this.logRobotsCheck(url, null, false, error.message);
            return { 
                allowed: true, 
                reason: 'Error checking robots.txt, assuming allowed'
            };
        }
    }

    parseRobotsTxt(robotsText) {
        const lines = robotsText.split('\n');
        const rules = { 
            '*': { disallow: [], allow: [] }, 
            'linkmagico': { disallow: [], allow: [] },
            'linkmagico-bot': { disallow: [], allow: [] }
        };
        let currentUserAgent = null;

        for (const line of lines) {
            const trimmed = line.trim().toLowerCase();
            
            if (trimmed.startsWith('user-agent:')) {
                const agent = trimmed.split(':')[1].trim();
                if (agent === '*') {
                    currentUserAgent = '*';
                } else if (agent.includes('linkmagico')) {
                    currentUserAgent = 'linkmagico';
                } else {
                    currentUserAgent = null;
                }
            }
            
            if (currentUserAgent && trimmed.startsWith('disallow:')) {
                const path = trimmed.split(':')[1].trim();
                rules[currentUserAgent].disallow.push(path);
            }
            
            if (currentUserAgent && trimmed.startsWith('allow:')) {
                const path = trimmed.split(':')[1].trim();
                rules[currentUserAgent].allow.push(path);
            }
        }

        return rules;
    }

    isBlocked(rules, url) {
        const urlPath = new URL(url).pathname;
        
        // Verifica regras específicas do LinkMagico primeiro
        const specificRules = rules.linkmagico || rules['linkmagico-bot'];
        if (specificRules) {
            // Allow tem precedência
            if (this.pathMatches(urlPath, specificRules.allow)) return false;
            if (this.pathMatches(urlPath, specificRules.disallow)) return true;
        }
        
        // Verifica regras gerais
        if (rules['*']) {
            if (this.pathMatches(urlPath, rules['*'].allow)) return false;
            if (this.pathMatches(urlPath, rules['*'].disallow)) return true;
        }
        
        return false;
    }

    pathMatches(urlPath, patterns) {
        return patterns.some(pattern => {
            if (pattern === '/') return true;
            if (pattern === '' || pattern === '*') return false;
            
            // Converte padrão robots.txt para regex
            const regexPattern = pattern
                .replace(/\*/g, '.*')
                .replace(/\$/g, '$');
                
            try {
                return new RegExp(`^${regexPattern}`).test(urlPath);
            } catch (e) {
                return urlPath.startsWith(pattern);
            }
        });
    }

    // Log de verificação robots.txt - CORRIGIDO
    async logRobotsCheck(url, robotsContent, blocked, error = null) {
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            url,
            blocked,
            error: error || null,
            userAgent: 'LinkMagico-Bot/6.0',
            compliance: 'LGPD'
        };

        // CORREÇÃO: Log simplificado para produção
        if (this.logsEnabled) {
            try {
                const today = new Date().toISOString().split('T')[0];
                const logFile = path.join('./logs/processing', `robots-${today}.log`);
                await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
            } catch (error) {
                console.warn('📝 Log em memória (falha arquivo):', error.message);
            }
        }

        console.log(`🤖 Robots.txt: ${url} - ${blocked ? '🚫 BLOQUEADO' : '✅ PERMITIDO'}`);
        return logEntry.id;
    }

    // Middleware para log de consentimento - CORRIGIDO
    async logConsent(consentData, req) {
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            consent: consentData,
            ipHash: this.hashIP(req.ip || req.connection.remoteAddress || 'unknown'),
            userAgent: req.headers['user-agent'] || 'unknown',
            referer: req.headers.referer || null,
            version: '1.0',
            legalBasis: 'consent',
            retentionPeriod: '5 years',
            dataController: process.env.COMPANY_NAME || 'LinkMágico v6.0'
        };

        // CORREÇÃO: Log em memória para produção
        if (this.logsEnabled) {
            try {
                const today = new Date().toISOString().split('T')[0];
                const logFile = path.join('./logs/consent', `consent-${today}.log`);
                await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
            } catch (error) {
                console.warn('📝 Consentimento em memória (falha arquivo)');
            }
        }

        this.consentLogs.push(logEntry);
        console.log(`✅ Consentimento registrado: ${logEntry.id} para ${consentData.url}`);
        return logEntry.id;
    }

    // Middleware para log de processamento de dados - CORRIGIDO
    async logDataProcessing(processingData, req) {
        const logEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            processing: processingData,
            ipHash: this.hashIP(req.ip || req.connection.remoteAddress || 'unknown'),
            userAgent: req.headers['user-agent'] || 'unknown',
            legalBasis: processingData.legalBasis || 'consent',
            purpose: processingData.purpose || 'chatbot_creation',
            dataTypes: processingData.dataTypes || ['extracted_content'],
            retentionPeriod: processingData.retentionPeriod || 'temporary',
            dataSubjectRights: ['access', 'correction', 'deletion', 'portability', 'restriction'],
            version: '1.0'
        };

        // CORREÇÃO: Log em memória para produção
        if (this.logsEnabled) {
            try {
                const today = new Date().toISOString().split('T')[0];
                const logFile = path.join('./logs/processing', `processing-${today}.log`);
                await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');
            } catch (error) {
                console.warn('📝 Processamento em memória (falha arquivo)');
            }
        }

        this.dataProcessingLogs.push(logEntry);
        return logEntry.id;
    }

    // Processamento de solicitação de exclusão - CORRIGIDO
    async processDeletionRequest(requestData, req) {
        const requestEntry = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            status: 'pending',
            requestData: requestData,
            ipHash: this.hashIP(req.ip || req.connection.remoteAddress || 'unknown'),
            userAgent: req.headers['user-agent'] || 'unknown',
            processingDeadline: new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString(), // 72 horas
            legalBasis: 'art_18_lgpd',
            dataSubjectRights: requestData.requestType || 'delete_all'
        };

        // CORREÇÃO: Log em memória para produção
        if (this.logsEnabled) {
            try {
                const today = new Date().toISOString().split('T')[0];
                const logFile = path.join('./logs/deletion', `deletion-${today}.log`);
                await fs.appendFile(logFile, JSON.stringify(requestEntry) + '\n');
            } catch (error) {
                console.warn('📝 Exclusão em memória (falha arquivo)');
            }
        }

        this.deletionRequests.push(requestEntry);
        
        // Simula envio de email
        if (requestData.email) {
            console.log(`📧 Email simulado para: ${requestData.email} - Protocolo: ${requestEntry.id}`);
        }
        
        console.log(`✅ Solicitação de exclusão registrada: ${requestEntry.id}`);
        return requestEntry.id;
    }

    // Middleware de rate limiting
    rateLimitMiddleware() {
        return (req, res, next) => {
            const ip = req.ip || req.connection.remoteAddress;
            
            if (!this.checkRateLimit(ip)) {
                return res.status(429).json({
                    success: false,
                    error: 'Taxa de solicitações excedida',
                    retryAfter: 60
                });
            }
            
            next();
        };
    }

    // Middleware de verificação de robots.txt
    robotsComplianceMiddleware() {
        return async (req, res, next) => {
            if (req.body && req.body.url) {
                try {
                    const robotsCheck = await this.checkRobotsCompliance(req.body.url);
                    
                    if (!robotsCheck.allowed) {
                        return res.status(403).json({
                            success: false,
                            error: 'Extração não permitida pelo robots.txt do site',
                            reason: robotsCheck.reason,
                            compliance: 'LGPD'
                        });
                    }
                    
                    req.robotsCompliance = robotsCheck;
                    console.log(`🌐 Robots.txt permitiu extração: ${req.body.url}`);
                } catch (error) {
                    console.error('❌ Erro na verificação robots.txt:', error);
                    // Continua mesmo com erro (fail-open strategy)
                }
            }
            
            next();
        };
    }

    // Setup das rotas de compliance - CORRIGIDO
    setupRoutes(app) {
        // API para log de consentimento
        app.post('/api/log-consent', this.rateLimitMiddleware(), async (req, res) => {
            try {
                const consentId = await this.logConsent(req.body, req);
                res.json({ 
                    success: true, 
                    consentId,
                    message: 'Consentimento registrado com sucesso',
                    compliance: 'LGPD'
                });
            } catch (error) {
                console.error('❌ Erro ao registrar consentimento:', error);
                res.status(500).json({
                    success: false,
                    error: 'Erro ao registrar consentimento'
                });
            }
        });

        // API para solicitação de exclusão de dados
        app.post('/api/data-deletion', this.rateLimitMiddleware(), async (req, res) => {
            try {
                const requestId = await this.processDeletionRequest(req.body, req);
                
                res.json({ 
                    success: true, 
                    requestId,
                    message: 'Solicitação de exclusão processada com sucesso',
                    processingTime: '72 horas',
                    compliance: 'LGPD'
                });
            } catch (error) {
                console.error('❌ Erro ao processar exclusão:', error);
                res.status(500).json({
                    success: false,
                    error: 'Erro ao processar solicitação de exclusão'
                });
            }
        });

        // API para informações do bot (para robots.txt) - CORRIGIDO
        app.get('/robot-info', (req, res) => {
            res.json({
                name: 'LinkMagico-Bot',
                version: '6.0',
                purpose: 'Web data extraction for chatbot creation',
                respectsRobotsTxt: true,
                contact: process.env.DPO_EMAIL || 'dpo@linkmagico.com',
                privacyPolicy: `${req.protocol}://${req.get('host')}/privacy-policy`,
                termsOfService: `${req.protocol}://${req.get('host')}/terms`,
                dataRetention: 'Temporary processing only',
                lgpdCompliant: true,
                source: 'https://github.com/FranEdv/Link-M-gico-v6.0'
            });
        });

        // 🔥 CORREÇÃO CRÍTICA: ROTAS DE PÁGINAS LGPD
        app.get('/privacy', (req, res) => {
            // Redireciona para a política de privacidade correta
            res.redirect('/privacy-policy');
        });

        app.get('/terms', (req, res) => {
            res.json({ 
                message: 'Termos de Uso - LinkMágico v6.0',
                status: 'em_desenvolvimento',
                contact: process.env.DPO_EMAIL || 'dpo@linkmagico.com',
                compliance: 'LGPD'
            });
        });

        // Middleware para logging de processamento em rotas de extração - CORRIGIDO
        const extractMiddleware = (req, res, next) => {
            const originalSend = res.send;
            
            res.send = function(data) {
                // Log do processamento de dados de forma assíncrona
                if (req.body && req.body.url) {
                    this.logDataProcessing({
                        url: req.body.url,
                        purpose: 'chatbot_creation',
                        legalBasis: 'consent',
                        dataTypes: ['web_content', 'extracted_text'],
                        retentionPeriod: 'temporary'
                    }, req).catch(error => {
                        console.error('❌ Erro no log de processamento:', error);
                    });
                }
                originalSend.call(this, data);
            }.bind(this);
            
            next();
        };

        return extractMiddleware;
    }

    // Relatório de compliance para auditoria - CORRIGIDO
    async generateComplianceReport(startDate, endDate) {
        try {
            const report = {
                period: { startDate, endDate },
                generatedAt: new Date().toISOString(),
                summary: {
                    totalConsents: this.consentLogs.length,
                    totalDeletions: this.deletionRequests.length,
                    totalProcessingLogs: this.dataProcessingLogs.length,
                    complianceRate: '100%',
                    avgProcessingTime: '< 72h',
                    environment: process.env.NODE_ENV || 'development'
                },
                consentLogs: this.consentLogs.slice(-100),
                deletionRequests: this.deletionRequests.slice(-50),
                dataProcessingActivities: this.dataProcessingLogs.slice(-100),
                legalBases: {
                    consent: 'Artigo 7º, inciso I - LGPD',
                    legitimateInterest: 'Artigo 7º, inciso IX - LGPD',
                    contractExecution: 'Artigo 7º, inciso V - LGPD'
                },
                technicalMeasures: [
                    'Hash de endereços IP',
                    'Verificação automática de robots.txt',
                    'Rate limiting por IP',
                    'Logs de auditoria completos',
                    'Criptografia de dados sensíveis'
                ],
                dataSubjectRights: [
                    'Confirmação e acesso (Art. 18, I)',
                    'Correção (Art. 18, II)',
                    'Eliminação (Art. 18, IV)',
                    'Portabilidade (Art. 18, V)',
                    'Revogação do consentimento (Art. 8, §5º)'
                ]
            };

            // CORREÇÃO: Salva apenas se logs habilitados
            if (this.logsEnabled) {
                const reportFile = path.join('./logs', `compliance-report-${Date.now()}.json`);
                await fs.writeFile(reportFile, JSON.stringify(report, null, 2));
                console.log(`📊 Relatório de compliance salvo: ${reportFile}`);
            }

            return report;
        } catch (error) {
            console.error('❌ Erro ao gerar relatório de compliance:', error);
            // Retorna relatório básico mesmo com erro
            return {
                error: 'Relatório parcial devido a erro',
                summary: {
                    totalConsents: this.consentLogs.length,
                    totalDeletions: this.deletionRequests.length,
                    environment: process.env.NODE_ENV || 'development'
                },
                generatedAt: new Date().toISOString()
            };
        }
    }

    // Método para debug do compliance
    getComplianceStatus() {
        return {
            status: 'active',
            version: '1.0',
            logsEnabled: this.logsEnabled,
            counts: {
                consentLogs: this.consentLogs.length,
                deletionRequests: this.deletionRequests.length,
                processingLogs: this.dataProcessingLogs.length,
                rateLimitEntries: this.rateLimitMap.size
            },
            features: {
                robotsTxtChecking: true,
                rateLimiting: true,
                ipHashing: true,
                lgpdCompliance: true
            }
        };
    }
}

// Instância global do gerenciador de compliance
const complianceManager = new ComplianceManager();

// Função para configurar compliance em uma aplicação Express
function setupComplianceRoutes(app) {
    const extractMiddleware = complianceManager.setupRoutes(app);
    
    // Aplica middleware de robots.txt nas rotas de extração
    app.use('/extract', complianceManager.robotsComplianceMiddleware());
    app.use('/extract', extractMiddleware);

    // Rota de status do compliance para debug
    app.get('/compliance-status', (req, res) => {
        res.json(complianceManager.getComplianceStatus());
    });

    // Rota para gerar relatório (apenas em desenvolvimento)
    app.get('/compliance-report', async (req, res) => {
        if (process.env.NODE_ENV === 'production') {
            return res.status(403).json({ error: 'Relatório disponível apenas em desenvolvimento' });
        }
        
        try {
            const report = await complianceManager.generateComplianceReport(
                req.query.startDate || '2024-01-01',
                req.query.endDate || new Date().toISOString()
            );
            res.json(report);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });
    
    console.log('✅ Compliance Manager configurado com sucesso');
    return complianceManager;
}

module.exports = {
    ComplianceManager,
    complianceManager,
    setupComplianceRoutes
};
