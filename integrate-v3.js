const fs = require('fs');

// Ler o server.js atual
let serverCode = fs.readFileSync('server.js', 'utf8');

// 1. Adicionar imports das novas integrações (depois dos imports existentes)
const newImports = `
// ===== NOVAS INTEGRAÇÕES V3.0 =====
const { gmailManager } = require('./gmail-integration');
const { whatsappManager } = require('./whatsapp-integration');
const { chatgptManager } = require('./chatgpt-integration');
const { crmIntegrations } = require('./crm-integrations');
const { whitelabelManager } = require('./whitelabel');
const { structuredLeadsManager } = require('./structured-leads');
console.log('✅ Módulos V3.0 carregados');
`;

// Encontrar onde inserir (depois do último require antes de console.log)
const insertAfter = "console.log('✅ Módulos de melhorias carregados');";
if (serverCode.includes(insertAfter)) {
    serverCode = serverCode.replace(insertAfter, insertAfter + newImports);
} else {
    // Se não encontrar, adiciona depois do último require
    const lastRequire = serverCode.lastIndexOf("require(");
    const nextLine = serverCode.indexOf('\n', lastRequire);
    serverCode = serverCode.slice(0, nextLine + 1) + newImports + serverCode.slice(nextLine + 1);
}

// 2. Adicionar rotas das novas integrações (antes do app.listen)
const newRoutes = `

// ===== ROTAS DAS NOVAS INTEGRAÇÕES V3.0 =====

// Gmail Integration
app.post('/api/gmail/send', async (req, res) => {
    try {
        const { to, subject, html, text } = req.body;
        const result = await gmailManager.sendEmail({ to, subject, html, text });
        res.json({ success: true, result });
    } catch (error) {
        logger.error('Erro ao enviar email:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/gmail/status', (req, res) => {
    const status = gmailManager.getStatus();
    res.json(status);
});

// WhatsApp Integration
app.post('/api/whatsapp/send', async (req, res) => {
    try {
        const { to, message } = req.body;
        const result = await whatsappManager.sendMessage(to, message);
        res.json({ success: true, result });
    } catch (error) {
        logger.error('Erro ao enviar WhatsApp:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/whatsapp/status', (req, res) => {
    const status = whatsappManager.getStatus();
    res.json(status);
});

// ChatGPT Integration
app.post('/api/chatgpt/generate', async (req, res) => {
    try {
        const { prompt, model, pageContent } = req.body;
        const result = await chatgptManager.generateResponse(prompt, pageContent, model);
        res.json({ success: true, result });
    } catch (error) {
        logger.error('Erro ao gerar resposta ChatGPT:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/chatgpt/status', (req, res) => {
    const status = chatgptManager.getStatus();
    res.json(status);
});

app.get('/api/chatgpt/models', (req, res) => {
    const models = chatgptManager.getAvailableModels();
    res.json(models);
});

// Whitelabel System
app.post('/api/whitelabel/:chatbotId', async (req, res) => {
    try {
        const { chatbotId } = req.params;
        const config = req.body;
        await whitelabelManager.saveConfig(chatbotId, config);
        res.json({ success: true, config });
    } catch (error) {
        logger.error('Erro ao salvar config whitelabel:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/whitelabel/:chatbotId', async (req, res) => {
    try {
        const { chatbotId } = req.params;
        const config = await whitelabelManager.getConfig(chatbotId);
        res.json({ success: true, config });
    } catch (error) {
        logger.error('Erro ao buscar config whitelabel:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Structured Leads
app.post('/api/leads/structured', async (req, res) => {
    try {
        const { chatbotId, leadData, metadata } = req.body;
        const lead = await structuredLeadsManager.saveLead(chatbotId, leadData, metadata);
        
        // Enviar notificações
        if (process.env.GMAIL_USER) {
            await gmailManager.sendLeadNotification(lead);
        }
        if (process.env.WHATSAPP_PROVIDER) {
            await whatsappManager.sendLeadNotification(lead);
        }
        
        res.json({ success: true, lead });
    } catch (error) {
        logger.error('Erro ao salvar lead estruturado:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/leads/structured/:chatbotId', async (req, res) => {
    try {
        const { chatbotId } = req.params;
        const { status, limit, offset } = req.query;
        const leads = await structuredLeadsManager.getLeads(chatbotId, { status, limit, offset });
        res.json({ success: true, leads });
    } catch (error) {
        logger.error('Erro ao buscar leads:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/leads/export/:chatbotId', async (req, res) => {
    try {
        const { chatbotId } = req.params;
        const csv = await structuredLeadsManager.exportToCSV(chatbotId);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', \`attachment; filename="leads-\${chatbotId}.csv"\`);
        res.send(csv);
    } catch (error) {
        logger.error('Erro ao exportar leads:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/leads/stats/:chatbotId', async (req, res) => {
    try {
        const { chatbotId } = req.params;
        const stats = await structuredLeadsManager.getStats(chatbotId);
        res.json({ success: true, stats });
    } catch (error) {
        logger.error('Erro ao buscar estatísticas:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// CRM Integrations (documentação)
app.get('/api/crm/templates', (req, res) => {
    const templates = crmIntegrations.getAllTemplates();
    res.json({ success: true, templates });
});

app.get('/api/crm/templates/:crm', (req, res) => {
    const { crm } = req.params;
    const template = crmIntegrations.getTemplate(crm);
    if (template) {
        res.json({ success: true, template });
    } else {
        res.status(404).json({ success: false, error: 'CRM não encontrado' });
    }
});

console.log('✅ Rotas V3.0 configuradas');
`;

// Encontrar onde inserir (antes do app.listen)
const listenPattern = /app\.listen\(PORT/;
const listenMatch = serverCode.match(listenPattern);
if (listenMatch) {
    const listenIndex = serverCode.indexOf(listenMatch[0]);
    serverCode = serverCode.slice(0, listenIndex) + newRoutes + '\n' + serverCode.slice(listenIndex);
} else {
    // Se não encontrar, adiciona no final
    serverCode += newRoutes;
}

// Salvar o server.js atualizado
fs.writeFileSync('server.js', serverCode, 'utf8');

console.log('✅ server.js atualizado com sucesso!');
console.log('📊 Tamanho final:', serverCode.length, 'caracteres');
console.log('📝 Total de linhas:', serverCode.split('\n').length);
