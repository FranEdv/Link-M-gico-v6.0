// admin-keys.js - Script de Gerenciamento de API Keys LinkMágico v6.0
// Execute: node admin-keys.js

const LinkMagicoAuth = require('./auth');

// Inicializar sistema
const auth = new LinkMagicoAuth();

// Cores para console
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

function colorLog(color, message) {
    console.log(color + message + colors.reset);
}

// Função principal
async function main() {
    colorLog(colors.cyan + colors.bright, '\n🔐 LinkMágico v6.0 - Gerenciador de API Keys\n');
    
    const args = process.argv.slice(2);
    const command = args[0];
    
    switch (command) {
        case 'generate':
        case 'create':
            await generateApiKey(args);
            break;
            
        case 'list':
        case 'ls':
            listApiKeys();
            break;
            
        case 'activate':
            await manageApiKey(args[1], 'activate');
            break;
            
        case 'deactivate':
            await manageApiKey(args[1], 'deactivate');
            break;
            
        case 'delete':
        case 'remove':
            await manageApiKey(args[1], 'delete');
            break;
            
        case 'report':
            generateReport(args[1]);
            break;
            
        case 'init':
            await initializeSystem();
            break;
            
        case 'help':
        case '--help':
        case '-h':
        default:
            showHelp();
            break;
    }
}

// Gerar nova API Key
async function generateApiKey(args) {
    const clientName = args[1];
    const plan = args[2] || 'basic';
    
    if (!clientName) {
        colorLog(colors.red, '❌ Erro: Nome do cliente é obrigatório');
        colorLog(colors.yellow, 'Uso: node admin-keys.js generate "Nome do Cliente" [plano]');
        return;
    }
    
    try {
        const keyData = auth.generateApiKey(clientName, plan);
        
        colorLog(colors.green + colors.bright, '\n✅ API Key gerada com sucesso!');
        console.log('\n📋 Detalhes da API Key:');
        console.log('┌─────────────────────────────────────────────────────────────────┐');
        console.log(`│ Cliente: ${clientName.padEnd(54)} │`);
        console.log(`│ Plano: ${plan.toUpperCase().padEnd(56)} │`);
        console.log(`│ API Key: ${keyData.key.padEnd(52)} │`);
        console.log(`│ Criada em: ${new Date(keyData.created).toLocaleString('pt-BR').padEnd(48)} │`);
        console.log('├─────────────────────────────────────────────────────────────────┤');
        console.log('│ LIMITES DO PLANO:                                               │');
        console.log(`│ • Requisições/dia: ${keyData.limits.dailyRequests.toString().padEnd(42)} │`);
        console.log(`│ • Requisições/mês: ${keyData.limits.monthlyRequests.toString().padEnd(42)} │`);
        console.log(`│ • Chatbots/dia: ${keyData.limits.chatbotsPerDay.toString().padEnd(45)} │`);
        console.log(`│ • Extrações/dia: ${keyData.limits.extractionsPerDay.toString().padEnd(44)} │`);
        console.log('└─────────────────────────────────────────────────────────────────┘');
        
        colorLog(colors.cyan, '\n📧 Envie esta API Key para o cliente de forma segura!');
        colorLog(colors.yellow, '⚠️  Mantenha um registro seguro desta chave - ela não será exibida novamente.');
        
    } catch (error) {
        colorLog(colors.red, '❌ Erro ao gerar API Key: ' + error.message);
    }
}

// Listar API Keys
function listApiKeys() {
    try {
        const keys = auth.listApiKeys();
        const report = auth.generateReport();
        
        colorLog(colors.cyan + colors.bright, '\n📊 Relatório de API Keys\n');
        
        console.log('📈 RESUMO GERAL:');
        console.log('┌─────────────────────────────────────────────────────┐');
        console.log(`│ Total de Keys: ${report.totalKeys.toString().padEnd(37)} │`);
        console.log(`│ Keys Ativas: ${report.activeKeys.toString().padEnd(39)} │`);
        console.log(`│ Total de Requisições: ${report.totalRequests.toString().padEnd(28)} │`);
        console.log('├─────────────────────────────────────────────────────┤');
        console.log('│ DISTRIBUIÇÃO POR PLANOS:                           │');
        console.log(`│ • Basic: ${report.plansDistribution.basic.toString().padEnd(43)} │`);
        console.log(`│ • Pro: ${report.plansDistribution.pro.toString().padEnd(45)} │`);
        console.log(`│ • Enterprise: ${report.plansDistribution.enterprise.toString().padEnd(36)} │`);
        console.log('└─────────────────────────────────────────────────────┘');
        
        if (keys.length === 0) {
            colorLog(colors.yellow, '\n⚠️  Nenhuma API Key encontrada. Use "generate" para criar a primeira.');
            return;
        }
        
        colorLog(colors.blue + colors.bright, '\n🔑 LISTA DE API KEYS:\n');
        
        keys.forEach((key, index) => {
            const status = key.active ? 
                colors.green + '🟢 ATIVA' + colors.reset : 
                colors.red + '🔴 INATIVA' + colors.reset;
            
            const planColor = key.plan === 'enterprise' ? colors.magenta : 
                             key.plan === 'pro' ? colors.blue : colors.cyan;
            
            console.log(`${index + 1}. ${key.client}`);
            console.log(`   Key: ${key.key}`);
            console.log(`   Status: ${status}`);
            console.log(`   Plano: ${planColor}${key.plan.toUpperCase()}${colors.reset}`);
            console.log(`   Criada: ${new Date(key.created).toLocaleDateString('pt-BR')}`);
            console.log(`   Uso: ${key.usage.requests} requisições | ${key.usage.chatbots} chatbots | ${key.usage.extractions} extrações`);
            if (key.usage.lastUsed) {
                console.log(`   Último uso: ${new Date(key.usage.lastUsed).toLocaleString('pt-BR')}`);
            }
            console.log('');
        });
        
    } catch (error) {
        colorLog(colors.red, '❌ Erro ao listar API Keys: ' + error.message);
    }
}

// Gerenciar API Key (ativar/desativar/deletar)
async function manageApiKey(apiKey, action) {
    if (!apiKey) {
        colorLog(colors.red, '❌ Erro: API Key é obrigatória');
        colorLog(colors.yellow, `Uso: node admin-keys.js ${action} "lm_xxxxx..."`);
        return;
    }
    
    try {
        let result = false;
        let actionText = '';
        
        switch (action) {
            case 'activate':
                result = auth.activateApiKey(apiKey);
                actionText = 'ativada';
                break;
            case 'deactivate':
                result = auth.deactivateApiKey(apiKey);
                actionText = 'desativada';
                break;
            case 'delete':
                if (confirm(`⚠️  Tem certeza que deseja DELETAR permanentemente a API Key ${apiKey}?`)) {
                    result = auth.deleteApiKey(apiKey);
                    actionText = 'deletada permanentemente';
                } else {
                    colorLog(colors.yellow, '⚠️  Operação cancelada.');
                    return;
                }
                break;
        }
        
        if (result) {
            colorLog(colors.green, `✅ API Key ${actionText} com sucesso!`);
        } else {
            colorLog(colors.red, '❌ API Key não encontrada.');
        }
        
    } catch (error) {
        colorLog(colors.red, `❌ Erro ao ${action} API Key: ` + error.message);
    }
}

// Gerar relatório de uma API Key específica
function generateReport(apiKey) {
    if (!apiKey) {
        colorLog(colors.red, '❌ Erro: API Key é obrigatória para o relatório');
        colorLog(colors.yellow, 'Uso: node admin-keys.js report "lm_xxxxx..."');
        return;
    }
    
    try {
        const report = auth.generateReport(apiKey);
        
        if (!report.client) {
            colorLog(colors.red, '❌ API Key não encontrada.');
            return;
        }
        
        colorLog(colors.cyan + colors.bright, '\n📊 Relatório Detalhado da API Key\n');
        
        const status = report.active ? 
            colors.green + '🟢 ATIVA' + colors.reset : 
            colors.red + '🔴 INATIVA' + colors.reset;
        
        console.log('📋 INFORMAÇÕES GERAIS:');
        console.log('┌─────────────────────────────────────────────────────────────────┐');
        console.log(`│ Cliente: ${report.client.padEnd(54)} │`);
        console.log(`│ Plano: ${report.plan.toUpperCase().padEnd(56)} │`);
        console.log(`│ Status: ${status}                                        │`);
        console.log(`│ API Key: ${report.key.padEnd(52)} │`);
        console.log('├─────────────────────────────────────────────────────────────────┤');
        console.log('│ USO GERAL:                                                      │');
        console.log(`│ • Total de requisições: ${report.usage.requests.toString().padEnd(38)} │`);
        console.log(`│ • Chatbots criados: ${report.usage.chatbots.toString().padEnd(42)} │`);
        console.log(`│ • Extrações realizadas: ${report.usage.extractions.toString().padEnd(38)} │`);
        if (report.usage.lastUsed) {
            console.log(`│ • Último uso: ${new Date(report.usage.lastUsed).toLocaleString('pt-BR').padEnd(46)} │`);
        }
        console.log('├─────────────────────────────────────────────────────────────────┤');
        console.log('│ LIMITES E USO ATUAL:                                           │');
        console.log(`│ • Limite diário: ${report.limits.dailyRequests.toString().padEnd(45)} │`);
        console.log(`│ • Uso hoje: ${report.currentUsage?.daily?.requests || 0} requisições                              │`);
        console.log(`│ • Limite mensal: ${report.limits.monthlyRequests.toString().padEnd(44)} │`);
        console.log(`│ • Uso este mês: ${report.currentUsage?.monthly?.requests || 0} requisições                         │`);
        console.log('└─────────────────────────────────────────────────────────────────┘');
        
        // Calcular percentual de uso
        const dailyUsage = report.currentUsage?.daily?.requests || 0;
        const monthlyUsage = report.currentUsage?.monthly?.requests || 0;
        const dailyPercent = Math.round((dailyUsage / report.limits.dailyRequests) * 100);
        const monthlyPercent = Math.round((monthlyUsage / report.limits.monthlyRequests) * 100);
        
        colorLog(colors.blue, '\n📈 ANÁLISE DE USO:');
        console.log(`• Uso diário: ${dailyPercent}% do limite`);
        console.log(`• Uso mensal: ${monthlyPercent}% do limite`);
        
        if (dailyPercent > 80) {
            colorLog(colors.red, '⚠️  ATENÇÃO: Uso diário próximo do limite!');
        } else if (dailyPercent > 60) {
            colorLog(colors.yellow, '⚠️  Uso diário moderado.');
        } else {
            colorLog(colors.green, '✅ Uso diário dentro do esperado.');
        }
        
    } catch (error) {
        colorLog(colors.red, '❌ Erro ao gerar relatório: ' + error.message);
    }
}

// Inicializar sistema (criar primeira API Key)
async function initializeSystem() {
    colorLog(colors.cyan + colors.bright, '\n🚀 Inicializando LinkMágico v6.0 Comercial\n');
    
    console.log('Este assistente criará sua primeira API Key para começar a usar o sistema.');
    console.log('');
    
    const clientName = await prompt('Nome do cliente/empresa: ');
    if (!clientName) {
        colorLog(colors.red, '❌ Nome é obrigatório.');
        return;
    }
    
    console.log('\nEscolha o plano:');
    console.log('1. Basic (100 req/dia, 2000 req/mês)');
    console.log('2. Pro (500 req/dia, 10000 req/mês)');
    console.log('3. Enterprise (2000 req/dia, 50000 req/mês)');
    
    const planChoice = await prompt('Digite o número do plano (1-3): ');
    const planMap = { '1': 'basic', '2': 'pro', '3': 'enterprise' };
    const plan = planMap[planChoice] || 'basic';
    
    try {
        const keyData = auth.generateApiKey(clientName, plan);
        
        colorLog(colors.green + colors.bright, '\n🎉 LinkMágico v6.0 inicializado com sucesso!\n');
        
        console.log('📋 SUA PRIMEIRA API KEY:');
        console.log('┌─────────────────────────────────────────────────────────────────┐');
        console.log(`│ ${keyData.key.padEnd(63)} │`);
        console.log('└─────────────────────────────────────────────────────────────────┘');
        
        colorLog(colors.cyan, '\n🔗 Para usar no frontend, adicione esta key no localStorage:');
        console.log(`localStorage.setItem('linkmagico_api_key', '${keyData.key}');`);
        
        colorLog(colors.yellow, '\n⚠️  IMPORTANTE:');
        console.log('1. Guarde esta API Key em local seguro');
        console.log('2. Não compartilhe publicamente');
        console.log('3. Use apenas em aplicações autorizadas');
        
        colorLog(colors.green, '\n✅ Sistema pronto para uso!');
        
    } catch (error) {
        colorLog(colors.red, '❌ Erro na inicialização: ' + error.message);
    }
}

// Função de confirmação simples
function confirm(message) {
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    return new Promise((resolve) => {
        readline.question(message + ' (s/n): ', (answer) => {
            readline.close();
            resolve(answer.toLowerCase() === 's' || answer.toLowerCase() === 'sim');
        });
    });
}

// Função de prompt simples
function prompt(message) {
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    return new Promise((resolve) => {
        readline.question(message, (answer) => {
            readline.close();
            resolve(answer.trim());
        });
    });
}

// Mostrar ajuda
function showHelp() {
    colorLog(colors.cyan + colors.bright, '\n🔐 LinkMágico v6.0 - Gerenciador de API Keys\n');
    
    console.log('COMANDOS DISPONÍVEIS:\n');
    
    console.log(colors.green + 'Gerenciamento:' + colors.reset);
    console.log('  init                              Inicializar sistema (primeira API Key)');
    console.log('  generate "Cliente" [plano]        Gerar nova API Key');
    console.log('  list                              Listar todas as API Keys');
    console.log('  report "api_key"                  Relatório detalhado de uma key');
    console.log('');
    
    console.log(colors.yellow + 'Controle:' + colors.reset);
    console.log('  activate "api_key"                Ativar API Key');
    console.log('  deactivate "api_key"              Desativar API Key');
    console.log('  delete "api_key"                  Deletar API Key permanentemente');
    console.log('');
    
    console.log(colors.blue + 'Exemplos:' + colors.reset);
    console.log('  node admin-keys.js init');
    console.log('  node admin-keys.js generate "João Silva" pro');
    console.log('  node admin-keys.js list');
    console.log('  node admin-keys.js report lm_xxxxx...');
    console.log('  node admin-keys.js deactivate lm_xxxxx...');
    console.log('');
    
    console.log(colors.magenta + 'Planos disponíveis:' + colors.reset);
    console.log('  basic      - 100 req/dia, 2000 req/mês');
    console.log('  pro        - 500 req/dia, 10000 req/mês');
    console.log('  enterprise - 2000 req/dia, 50000 req/mês');
    console.log('');
}

// Executar
if (require.main === module) {
    main().catch(error => {
        colorLog(colors.red, '❌ Erro fatal: ' + error.message);
        process.exit(1);
    });
}

module.exports = {
    main,
    generateApiKey,
    listApiKeys,
    manageApiKey,
    generateReport,
    initializeSystem
};