/**
 * 🚀 SCRIPT DE INICIALIZAÇÃO - Link Mágico Melhorado
 * Inicializa todos os sistemas e módulos
 */

const { initializeDatabase } = require('./database');
const { initializeCache } = require('./cache');
const { analyticsManager } = require('./analytics');

/**
 * Inicializar todos os sistemas
 */
async function initialize() {
    console.log('🚀 Iniciando Link Mágico Melhorado...\n');

    try {
        // 1. Inicializar banco de dados
        console.log('📊 Inicializando banco de dados...');
        await initializeDatabase();
        console.log('✅ Banco de dados pronto\n');

        // 2. Inicializar cache
        console.log('💾 Inicializando sistema de cache...');
        await initializeCache();
        console.log('✅ Cache pronto\n');

        // 3. Limpar analytics antigos (se configurado)
        const retentionDays = parseInt(process.env.ANALYTICS_RETENTION_DAYS || '90');
        console.log(`🧹 Limpando analytics com mais de ${retentionDays} dias...`);
        await analyticsManager.cleanOldAnalytics(retentionDays);
        console.log('✅ Analytics limpo\n');

        console.log('✅ Todos os sistemas inicializados com sucesso!\n');
        console.log('═'.repeat(60));
        console.log('🎯 Link Mágico Melhorado - Pronto para uso!');
        console.log('═'.repeat(60));
        console.log('');
        
        return true;
    } catch (error) {
        console.error('❌ Erro na inicialização:', error);
        console.error('\n⚠️  Alguns sistemas podem não estar disponíveis');
        console.error('   Verifique as variáveis de ambiente e tente novamente\n');
        
        // Não falhar completamente, permitir que o servidor inicie
        return false;
    }
}

module.exports = { initialize };
