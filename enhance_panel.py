#!/usr/bin/env python3
"""
Script para adicionar novos sistemas ao painel do Link Mágico
sem quebrar funcionalidades existentes
"""

def add_new_sections():
    # Ler o HTML original
    with open('public/index_app.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    # Encontrar onde inserir (antes do </body>)
    insert_pos = html.rfind('</body>')
    
    if insert_pos == -1:
        print("❌ Não encontrou </body>")
        return False
    
    # Novo HTML para adicionar
    new_html = '''
    
    <!-- ===== NOVOS SISTEMAS - LINK MÁGICO V2.0 ===== -->
    <div id="newSystemsPanel" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.9); z-index:9999; overflow-y:auto;">
        <div style="max-width:1400px; margin:2rem auto; padding:2rem;">
            <button onclick="closeNewSystems()" style="position:fixed; top:20px; right:20px; background:#ef4444; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600; z-index:10000;">
                <i class="fas fa-times"></i> Fechar
            </button>
            
            <h1 style="color:#60a5fa; font-size:2rem; margin-bottom:2rem; text-align:center;">
                🚀 Sistemas Avançados - Link Mágico V2.0
            </h1>
            
            <!-- Tabs -->
            <div class="new-tabs" style="display:flex; gap:1rem; margin-bottom:2rem; flex-wrap:wrap; justify-content:center;">
                <button class="new-tab active" onclick="showNewTab('analytics')" style="background:#3b82f6; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600;">
                    📊 Analytics
                </button>
                <button class="new-tab" onclick="showNewTab('webhooks')" style="background:#334155; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600;">
                    🔗 Webhooks
                </button>
                <button class="new-tab" onclick="showNewTab('knowledge')" style="background:#334155; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600;">
                    📚 Knowledge Base
                </button>
                <button class="new-tab" onclick="showNewTab('billing')" style="background:#334155; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600;">
                    💳 Billing
                </button>
                <button class="new-tab" onclick="showNewTab('llm')" style="background:#334155; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600;">
                    🎯 Otimização LLM
                </button>
                <button class="new-tab" onclick="showNewTab('system')" style="background:#334155; color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600;">
                    ⚙️ Sistema
                </button>
            </div>
            
            <!-- Tab Contents -->
            <div id="tab-analytics" class="new-tab-content" style="display:block;">
                <div style="background:#1e293b; padding:2rem; border-radius:16px; margin-bottom:1rem;">
                    <h2 style="color:#60a5fa; margin-bottom:1rem;">📊 Analytics Profissional</h2>
                    <p style="color:#cbd5e1; margin-bottom:1.5rem;">Visualize métricas detalhadas do seu chatbot</p>
                    
                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); gap:1rem; margin-bottom:2rem;">
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Total de Mensagens</div>
                            <div id="analytics-messages" style="color:#60a5fa; font-size:2rem; font-weight:700;">-</div>
                        </div>
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Conversas</div>
                            <div id="analytics-conversations" style="color:#10b981; font-size:2rem; font-weight:700;">-</div>
                        </div>
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Leads Capturados</div>
                            <div id="analytics-leads" style="color:#f59e0b; font-size:2rem; font-weight:700;">-</div>
                        </div>
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Taxa de Sucesso</div>
                            <div id="analytics-success" style="color:#06d6a0; font-size:2rem; font-weight:700;">-</div>
                        </div>
                    </div>
                    
                    <button onclick="loadAnalytics()" style="background:#3b82f6; color:white; border:none; padding:1rem 2rem; border-radius:12px; cursor:pointer; font-weight:600; width:100%;">
                        🔄 Atualizar Analytics
                    </button>
                </div>
            </div>
            
            <div id="tab-webhooks" class="new-tab-content" style="display:none;">
                <div style="background:#1e293b; padding:2rem; border-radius:16px;">
                    <h2 style="color:#60a5fa; margin-bottom:1rem;">🔗 Webhooks</h2>
                    <p style="color:#cbd5e1; margin-bottom:1.5rem;">Configure webhooks para integrar com sistemas externos</p>
                    
                    <div id="webhooks-list" style="margin-bottom:2rem;">
                        <p style="color:#94a3b8;">Carregando webhooks...</p>
                    </div>
                    
                    <button onclick="showAddWebhook()" style="background:#10b981; color:white; border:none; padding:1rem 2rem; border-radius:12px; cursor:pointer; font-weight:600; width:100%;">
                        ➕ Adicionar Webhook
                    </button>
                </div>
            </div>
            
            <div id="tab-knowledge" class="new-tab-content" style="display:none;">
                <div style="background:#1e293b; padding:2rem; border-radius:16px;">
                    <h2 style="color:#60a5fa; margin-bottom:1rem;">📚 Knowledge Base</h2>
                    <p style="color:#cbd5e1; margin-bottom:1.5rem;">Gerencie FAQs e documentos do seu chatbot</p>
                    
                    <div style="margin-bottom:2rem;">
                        <label style="color:#cbd5e1; display:block; margin-bottom:0.5rem; font-weight:600;">Pergunta:</label>
                        <input id="faq-question" type="text" placeholder="Ex: Qual o horário de funcionamento?" style="width:100%; padding:1rem; border:2px solid #475569; border-radius:12px; background:#334155; color:#f8fafc; margin-bottom:1rem;">
                        
                        <label style="color:#cbd5e1; display:block; margin-bottom:0.5rem; font-weight:600;">Resposta:</label>
                        <textarea id="faq-answer" placeholder="Ex: Funcionamos de segunda a sexta, das 9h às 18h" style="width:100%; padding:1rem; border:2px solid #475569; border-radius:12px; background:#334155; color:#f8fafc; min-height:100px; margin-bottom:1rem;"></textarea>
                        
                        <button onclick="addFAQ()" style="background:#10b981; color:white; border:none; padding:1rem 2rem; border-radius:12px; cursor:pointer; font-weight:600; width:100%;">
                            ➕ Adicionar FAQ
                        </button>
                    </div>
                    
                    <div id="faqs-list" style="margin-top:2rem;">
                        <h3 style="color:#cbd5e1; margin-bottom:1rem;">FAQs Cadastradas:</h3>
                        <div id="faqs-container" style="color:#94a3b8;">
                            Nenhuma FAQ cadastrada ainda.
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="tab-billing" class="new-tab-content" style="display:none;">
                <div style="background:#1e293b; padding:2rem; border-radius:16px;">
                    <h2 style="color:#60a5fa; margin-bottom:1rem;">💳 Planos e Billing</h2>
                    <p style="color:#cbd5e1; margin-bottom:1.5rem;">Gerencie planos e assinaturas</p>
                    
                    <div id="plans-container" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(250px, 1fr)); gap:1.5rem;">
                        <p style="color:#94a3b8;">Carregando planos...</p>
                    </div>
                </div>
            </div>
            
            <div id="tab-llm" class="new-tab-content" style="display:none;">
                <div style="background:#1e293b; padding:2rem; border-radius:16px;">
                    <h2 style="color:#60a5fa; margin-bottom:1rem;">🎯 Otimização LLM</h2>
                    <p style="color:#cbd5e1; margin-bottom:1.5rem;">Economize até 60% nos custos de IA</p>
                    
                    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:1rem;">
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Cache Hits</div>
                            <div id="llm-cache-hits" style="color:#10b981; font-size:2rem; font-weight:700;">-</div>
                        </div>
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Economia</div>
                            <div id="llm-savings" style="color:#06d6a0; font-size:2rem; font-weight:700;">-</div>
                        </div>
                        <div style="background:#334155; padding:1.5rem; border-radius:12px;">
                            <div style="color:#94a3b8; font-size:0.9rem; margin-bottom:0.5rem;">Taxa de Cache</div>
                            <div id="llm-cache-rate" style="color:#f59e0b; font-size:2rem; font-weight:700;">-</div>
                        </div>
                    </div>
                    
                    <button onclick="loadLLMStats()" style="background:#3b82f6; color:white; border:none; padding:1rem 2rem; border-radius:12px; cursor:pointer; font-weight:600; width:100%; margin-top:2rem;">
                        🔄 Atualizar Estatísticas
                    </button>
                </div>
            </div>
            
            <div id="tab-system" class="new-tab-content" style="display:none;">
                <div style="background:#1e293b; padding:2rem; border-radius:16px;">
                    <h2 style="color:#60a5fa; margin-bottom:1rem;">⚙️ Status do Sistema</h2>
                    <div id="system-status" style="color:#cbd5e1;">
                        <p>Carregando status...</p>
                    </div>
                    
                    <button onclick="loadSystemStatus()" style="background:#3b82f6; color:white; border:none; padding:1rem 2rem; border-radius:12px; cursor:pointer; font-weight:600; width:100%; margin-top:2rem;">
                        🔄 Atualizar Status
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Botão para abrir novos sistemas -->
    <button id="openNewSystemsBtn" onclick="openNewSystems()" style="position:fixed; bottom:20px; right:20px; background:linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color:white; border:none; padding:1rem 1.5rem; border-radius:12px; cursor:pointer; font-weight:600; box-shadow:0 10px 25px rgba(59,130,246,0.4); z-index:1000; display:flex; align-items:center; gap:0.5rem; animation:pulse 2s infinite;">
        <i class="fas fa-rocket"></i> Novos Sistemas V2.0
    </button>
    
    <style>
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .new-tab.active {
            background: #3b82f6 !important;
        }
        
        .new-tab:hover {
            opacity: 0.8;
        }
    </style>
    
    <script>
        // Funções para os novos sistemas
        function openNewSystems() {
            document.getElementById('newSystemsPanel').style.display = 'block';
            loadSystemStatus();
        }
        
        function closeNewSystems() {
            document.getElementById('newSystemsPanel').style.display = 'none';
        }
        
        function showNewTab(tabName) {
            // Esconder todos os conteúdos
            document.querySelectorAll('.new-tab-content').forEach(el => el.style.display = 'none');
            
            // Remover active de todas as tabs
            document.querySelectorAll('.new-tab').forEach(el => el.classList.remove('active'));
            
            // Mostrar conteúdo selecionado
            document.getElementById('tab-' + tabName).style.display = 'block';
            
            // Ativar tab
            event.target.classList.add('active');
            
            // Carregar dados da tab
            if (tabName === 'analytics') loadAnalytics();
            if (tabName === 'webhooks') loadWebhooks();
            if (tabName === 'billing') loadPlans();
            if (tabName === 'llm') loadLLMStats();
            if (tabName === 'system') loadSystemStatus();
        }
        
        async function loadAnalytics() {
            try {
                const response = await fetch('/api/analytics/default?days=30');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('analytics-messages').textContent = data.analytics.totalMessages || 0;
                    document.getElementById('analytics-conversations').textContent = data.analytics.totalConversations || 0;
                    document.getElementById('analytics-leads').textContent = data.analytics.leadsCount || 0;
                    document.getElementById('analytics-success').textContent = (data.analytics.successRate || 0) + '%';
                }
            } catch (error) {
                console.error('Erro ao carregar analytics:', error);
            }
        }
        
        async function loadWebhooks() {
            try {
                const response = await fetch('/api/webhooks/default');
                const data = await response.json();
                
                const container = document.getElementById('webhooks-list');
                if (data.success && data.webhooks.length > 0) {
                    container.innerHTML = data.webhooks.map(w => `
                        <div style="background:#334155; padding:1rem; border-radius:12px; margin-bottom:1rem;">
                            <div style="color:#cbd5e1; font-weight:600;">${w.eventType}</div>
                            <div style="color:#94a3b8; font-size:0.9rem;">${w.url}</div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = '<p style="color:#94a3b8;">Nenhum webhook configurado.</p>';
                }
            } catch (error) {
                console.error('Erro ao carregar webhooks:', error);
            }
        }
        
        async function addFAQ() {
            const question = document.getElementById('faq-question').value;
            const answer = document.getElementById('faq-answer').value;
            
            if (!question || !answer) {
                alert('Preencha pergunta e resposta!');
                return;
            }
            
            try {
                const response = await fetch('/api/knowledge/default/faq', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({question, answer})
                });
                
                const data = await response.json();
                if (data.success) {
                    alert('FAQ adicionada com sucesso!');
                    document.getElementById('faq-question').value = '';
                    document.getElementById('faq-answer').value = '';
                    loadFAQs();
                }
            } catch (error) {
                console.error('Erro ao adicionar FAQ:', error);
                alert('Erro ao adicionar FAQ');
            }
        }
        
        async function loadFAQs() {
            try {
                const response = await fetch('/api/knowledge/default');
                const data = await response.json();
                
                const container = document.getElementById('faqs-container');
                if (data.success && data.knowledge.faqs && data.knowledge.faqs.length > 0) {
                    container.innerHTML = data.knowledge.faqs.map(faq => `
                        <div style="background:#334155; padding:1rem; border-radius:12px; margin-bottom:1rem;">
                            <div style="color:#cbd5e1; font-weight:600; margin-bottom:0.5rem;">❓ ${faq.question}</div>
                            <div style="color:#94a3b8; font-size:0.9rem;">💬 ${faq.answer}</div>
                        </div>
                    `).join('');
                } else {
                    container.innerHTML = '<p style="color:#94a3b8;">Nenhuma FAQ cadastrada ainda.</p>';
                }
            } catch (error) {
                console.error('Erro ao carregar FAQs:', error);
            }
        }
        
        async function loadPlans() {
            try {
                const response = await fetch('/api/plans');
                const data = await response.json();
                
                const container = document.getElementById('plans-container');
                if (data.success) {
                    container.innerHTML = data.plans.map(plan => `
                        <div style="background:#334155; padding:1.5rem; border-radius:12px; border:2px solid ${plan.id === 'professional' ? '#3b82f6' : '#475569'};">
                            <h3 style="color:#cbd5e1; margin-bottom:0.5rem;">${plan.name}</h3>
                            <div style="color:#60a5fa; font-size:2rem; font-weight:700; margin-bottom:1rem;">
                                ${plan.price === 0 ? 'Grátis' : 'R$ ' + plan.price.toFixed(2)}
                            </div>
                            <ul style="color:#94a3b8; font-size:0.9rem; list-style:none; padding:0;">
                                <li style="margin-bottom:0.5rem;">✓ ${plan.features.maxChatbots} chatbots</li>
                                <li style="margin-bottom:0.5rem;">✓ ${plan.features.requestsPerMinute} req/min</li>
                                <li style="margin-bottom:0.5rem;">✓ ${plan.features.requestsPerHour} req/hora</li>
                            </ul>
                        </div>
                    `).join('');
                }
            } catch (error) {
                console.error('Erro ao carregar planos:', error);
            }
        }
        
        async function loadLLMStats() {
            try {
                const response = await fetch('/api/llm/stats/default?days=30');
                const data = await response.json();
                
                if (data.success && data.savings) {
                    document.getElementById('llm-cache-hits').textContent = data.savings.cacheHits || 0;
                    document.getElementById('llm-savings').textContent = 'R$ ' + (data.savings.savings || 0);
                    document.getElementById('llm-cache-rate').textContent = (data.savings.cacheHitRate || 0) + '%';
                }
            } catch (error) {
                console.error('Erro ao carregar stats LLM:', error);
            }
        }
        
        async function loadSystemStatus() {
            try {
                const response = await fetch('/api/system/status');
                const data = await response.json();
                
                const container = document.getElementById('system-status');
                if (data.success) {
                    container.innerHTML = `
                        <div style="display:grid; gap:1rem;">
                            <div style="background:#334155; padding:1rem; border-radius:12px;">
                                <div style="color:#94a3b8;">Servidor:</div>
                                <div style="color:#10b981; font-weight:600;">${data.status.server}</div>
                            </div>
                            <div style="background:#334155; padding:1rem; border-radius:12px;">
                                <div style="color:#94a3b8;">Banco de Dados:</div>
                                <div style="color:#10b981; font-weight:600;">${data.status.database.type} - ${data.status.database.connected ? 'Conectado' : 'Desconectado'}</div>
                            </div>
                            <div style="background:#334155; padding:1rem; border-radius:12px;">
                                <div style="color:#94a3b8;">Cache:</div>
                                <div style="color:#10b981; font-weight:600;">${data.status.cache.type} - ${data.status.cache.connected ? 'Conectado' : 'Desconectado'}</div>
                            </div>
                            <div style="background:#334155; padding:1rem; border-radius:12px;">
                                <div style="color:#94a3b8;">Uptime:</div>
                                <div style="color:#60a5fa; font-weight:600;">${Math.floor(data.status.uptime / 60)} minutos</div>
                            </div>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Erro ao carregar status:', error);
                document.getElementById('system-status').innerHTML = '<p style="color:#ef4444;">Erro ao carregar status do sistema</p>';
            }
        }
        
        function showAddWebhook() {
            alert('Funcionalidade de adicionar webhook em desenvolvimento. Use a API diretamente por enquanto.');
        }
        
        // Carregar FAQs ao abrir a tab
        setTimeout(() => {
            if (document.getElementById('tab-knowledge').style.display === 'block') {
                loadFAQs();
            }
        }, 1000);
    </script>
    '''
    
    # Inserir o novo HTML
    new_full_html = html[:insert_pos] + new_html + html[insert_pos:]
    
    # Salvar
    with open('public/index_app.html', 'w', encoding='utf-8') as f:
        f.write(new_full_html)
    
    print("✅ Painel melhorado criado com sucesso!")
    return True

if __name__ == '__main__':
    add_new_sections()
