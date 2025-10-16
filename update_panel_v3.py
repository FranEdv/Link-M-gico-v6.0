#!/usr/bin/env python3
# Script para adicionar novas integrações ao painel

import re

# Ler o HTML atual
with open('public/index_app.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Adicionar novas abas ao painel de sistemas V2.0
new_tabs_html = '''
                <!-- Aba Gmail -->
                <button class="new-systems-tab" onclick="switchNewSystemsTab('gmail')">
                    📧 Gmail
                </button>
                
                <!-- Aba WhatsApp -->
                <button class="new-systems-tab" onclick="switchNewSystemsTab('whatsapp')">
                    📱 WhatsApp
                </button>
                
                <!-- Aba ChatGPT -->
                <button class="new-systems-tab" onclick="switchNewSystemsTab('chatgpt')">
                    🤖 ChatGPT
                </button>
                
                <!-- Aba Whitelabel -->
                <button class="new-systems-tab" onclick="switchNewSystemsTab('whitelabel')">
                    🎨 Whitelabel
                </button>
                
                <!-- Aba Leads -->
                <button class="new-systems-tab" onclick="switchNewSystemsTab('leads')">
                    📝 Leads
                </button>'''

# Encontrar onde inserir as novas abas (depois da aba Sistema)
pattern = r'(<button class="new-systems-tab" onclick="switchNewSystemsTab\(\'system\'\)">.*?</button>)'
html = re.sub(pattern, r'\1' + new_tabs_html, html, count=1)

# Adicionar novas seções de conteúdo
new_sections_html = '''
            <!-- Seção Gmail -->
            <div id="gmail-section" class="new-systems-section" style="display: none;">
                <h2 style="margin-bottom: 20px;">📧 Integração Gmail</h2>
                
                <div style="background: #eff6ff; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <p><strong>Status:</strong> <span id="gmail-status">Verificando...</span></p>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3>Configurar Gmail</h3>
                    <form id="gmail-config-form" style="margin-top: 15px;">
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Email Gmail:</label>
                            <input type="email" id="gmail-user" placeholder="seu@gmail.com" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Senha de App:</label>
                            <input type="password" id="gmail-password" placeholder="Senha de aplicativo do Gmail" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                            <small style="color: #6b7280;">Gere uma senha de aplicativo em: myaccount.google.com/apppasswords</small>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Email para Notificações:</label>
                            <input type="email" id="owner-email" placeholder="seu@email.com" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        
                        <button type="submit" style="background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500;">
                            Salvar Configuração
                        </button>
                        <button type="button" onclick="testGmailConnection()" style="background: #10b981; color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500; margin-left: 10px;">
                            Testar Conexão
                        </button>
                    </form>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px;">
                    <h3>Templates de Email</h3>
                    <div style="margin-top: 15px;">
                        <div style="padding: 15px; background: #f9fafb; border-radius: 6px; margin-bottom: 10px;">
                            <strong>🎉 Novo Lead Capturado</strong>
                            <p style="margin: 5px 0; color: #6b7280; font-size: 14px;">Notifica você quando um novo lead é capturado</p>
                        </div>
                        <div style="padding: 15px; background: #f9fafb; border-radius: 6px;">
                            <strong>👋 Boas-vindas ao Lead</strong>
                            <p style="margin: 5px 0; color: #6b7280; font-size: 14px;">Email automático enviado ao lead após captura</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Seção WhatsApp -->
            <div id="whatsapp-section" class="new-systems-section" style="display: none;">
                <h2 style="margin-bottom: 20px;">📱 Integração WhatsApp</h2>
                
                <div style="background: #eff6ff; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <p><strong>Status:</strong> <span id="whatsapp-status">Verificando...</span></p>
                    <p style="margin-top: 5px;"><strong>Provider:</strong> <span id="whatsapp-provider">Nenhum</span></p>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3>Escolher Provider</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 15px;">
                        <div onclick="selectWhatsAppProvider('twilio')" style="padding: 20px; border: 2px solid #e5e7eb; border-radius: 8px; cursor: pointer; text-align: center;">
                            <h4>Twilio</h4>
                            <p style="font-size: 14px; color: #6b7280;">WhatsApp Business API oficial</p>
                            <p style="font-size: 12px; color: #9ca3af; margin-top: 10px;">Pago, mais confiável</p>
                        </div>
                        <div onclick="selectWhatsAppProvider('evolution')" style="padding: 20px; border: 2px solid #e5e7eb; border-radius: 8px; cursor: pointer; text-align: center;">
                            <h4>Evolution API</h4>
                            <p style="font-size: 14px; color: #6b7280;">API open-source</p>
                            <p style="font-size: 12px; color: #9ca3af; margin-top: 10px;">Gratuito, auto-hospedado</p>
                        </div>
                    </div>
                </div>
                
                <div id="twilio-config" style="display: none; background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3>Configurar Twilio</h3>
                    <form id="twilio-config-form" style="margin-top: 15px;">
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Account SID:</label>
                            <input type="text" id="twilio-sid" placeholder="ACxxxxxxxxx" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Auth Token:</label>
                            <input type="password" id="twilio-token" placeholder="Token de autenticação" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">WhatsApp Number:</label>
                            <input type="text" id="twilio-number" placeholder="+14155238886" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Seu WhatsApp (para notificações):</label>
                            <input type="text" id="owner-whatsapp" placeholder="+5511999999999" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <button type="submit" style="background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500;">
                            Salvar Configuração
                        </button>
                    </form>
                </div>
                
                <div id="evolution-config" style="display: none; background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3>Configurar Evolution API</h3>
                    <form id="evolution-config-form" style="margin-top: 15px;">
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">API URL:</label>
                            <input type="url" id="evolution-url" placeholder="https://sua-api.com" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">API Key:</label>
                            <input type="password" id="evolution-key" placeholder="Sua chave de API" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Instance Name:</label>
                            <input type="text" id="evolution-instance" placeholder="nome_da_instancia" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Seu WhatsApp (para notificações):</label>
                            <input type="text" id="owner-whatsapp-evo" placeholder="+5511999999999" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        <button type="submit" style="background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500;">
                            Salvar Configuração
                        </button>
                    </form>
                </div>
            </div>

            <!-- Seção ChatGPT -->
            <div id="chatgpt-section" class="new-systems-section" style="display: none;">
                <h2 style="margin-bottom: 20px;">🤖 Integração ChatGPT</h2>
                
                <div style="background: #eff6ff; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <p><strong>Status:</strong> <span id="chatgpt-status">Verificando...</span></p>
                    <p style="margin-top: 5px;"><strong>Modelo Padrão:</strong> <span id="chatgpt-model">GPT-4 Turbo</span></p>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3>Configurar ChatGPT</h3>
                    <form id="chatgpt-config-form" style="margin-top: 15px;">
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">API Key:</label>
                            <input type="password" id="chatgpt-key" placeholder="sk-proj-xxxxxxxxx" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                            <small style="color: #6b7280;">Obtenha em: platform.openai.com/api-keys</small>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Modelo Padrão:</label>
                            <select id="chatgpt-model-select" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                                <option value="gpt-4-turbo">GPT-4 Turbo (Recomendado)</option>
                                <option value="gpt-4">GPT-4 (Melhor qualidade)</option>
                                <option value="gpt-3.5-turbo">GPT-3.5 Turbo (Mais barato)</option>
                            </select>
                        </div>
                        
                        <button type="submit" style="background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500;">
                            Salvar Configuração
                        </button>
                        <button type="button" onclick="testChatGPTConnection()" style="background: #10b981; color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500; margin-left: 10px;">
                            Testar Conexão
                        </button>
                    </form>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px;">
                    <h3>Comparação de Modelos</h3>
                    <table style="width: 100%; margin-top: 15px; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f9fafb;">
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e5e7eb;">Modelo</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e5e7eb;">Custo/1k tokens</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e5e7eb;">Qualidade</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e5e7eb;">Velocidade</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">GPT-4</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">$0.03</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">⭐⭐⭐⭐⭐</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">⭐⭐⭐</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">GPT-4 Turbo</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">$0.01</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">⭐⭐⭐⭐⭐</td>
                                <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">⭐⭐⭐⭐</td>
                            </tr>
                            <tr>
                                <td style="padding: 10px;">GPT-3.5 Turbo</td>
                                <td style="padding: 10px;">$0.0015</td>
                                <td style="padding: 10px;">⭐⭐⭐⭐</td>
                                <td style="padding: 10px;">⭐⭐⭐⭐⭐</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Seção Whitelabel -->
            <div id="whitelabel-section" class="new-systems-section" style="display: none;">
                <h2 style="margin-bottom: 20px;">🎨 Whitelabel</h2>
                
                <div style="background: #fef3c7; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #f59e0b;">
                    <p><strong>⭐ Recurso Premium</strong></p>
                    <p style="margin-top: 5px; font-size: 14px;">Disponível nos planos Profissional e Empresarial</p>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h3>Personalização de Marca</h3>
                    <form id="whitelabel-config-form" style="margin-top: 15px;">
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Nome da Empresa:</label>
                            <input type="text" id="company-name" placeholder="Minha Empresa" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">URL do Logo:</label>
                            <input type="url" id="logo-url" placeholder="https://exemplo.com/logo.png" style="width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px;">
                            <small style="color: #6b7280;">Formatos: PNG, JPG, SVG (recomendado: 200x50px)</small>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 500;">Cor Primária:</label>
                                <input type="color" id="primary-color" value="#3b82f6" style="width: 100%; height: 50px; border: 1px solid #d1d5db; border-radius: 6px; cursor: pointer;">
                            </div>
                            <div>
                                <label style="display: block; margin-bottom: 5px; font-weight: 500;">Cor Secundária:</label>
                                <input type="color" id="secondary-color" value="#8b5cf6" style="width: 100%; height: 50px; border: 1px solid #d1d5db; border-radius: 6px; cursor: pointer;">
                            </div>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: flex; align-items: center; cursor: pointer;">
                                <input type="checkbox" id="show-powered-by" checked style="margin-right: 10px; width: 20px; height: 20px;">
                                <span>Mostrar "Powered by Link Mágico"</span>
                            </label>
                        </div>
                        
                        <button type="submit" style="background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; font-weight: 500;">
                            Salvar Personalização
                        </button>
                    </form>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px;">
                    <h3>Preview</h3>
                    <div id="whitelabel-preview" style="margin-top: 15px; padding: 20px; border: 2px dashed #e5e7eb; border-radius: 8px; text-align: center;">
                        <p style="color: #9ca3af;">Configure as opções acima para ver o preview</p>
                    </div>
                </div>
            </div>

            <!-- Seção Leads Estruturados -->
            <div id="leads-section" class="new-systems-section" style="display: none;">
                <h2 style="margin-bottom: 20px;">📝 Leads Estruturados</h2>
                
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px;">
                    <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #3b82f6;">
                        <p style="font-size: 14px; color: #6b7280;">Total de Leads</p>
                        <p style="font-size: 32px; font-weight: bold; margin-top: 5px;" id="total-leads-count">0</p>
                    </div>
                    <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #ef4444;">
                        <p style="font-size: 14px; color: #6b7280;">Leads Quentes</p>
                        <p style="font-size: 32px; font-weight: bold; margin-top: 5px; color: #ef4444;" id="hot-leads-count">0</p>
                    </div>
                    <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #f59e0b;">
                        <p style="font-size: 14px; color: #6b7280;">Leads Mornos</p>
                        <p style="font-size: 32px; font-weight: bold; margin-top: 5px; color: #f59e0b;" id="warm-leads-count">0</p>
                    </div>
                    <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #10b981;">
                        <p style="font-size: 14px; color: #6b7280;">Taxa de Conversão</p>
                        <p style="font-size: 32px; font-weight: bold; margin-top: 5px; color: #10b981;" id="conversion-rate">0%</p>
                    </div>
                </div>
                
                <div style="background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h3>Lista de Leads</h3>
                        <div>
                            <button onclick="refreshLeads()" style="background: #3b82f6; color: white; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; margin-right: 10px;">
                                🔄 Atualizar
                            </button>
                            <button onclick="exportLeadsCSV()" style="background: #10b981; color: white; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer;">
                                📥 Exportar CSV
                            </button>
                        </div>
                    </div>
                    
                    <div style="overflow-x: auto;">
                        <table id="leads-table" style="width: 100%; border-collapse: collapse;">
                            <thead>
                                <tr style="background: #f9fafb;">
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Nome</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Email</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Telefone</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Empresa</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Score</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Status</th>
                                    <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Data</th>
                                </tr>
                            </thead>
                            <tbody id="leads-table-body">
                                <tr>
                                    <td colspan="7" style="padding: 40px; text-align: center; color: #9ca3af;">
                                        Carregando leads...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>'''

# Encontrar onde inserir as novas seções (depois da seção Sistema)
pattern = r'(<div id="system-section" class="new-systems-section".*?</div>\s*</div>)'
html = re.sub(pattern, r'\1' + new_sections_html, html, count=1, flags=re.DOTALL)

# Salvar o HTML atualizado
with open('public/index_app.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("✅ Painel atualizado com sucesso!")
print(f"📊 Tamanho final: {len(html)} caracteres")
