function showToast(message, type = 'info') {
            const toastContainer = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `<i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-times-circle' : 'fa-info-circle'}"></i><span>${message}</span>`;
            toastContainer.appendChild(toast);
            setTimeout(() => toast.classList.add('show'), 10);
            setTimeout(() => {
                toast.classList.remove('show');
                toast.addEventListener('transitionend', () => toast.remove());
            }, 5000);
        }

        const consentModal = document.getElementById('consentModal');
        const lgpdBadge = document.getElementById('lgpdBadge');
        const closeConsentModal = document.getElementById('closeConsentModal');
        const urlResponsibilityCheckbox = document.getElementById('urlResponsibilityCheckbox');
        const acceptConsentBtn = document.getElementById('acceptConsentBtn');
        const rejectConsentBtn = document.getElementById('rejectConsentBtn');

        lgpdBadge.addEventListener('click', () => {
            consentModal.style.display = 'flex';
        });

        closeConsentModal.addEventListener('click', () => {
            consentModal.style.display = 'none';
        });

        urlResponsibilityCheckbox.addEventListener('change', () => {
            acceptConsentBtn.disabled = !urlResponsibilityCheckbox.checked;
        });

        rejectConsentBtn.addEventListener('click', () => {
            showToast('Consentimento recusado. Algumas funcionalidades podem ser limitadas.', 'error');
            consentModal.style.display = 'none';
            // Implementar lógica para limitar funcionalidades ou redirecionar
        });

        acceptConsentBtn.addEventListener('click', () => {
            if (urlResponsibilityCheckbox.checked) {
                showToast('Consentimento aceito! Aproveite todas as funcionalidades.', 'success');
                consentModal.style.display = 'none';
                localStorage.setItem('lgpd_consent', 'accepted');
            } else {
                showToast('Por favor, confirme a responsabilidade da URL.', 'error');
            }
        });

        // Verificar consentimento ao carregar a página
        window.addEventListener('DOMContentLoaded', () => {
            if (!localStorage.getItem('lgpd_consent')) {
                consentModal.style.display = 'flex';
            }
        });

        // ===== NOVA LÓGICA: GERAÇÃO DO LINK DO CHATBOT =====
        const robotNameInput = document.getElementById('robotName');
        const salesUrlInput = document.getElementById('salesUrl');
        const customInstructionsInput = document.getElementById('customInstructions');
        const activateChatbotBtn = document.getElementById('activateChatbotBtn');
        const chatbotFrame = document.getElementById('chatbotFrame');
        const successAlert = document.getElementById('successAlert');
        const widgetCodeDisplay = document.getElementById('widgetCodeDisplay');
        const copyWidgetCodeBtn = document.getElementById('copyWidgetCodeBtn');
        
        // Novos elementos
        const chatbotLinkSection = document.getElementById('chatbotLinkSection');
        const chatbotLinkUrl = document.getElementById('chatbotLinkUrl');
        const copyChatbotLinkBtn = document.getElementById('copyChatbotLinkBtn');
        const extractedDataContent = document.getElementById('extractedDataContent');
        const extractedSummary = document.getElementById('extractedSummary');

        // Botões de compartilhamento social
        const shareWhatsApp = document.getElementById('shareWhatsApp');
        const shareInstagram = document.getElementById('shareInstagram');
        const shareFacebook = document.getElementById('shareFacebook');
        const shareYouTube = document.getElementById('shareYouTube');
        const shareTikTok = document.getElementById('shareTikTok');
        const shareTwitter = document.getElementById('shareTwitter');
        const shareKwai = document.getElementById('shareKwai');
        const shareLinkedIn = document.getElementById('shareLinkedIn');
        const shareTelegram = document.getElementById('shareTelegram');
        const shareMessenger = document.getElementById('shareMessenger');

        let currentChatbotUrl = '';

        function showLoading() {
            activateChatbotBtn.disabled = true;
            activateChatbotBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ativando...';
        }

        function hideLoading() {
            activateChatbotBtn.disabled = false;
            activateChatbotBtn.innerHTML = '<i class="fas fa-play-circle"></i> Ativar Chatbot Inteligente';
        }

        function generateChatbotUrl(robotName, salesUrl, instructions) {
            const params = new URLSearchParams({
                name: robotName,
                url: salesUrl,
                instructions: instructions
            });
            return `${window.location.origin}/chatbot?${params.toString()}`;
        }

        function updateSocialShareLinks(chatbotUrl, robotName) {
            const shareText = `Converse com ${robotName} - Assistente IA inteligente para vendas`;
            const encodedUrl = encodeURIComponent(chatbotUrl);
            const encodedText = encodeURIComponent(shareText);
            
            // WhatsApp
            shareWhatsApp.onclick = () => {
                window.open(`https://wa.me/?text=${encodedText}%20${encodedUrl}`, '_blank');
            };
            
            // Instagram (simplificado - abre em nova aba)
            shareInstagram.onclick = () => {
                window.open('https://www.instagram.com/', '_blank');
            };
            
            // Facebook
            shareFacebook.onclick = () => {
                window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}&quote=${encodedText}`, '_blank');
            };
            
            // YouTube (simplificado)
            shareYouTube.onclick = () => {
                window.open('https://www.youtube.com/', '_blank');
            };
            
            // TikTok (simplificado)
            shareTikTok.onclick = () => {
                window.open('https://www.tiktok.com/', '_blank');
            };
            
            // Twitter
            shareTwitter.onclick = () => {
                window.open(`https://twitter.com/intent/tweet?text=${encodedText}&url=${encodedUrl}`, '_blank');
            };
            
            // Kwai (simplificado)
            shareKwai.onclick = () => {
                window.open('https://www.kwai.com/', '_blank');
            };
            
            // LinkedIn
            shareLinkedIn.onclick = () => {
                window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`, '_blank');
            };
            
            // Telegram
            shareTelegram.onclick = () => {
                window.open(`https://t.me/share/url?url=${encodedUrl}&text=${encodedText}`, '_blank');
            };
            
            // Messenger (simplificado)
            shareMessenger.onclick = () => {
                window.open(`https://www.facebook.com/dialog/send?link=${encodedUrl}&app_id=YOUR_APP_ID&redirect_uri=${encodedUrl}`, '_blank');
            };
        }

        activateChatbotBtn.addEventListener('click', async () => {
            const robotName = robotNameInput.value;
            const salesUrl = salesUrlInput.value;
            const customInstructions = customInstructionsInput.value;

            if (!robotName || !salesUrl) {
                showToast('Por favor, preencha o nome do assistente e a URL da página.', 'error');
                return;
            }

            showLoading();

            try {
                const response = await fetch('/api/extract', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ url: salesUrl, instructions: customInstructions, robotName: robotName })
                });

                const data = await response.json();

                if (!data.success) {
                    throw new Error(data.error || 'Erro desconhecido na extração.');
                }

                // Gerar URL do chatbot
                currentChatbotUrl = generateChatbotUrl(robotName, salesUrl, customInstructions);
                
                // Atualizar seção do link do chatbot
                chatbotLinkUrl.href = currentChatbotUrl;
                chatbotLinkUrl.textContent = currentChatbotUrl;
                
                // Atualizar dados extraídos
                if (data.data && data.data.summary) {
                    extractedSummary.textContent = data.data.summary;
                } else {
                    extractedSummary.textContent = 'Dados extraídos com sucesso da página.';
                }
                
                // Mostrar seção do link do chatbot
                chatbotLinkSection.classList.add('active');

                // Atualizar links de compartilhamento social
                updateSocialShareLinks(currentChatbotUrl, robotName);

                // Atualiza o iframe do chatbot preview
                const chatbotParams = new URLSearchParams({
                    url: salesUrl,
                    name: robotName,
                    instructions: customInstructions
                });
                chatbotFrame.src = `/chat.html?${chatbotParams.toString()}`;

                // Atualiza o código do widget
                widgetCodeDisplay.innerHTML = `&lt;!-- LinkMágico Chatbot Widget --&gt;\n&lt;script&gt;\n    window.LinkMagicoWidgetConfig = {\n        robotName: "${robotName}",\n        salesUrl: "${salesUrl}",\n        instructions: "${customInstructions}",\n        primaryColor: "#3b82f6"\n    };\n&lt;/script&gt;\n&lt;script src="/public/widget.js"&gt;&lt;/script&gt;`;

                successAlert.style.display = 'block';
                showToast('Chatbot ativado com sucesso! Link gerado e pronto para compartilhar.', 'success');

                // Atualizar analytics
                document.getElementById('activeChatbots').textContent = '1';
                document.getElementById('createdToday').textContent = '1';

            } catch (error) {
                console.error('Erro ao ativar chatbot:', error);
                showToast(`Erro ao ativar chatbot: ${error.message || 'Servidor indisponível. Tente novamente em alguns minutos.'}`, 'error');
            } finally {
                hideLoading();
            }
        });

        // Copiar link do chatbot
        copyChatbotLinkBtn.addEventListener('click', () => {
            if (currentChatbotUrl) {
                navigator.clipboard.writeText(currentChatbotUrl).then(() => {
                    showToast('Link do chatbot copiado!', 'success');
                }).catch(err => {
                    console.error('Erro ao copiar link:', err);
                    showToast('Erro ao copiar link.', 'error');
                });
            } else {
                showToast('Nenhum link de chatbot disponível para copiar.', 'error');
            }
        });

        copyWidgetCodeBtn.addEventListener('click', () => {
            const codeToCopy = widgetCodeDisplay.textContent;
            navigator.clipboard.writeText(codeToCopy).then(() => {
                showToast('Código do widget copiado!', 'success');
            }).catch(err => {
                console.error('Erro ao copiar código:', err);
                showToast('Erro ao copiar código.', 'error');
            });
        });

        // Botões de funcionalidades adicionais
        document.getElementById('promptBtn').addEventListener('click', () => {
            showToast('Funcionalidade Prompt em desenvolvimento', 'info');
        });

        document.getElementById('analyticsBtn').addEventListener('click', () => {
            showToast('Funcionalidade Analytics em desenvolvimento', 'info');
        });