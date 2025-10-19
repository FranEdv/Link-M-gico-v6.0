/**
 * 💬 WIDGET DE CHATBOT LINK MÁGICO
 * Versão: 1.0.0
 * 
 * Este script injeta um botão flutuante na página que, ao ser clicado,
 * abre um iframe com o chatbot do Link Mágico.
 * A configuração é feita via `window.LinkMagicoWidgetConfig`.
 */

(function() {
    // Configurações padrão e sobrescritas pelo cliente
    const defaultConfig = {
        robotName: "Chatbot Link Mágico",
        salesUrl: "https://linkmagico-comercial.onrender.com/chatbot", // URL padrão do chatbot
        instructions: "Olá! Como posso ajudar hoje?",
        primaryColor: "#3b82f6",
        position: "right", // ou "left"
        buttonText: "Chatbot",
        buttonIcon: "💬", // Pode ser um SVG ou ícone de fonte
        welcomeMessage: "Olá! Sou seu assistente virtual. Como posso te ajudar?",
        apiKey: null // A API Key do cliente, essencial para identificar o chatbot
    };

    const userConfig = window.LinkMagicoWidgetConfig || {};
    const config = { ...defaultConfig, ...userConfig };

    // Validar API Key
    if (!config.apiKey) {
        console.error("Link Mágico Widget: API Key não configurada. O widget não será carregado.");
        return;
    }

    // Criar o botão flutuante
    const chatButton = document.createElement("button");
    chatButton.id = "linkmagico-chatbot-button";
    chatButton.style.cssText = `
        position: fixed;
        bottom: 20px;
        ${config.position}: 20px;
        background-color: ${config.primaryColor};
        color: white;
        border: none;
        border-radius: 50%;
        width: 60px;
        height: 60px;
        font-size: 24px;
        cursor: pointer;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 99999;
        transition: all 0.3s ease;
    `;
    chatButton.innerHTML = config.buttonIcon;
    document.body.appendChild(chatButton);

    // Criar o iframe do chatbot
    const chatIframe = document.createElement("iframe");
    chatIframe.id = "linkmagico-chatbot-iframe";
    chatIframe.style.cssText = `
        position: fixed;
        bottom: 90px;
        ${config.position}: 20px;
        width: 350px;
        height: 500px;
        border: 1px solid #ccc;
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        z-index: 99998;
        display: none;
        opacity: 0;
        transition: opacity 0.3s ease;
    `;
    // Construir a URL do chatbot com os parâmetros de configuração
    const chatbotUrl = new URL(config.salesUrl);
    chatbotUrl.searchParams.append("robotName", config.robotName);
    chatbotUrl.searchParams.append("instructions", config.instructions);
    chatbotUrl.searchParams.append("primaryColor", config.primaryColor.replace("#", ""));
    chatbotUrl.searchParams.append("apiKey", config.apiKey);
    chatbotUrl.searchParams.append("welcomeMessage", config.welcomeMessage);

    chatIframe.src = chatbotUrl.toString();
    document.body.appendChild(chatIframe);

    // Lógica para abrir/fechar o chatbot
    let isOpen = false;
    chatButton.addEventListener("click", () => {
        isOpen = !isOpen;
        if (isOpen) {
            chatIframe.style.display = "block";
            setTimeout(() => chatIframe.style.opacity = "1", 10);
            chatButton.style.transform = "rotate(45deg)";
            chatButton.innerHTML = "✖"; // Ícone de fechar
        } else {
            chatIframe.style.opacity = "0";
            chatButton.style.transform = "rotate(0deg)";
            chatButton.innerHTML = config.buttonIcon;
            setTimeout(() => chatIframe.style.display = "none", 300);
        }
    });

    // Opcional: Adicionar estilos básicos para o botão ao passar o mouse
    chatButton.addEventListener("mouseover", () => {
        chatButton.style.transform += " scale(1.05)";
    });
    chatButton.addEventListener("mouseout", () => {
        chatButton.style.transform = chatButton.style.transform.replace(" scale(1.05)", "");
    });

    console.log("Link Mágico Chatbot Widget carregado.");
})();

