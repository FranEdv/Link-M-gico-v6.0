// ===== CRM INTEGRATIONS MODULE =====
// Módulo com templates e documentação para integrar com CRMs via Webhooks

class CRMIntegrations {
    constructor() {
        this.integrations = {
            rdstation: {
                name: 'RD Station',
                description: 'CRM e automação de marketing líder no Brasil',
                webhookFormat: 'json',
                documentation: this.getRDStationDocs(),
                examplePayload: this.getRDStationPayload()
            },
            hubspot: {
                name: 'HubSpot',
                description: 'Plataforma completa de CRM e marketing',
                webhookFormat: 'json',
                documentation: this.getHubSpotDocs(),
                examplePayload: this.getHubSpotPayload()
            },
            pipedrive: {
                name: 'Pipedrive',
                description: 'CRM focado em vendas',
                webhookFormat: 'json',
                documentation: this.getPipedriveDocs(),
                examplePayload: this.getPipedrivePayload()
            },
            activecamp: {
                name: 'ActiveCampaign',
                description: 'Automação de marketing e CRM',
                webhookFormat: 'json',
                documentation: this.getActiveCampaignDocs(),
                examplePayload: this.getActiveCampaignPayload()
            }
        };
    }

    // ===== RD STATION =====
    getRDStationDocs() {
        return {
            title: 'Integração com RD Station via Webhook',
            steps: [
                {
                    step: 1,
                    title: 'Obter Token de Integração',
                    description: 'Acesse RD Station > Integrações > API > Gerar Token Público',
                    url: 'https://app.rdstation.com.br/integracoes'
                },
                {
                    step: 2,
                    title: 'Configurar Webhook no Link Mágico',
                    description: 'Use a URL: https://api.rd.services/platform/conversions?api_key=SEU_TOKEN',
                    code: `POST https://linkmagico-comercial.onrender.com/api/webhooks/SEU_CHATBOT_ID

{
  "eventType": "lead_captured",
  "url": "https://api.rd.services/platform/conversions?api_key=SEU_TOKEN_RD",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "payloadTemplate": {
    "event_type": "CONVERSION",
    "event_family": "CDP",
    "payload": {
      "conversion_identifier": "lead_chatbot",
      "name": "{{leadName}}",
      "email": "{{leadEmail}}",
      "mobile_phone": "{{leadPhone}}",
      "cf_origem": "Chatbot Link Mágico",
      "cf_chatbot_id": "{{chatbotId}}",
      "cf_url_origem": "{{pageUrl}}"
    }
  }
}`
                },
                {
                    step: 3,
                    title: 'Testar Integração',
                    description: 'Capture um lead de teste e verifique no RD Station'
                }
            ],
            tips: [
                'Use campos personalizados (cf_) para informações extras',
                'Configure automações no RD Station baseadas no evento "lead_chatbot"',
                'Monitore os logs de webhook para debug'
            ]
        };
    }

    getRDStationPayload() {
        return {
            event_type: 'CONVERSION',
            event_family: 'CDP',
            payload: {
                conversion_identifier: 'lead_chatbot',
                name: '{{leadName}}',
                email: '{{leadEmail}}',
                mobile_phone: '{{leadPhone}}',
                cf_origem: 'Chatbot',
                cf_chatbot_id: '{{chatbotId}}',
                cf_timestamp: '{{timestamp}}'
            }
        };
    }

    // ===== HUBSPOT =====
    getHubSpotDocs() {
        return {
            title: 'Integração com HubSpot via Webhook',
            steps: [
                {
                    step: 1,
                    title: 'Criar Formulário no HubSpot',
                    description: 'Marketing > Lead Capture > Forms > Create Form',
                    url: 'https://app.hubspot.com/forms'
                },
                {
                    step: 2,
                    title: 'Obter URL de Submissão',
                    description: 'No formulário, vá em Share > Embed > Get Form Submit URL',
                    example: 'https://api.hsforms.com/submissions/v3/integration/submit/PORTAL_ID/FORM_GUID'
                },
                {
                    step: 3,
                    title: 'Configurar Webhook no Link Mágico',
                    code: `POST https://linkmagico-comercial.onrender.com/api/webhooks/SEU_CHATBOT_ID

{
  "eventType": "lead_captured",
  "url": "https://api.hsforms.com/submissions/v3/integration/submit/PORTAL_ID/FORM_GUID",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "payloadTemplate": {
    "fields": [
      {
        "name": "firstname",
        "value": "{{leadName}}"
      },
      {
        "name": "email",
        "value": "{{leadEmail}}"
      },
      {
        "name": "phone",
        "value": "{{leadPhone}}"
      },
      {
        "name": "lead_source",
        "value": "Chatbot"
      }
    ],
    "context": {
      "pageUri": "{{pageUrl}}",
      "pageName": "Chatbot {{chatbotName}}"
    }
  }
}`
                },
                {
                    step: 4,
                    title: 'Configurar Automações',
                    description: 'Crie workflows no HubSpot baseados no formulário'
                }
            ],
            tips: [
                'Crie propriedades customizadas no HubSpot para dados do chatbot',
                'Use workflows para nutrir leads automaticamente',
                'Configure notificações para a equipe de vendas'
            ]
        };
    }

    getHubSpotPayload() {
        return {
            fields: [
                { name: 'firstname', value: '{{leadName}}' },
                { name: 'email', value: '{{leadEmail}}' },
                { name: 'phone', value: '{{leadPhone}}' },
                { name: 'lead_source', value: 'Chatbot' }
            ],
            context: {
                pageUri: '{{pageUrl}}',
                pageName: 'Chatbot {{chatbotName}}'
            }
        };
    }

    // ===== PIPEDRIVE =====
    getPipedriveDocs() {
        return {
            title: 'Integração com Pipedrive via Webhook',
            steps: [
                {
                    step: 1,
                    title: 'Obter API Token',
                    description: 'Settings > Personal Preferences > API > Your personal API token',
                    url: 'https://app.pipedrive.com/settings/api'
                },
                {
                    step: 2,
                    title: 'Configurar Webhook no Link Mágico',
                    code: `POST https://linkmagico-comercial.onrender.com/api/webhooks/SEU_CHATBOT_ID

{
  "eventType": "lead_captured",
  "url": "https://api.pipedrive.com/v1/persons?api_token=SEU_TOKEN",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "payloadTemplate": {
    "name": "{{leadName}}",
    "email": [{"value": "{{leadEmail}}", "primary": true}],
    "phone": [{"value": "{{leadPhone}}", "primary": true}],
    "visible_to": "3",
    "add_time": "{{timestamp}}"
  }
}`
                },
                {
                    step: 3,
                    title: 'Criar Deal Automaticamente (Opcional)',
                    description: 'Configure um segundo webhook para criar negócio',
                    code: `{
  "eventType": "lead_captured",
  "url": "https://api.pipedrive.com/v1/deals?api_token=SEU_TOKEN",
  "method": "POST",
  "payloadTemplate": {
    "title": "Lead Chatbot - {{leadName}}",
    "person_id": "{{pipedrivePersonId}}",
    "value": 1000,
    "currency": "BRL",
    "stage_id": 1
  }
}`
                }
            ],
            tips: [
                'Use campos customizados para rastrear origem do lead',
                'Configure automações para atribuir leads à equipe',
                'Integre com email para follow-up automático'
            ]
        };
    }

    getPipedrivePayload() {
        return {
            name: '{{leadName}}',
            email: [{ value: '{{leadEmail}}', primary: true }],
            phone: [{ value: '{{leadPhone}}', primary: true }],
            visible_to: '3'
        };
    }

    // ===== ACTIVECAMPAIGN =====
    getActiveCampaignDocs() {
        return {
            title: 'Integração com ActiveCampaign via Webhook',
            steps: [
                {
                    step: 1,
                    title: 'Obter Credenciais da API',
                    description: 'Settings > Developer > API Access',
                    url: 'https://SUACONTA.activehosted.com/admin/main.php?action=settings'
                },
                {
                    step: 2,
                    title: 'Configurar Webhook no Link Mágico',
                    code: `POST https://linkmagico-comercial.onrender.com/api/webhooks/SEU_CHATBOT_ID

{
  "eventType": "lead_captured",
  "url": "https://SUACONTA.api-us1.com/api/3/contacts",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json",
    "Api-Token": "SEU_API_TOKEN"
  },
  "payloadTemplate": {
    "contact": {
      "email": "{{leadEmail}}",
      "firstName": "{{leadName}}",
      "phone": "{{leadPhone}}",
      "fieldValues": [
        {
          "field": "1",
          "value": "Chatbot"
        }
      ]
    }
  }
}`
                },
                {
                    step: 3,
                    title: 'Adicionar a Lista/Tag',
                    description: 'Configure para adicionar contato a lista ou tag específica'
                }
            ],
            tips: [
                'Use tags para segmentar leads do chatbot',
                'Configure automações baseadas em tags',
                'Integre com campanhas de email marketing'
            ]
        };
    }

    getActiveCampaignPayload() {
        return {
            contact: {
                email: '{{leadEmail}}',
                firstName: '{{leadName}}',
                phone: '{{leadPhone}}',
                fieldValues: [
                    { field: '1', value: 'Chatbot' }
                ]
            }
        };
    }

    // ===== MÉTODOS PÚBLICOS =====

    // Listar integrações disponíveis
    listIntegrations() {
        return Object.keys(this.integrations).map(key => ({
            id: key,
            name: this.integrations[key].name,
            description: this.integrations[key].description
        }));
    }

    // Obter documentação de uma integração
    getDocumentation(crmName) {
        const integration = this.integrations[crmName.toLowerCase()];
        if (!integration) {
            return { error: 'CRM não encontrado' };
        }

        return {
            name: integration.name,
            description: integration.description,
            documentation: integration.documentation,
            examplePayload: integration.examplePayload
        };
    }

    // Obter todas as documentações
    getAllDocumentations() {
        const docs = {};
        for (const [key, integration] of Object.entries(this.integrations)) {
            docs[key] = {
                name: integration.name,
                description: integration.description,
                documentation: integration.documentation
            };
        }
        return docs;
    }

    // Gerar código de webhook para um CRM
    generateWebhookCode(crmName, chatbotId, customConfig = {}) {
        const integration = this.integrations[crmName.toLowerCase()];
        if (!integration) {
            return { error: 'CRM não encontrado' };
        }

        const baseUrl = customConfig.baseUrl || 'https://linkmagico-comercial.onrender.com';
        
        return {
            curl: this.generateCurlCommand(crmName, chatbotId, baseUrl, customConfig),
            javascript: this.generateJavaScriptCode(crmName, chatbotId, baseUrl, customConfig),
            python: this.generatePythonCode(crmName, chatbotId, baseUrl, customConfig)
        };
    }

    generateCurlCommand(crmName, chatbotId, baseUrl, config) {
        const integration = this.integrations[crmName.toLowerCase()];
        const payload = JSON.stringify({
            eventType: 'lead_captured',
            ...config
        }, null, 2);

        return `curl -X POST ${baseUrl}/api/webhooks/${chatbotId} \\
  -H "Content-Type: application/json" \\
  -d '${payload}'`;
    }

    generateJavaScriptCode(crmName, chatbotId, baseUrl, config) {
        return `// Configurar webhook para ${this.integrations[crmName].name}
const response = await fetch('${baseUrl}/api/webhooks/${chatbotId}', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    eventType: 'lead_captured',
    ...${JSON.stringify(config, null, 2)}
  })
});

const result = await response.json();
console.log('Webhook configurado:', result);`;
    }

    generatePythonCode(crmName, chatbotId, baseUrl, config) {
        return `# Configurar webhook para ${this.integrations[crmName].name}
import requests

response = requests.post(
    '${baseUrl}/api/webhooks/${chatbotId}',
    json={
        'eventType': 'lead_captured',
        **${JSON.stringify(config, null, 2)}
    }
)

result = response.json()
print('Webhook configurado:', result)`;
    }
}

// Singleton instance
const crmIntegrations = new CRMIntegrations();

module.exports = {
    crmIntegrations,
    CRMIntegrations
};

