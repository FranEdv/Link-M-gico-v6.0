# Diretório de Dados Persistentes

Este diretório armazena dados que devem persistir entre reinicializações do servidor.

## Arquivos:

- **leads.json**: Armazena todos os leads capturados pelo sistema
- **api_keys.json**: Chaves de API para autenticação
- **analytics/**: Dados de analytics e métricas
- **knowledge/**: Base de conhecimento e FAQs

## ⚠️ IMPORTANTE:

**NÃO DELETE ESTE DIRETÓRIO** ou você perderá todos os leads capturados!

No Render ou outras plataformas de hospedagem, certifique-se de que este diretório está incluído no deploy e não é limpo entre reinicializações.

### Backup Recomendado:

Faça backup regular do arquivo `leads.json` para não perder dados importantes.

```bash
# Exemplo de backup
cp data/leads.json data/leads-backup-$(date +%Y%m%d).json
```

