# LinkMágico v6.0 - Git Ignore

# Variáveis de ambiente (NUNCA commitar!)
.env
.env.local
.env.*.local

# Dependências
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
package-lock.json
yarn.lock

# Dados sensíveis
data/
logs/
*.log

# Arquivos do sistema operacional
.DS_Store
Thumbs.db
desktop.ini

# IDEs e editores
.vscode/
.idea/
*.swp
*.swo
*~
.project
.classpath
.settings/

# Temporários
tmp/
temp/
*.tmp

# Build e distribuição
dist/
build/
.cache/

# Testes
coverage/
.nyc_output/

# Puppeteer
.local-chromium/