const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function generateApiKey() {
    return crypto.randomBytes(32).toString("hex");
}

const newApiKey = generateApiKey();

const dataFilePath = path.join(__dirname, "..", "api-keys.json");

let existingApiKeys = {};
try {
    if (fs.existsSync(dataFilePath)) {
        existingApiKeys = JSON.parse(fs.readFileSync(dataFilePath, "utf8"));
    }
} catch (error) {
    console.error("Erro ao carregar api-keys.json existente:", error);
}

existingApiKeys[newApiKey] = {
    name: "API Client",
    plan: "basic",
    active: true
};

fs.writeFileSync(dataFilePath, JSON.stringify(existingApiKeys, null, 2));
console.log(`Sua nova chave de API é: ${newApiKey}`);
console.log(`API Key salva em ${dataFilePath}`);

