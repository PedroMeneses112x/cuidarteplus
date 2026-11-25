FROM node:22-alpine

WORKDIR /app

# Actualizar npm global para mitigar CVE-2026-59873 en tar
RUN npm install -g npm@latest

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias
RUN npm ci --only=production

# Copiar código de la aplicación
COPY src/ ./src/
COPY sql/ ./sql/

# Crear directorios para uploads
RUN mkdir -p uploads/contracts uploads/documentos

# Exponer puerto
EXPOSE 3000

# Comando para iniciar la aplicación
CMD ["node", "src/app.js"]