FROM node:20-alpine

# Install Poppler for pdftoppm (needed for PDF rasterisation)
RUN apk add --no-cache poppler-utils

WORKDIR /app

# Copy package files first (faster rebuilds)
COPY package*.json ./
RUN npm install

# Copy rest of project
COPY . .

# Build Next.js
RUN npm run build

# Railway uses PORT env variable — this just documents it
EXPOSE 8080

# Start the app — Next.js reads PORT automatically
CMD ["npm", "start"]