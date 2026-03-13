FROM node:20-slim
RUN apt-get update && apt-get install -y python3 make g++ \
    libglib2.0-0 libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 libasound2 libpangocairo-1.0-0 libx11-xcb1 libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm install --production
RUN npx playwright install chromium --with-deps
COPY *.mjs ui.html ./
RUN mkdir -p .data screenshots
EXPOSE 3000
ENV PORT=3000 HOST=0.0.0.0
CMD ["node", "server.mjs"]
