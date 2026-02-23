FROM node:20-slim
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY server.mjs ui.html ./
RUN mkdir -p .data
EXPOSE 3000
ENV PORT=3000 HOST=0.0.0.0
CMD ["node", "server.mjs"]
