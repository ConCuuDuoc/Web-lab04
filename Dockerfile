FROM node:18
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
RUN npm rebuild bcrypt --build-from-source
COPY . .
EXPOSE 5500
CMD ["npm", "run", "dev"]
