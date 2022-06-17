FROM node:lts-jessie

WORKDIR /root/app

COPY package.json .
COPY package-lock.json .
RUN npm install

COPY . .

EXPOSE 8080
ENTRYPOINT ["npm", "start"]