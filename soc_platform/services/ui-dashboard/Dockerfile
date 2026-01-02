FROM node:18-alpine

WORKDIR /app

# Install dependencies
RUN npm install -g serve

# Create placeholder index.html
RUN echo '<html><body><h1>SOC IoT Platform UI</h1><p>Dashboard coming soon...</p></body></html>' > index.html

EXPOSE 3000

CMD ["serve", "-s", ".", "-l", "3000"]
