FROM node:20-slim

# add Python next to Node
RUN apt-get update && apt-get install -y python3 python3-pip --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Node dependencies
COPY package*.json ./
RUN npm install

# Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages flask sympy gunicorn

# all your code
COPY . .

CMD ["./start.sh"]