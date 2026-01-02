FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Run
CMD ["python", "main.py"]
