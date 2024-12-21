# Use Python 3.10 slim
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for process monitoring
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    procps \
    psmisc \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY src/ ./src/
COPY cert/ ./cert/

# Create necessary directories
RUN mkdir -p cert
RUN mkdir -p /host/proc
RUN mkdir -p /host/sys

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the working directory to where server.py is located
WORKDIR /app/src

# Start the application
CMD ["python", "server.py"]