FROM python:3.10-slim

LABEL maintainer="Web Security Scanner Team"
LABEL description="Web Security Scanner - Automated vulnerability detection tool"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY src/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ .

# Create necessary directories
RUN mkdir -p templates static logs

# Expose port for web interface
EXPOSE 8080

# Set environment variables
ENV FLASK_APP=web_app.py
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/', timeout=2)" || exit 1

# Default command - web interface
CMD ["python", "web_app.py"]

# Alternative: Run CLI scanner
# CMD ["python", "main.py", "--help"]
