# Docker Usage Guide

## Build Docker Image

```bash
docker build -t web-security-scanner .
```

## Run with Docker

### Web Interface (Port 8080)
```bash
docker run -p 8080:8080 web-security-scanner
```

Access at: http://localhost:8080

### CLI Mode
```bash
docker run web-security-scanner python main.py -u http://example.com
```

## Run with Docker Compose

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Environment Variables

- `FLASK_ENV`: Set to 'production' for production deployment
- `SECRET_KEY`: Change the default secret key in production

## Production Deployment

1. Update the secret key in `web_app.py`
2. Set `FLASK_ENV=production`
3. Use a reverse proxy (nginx) in front
4. Enable HTTPS
5. Use a proper database instead of in-memory storage
