# Deployment Guide

This guide covers deploying PromptPurify AI using Docker Compose.

## Prerequisites
- Docker and Docker Compose installed.
- A virtual machine or server (Ubuntu 22.04 recommended).
- Domain name mapped to your server IP.

## 1. Clone the Repository
```bash
git clone https://github.com/your-org/PromptPurifyAI.git
cd PromptPurifyAI/infra
```

## 2. Configuration
Copy the `.env` template and fill in production secrets:
```bash
nano .env
```
Ensure you set a strong `POSTGRES_PASSWORD`, `JWT_SECRET_KEY`, and provide your `GROQ_API_KEY`.

## 3. SSL/TLS (HTTPS)
For production, you should use Let's Encrypt.
Modify `nginx.conf` to include certbot configurations or use a reverse proxy like Traefik/Caddy in place of the default Nginx.

## 4. Launch Services
Start the application in detached mode:
```bash
docker-compose up -d --build
```

## 5. Verify
Check the logs to ensure everything is running:
```bash
docker-compose logs -f
```
Visit your domain to see the Streamlit UI, and `/docs` for the FastAPI swagger interface.
