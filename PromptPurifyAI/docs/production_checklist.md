# Production Deployment Checklist

Before taking PromptPurify AI to production, ensure the following are completed:

## Security & Auth
- [ ] Ensure HTTPS/TLS is configured via Nginx or Cloud Load Balancer.
- [ ] Replace default `JWT_SECRET_KEY` with a strong 256-bit cryptographically secure key.
- [ ] Store `.env` variables in a secure vault (e.g., HashiCorp Vault, AWS Secrets Manager) if possible.
- [ ] Ensure Supabase JWT `SUPABASE_KEY` is properly restricted via RLS policies.
- [ ] Restrict FastAPI CORS `allow_origins` to only the exact frontend domain.

## Infrastructure & DB
- [ ] Change `POSTGRES_PASSWORD` and avoid exposing port 5432 directly to the internet.
- [ ] Set up automated daily database backups for the Supabase volume.
- [ ] Configure Redis for persistence if rate limit/queue data needs to survive restarts (AOF/RDB).

## Application Config
- [ ] Update Streamlit Authenticator in `frontend/components/auth.py` to use a real database lookup instead of the YAML mock config.
- [ ] Adjust `slowapi` rate limits in `backend/app/main.py` based on expected traffic.

## Monitoring
- [ ] Set up Prometheus/Grafana or Datadog for container monitoring.
- [ ] Ensure audit logs are retained and exported to a SIEM (e.g., Splunk, ELK) for compliance.
