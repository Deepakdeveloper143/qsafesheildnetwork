# PromptPurify AI

PromptPurify AI is a production-ready AI security platform that detects and mitigates Prompt Injection, Jailbreaks, Model Poisoning, Data Exfiltration, Agent Manipulation attacks, and the OWASP LLM Top 10 vulnerabilities.

## Features

- **Prompt Injection Scanner:** Identifies "ignore instructions", DAN attacks, system prompt leaks.
- **Model Poisoning Detector:** Scans training data and outputs for contamination.
- **OWASP LLM Top 10 Analyzer:** Detailed compliance checks against LLM01-LLM10.
- **Multi-Agent Security Engine:** Concurrent threat analysis across specialized agents.
- **Cloud & GitHub Security:** Scans AWS, Azure, GCP buckets and GitHub repositories for secrets and misconfigurations.
- **Dashboard:** Rich visualizations using Streamlit and Plotly.

## Architecture

```text
User
 │
 ▼
Streamlit UI
 │
 ▼
FastAPI Gateway
 │
 ├── Prompt Injection Engine
 ├── Model Poisoning Engine
 ├── OWASP Analyzer
 ├── Multi-Agent Security Layer
 │
 ▼
Groq LLM
 │
 ▼
Supabase
 │
 ▼
Dashboard + Reports
```

## Quick Start (Docker)

1. Clone the repository.
2. Copy `infra/.env` (modify to `.env` in infra folder) and fill in your secrets (e.g., `GROQ_API_KEY`).
3. Run the stack:
   ```bash
   cd infra
   docker-compose up -d --build
   ```
4. Access the UI at `http://localhost:8501` and the API at `http://localhost/api/v1`.

## Documentation

See the `docs/` folder for:
- [Deployment Guide](docs/deployment_guide.md)
- [API Documentation](docs/api_documentation.md)
- [Production Checklist](docs/production_checklist.md)
