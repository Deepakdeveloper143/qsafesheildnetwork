# API Documentation

PromptPurify AI provides a RESTful API built with FastAPI. Complete interactive documentation (Swagger UI) is available at `/docs` when the backend is running.

## Base URL
`/api/v1`

## Authentication
All endpoints require a Bearer token in the Authorization header.
```
Authorization: Bearer <your_jwt_token>
```

## Endpoints

### 1. `POST /scan-prompt`
Analyzes a prompt for injections and jailbreaks.
**Body:**
```json
{
  "project_id": "uuid",
  "prompt": "user input here"
}
```

### 2. `POST /detect-poisoning`
Analyzes training data or model output for poisoning.
**Body:**
```json
{
  "project_id": "uuid",
  "training_data_snippet": "...",
  "model_output": "..."
}
```

### 3. `POST /owasp-scan`
Checks application context against OWASP LLM Top 10.
**Body:**
```json
{
  "project_id": "uuid",
  "prompt": "..."
}
```

### 4. `POST /agent-analysis`
Runs the Multi-Agent Engine (Injection, Poisoning, OWASP concurrently).
**Body:**
```json
{
  "project_id": "uuid",
  "prompt": "..."
}
```

### 5. `GET /dashboard`
Retrieves aggregated statistics for the UI.

### 6. `GET /audit-logs`
Requires Admin role. Returns system audit logs.
