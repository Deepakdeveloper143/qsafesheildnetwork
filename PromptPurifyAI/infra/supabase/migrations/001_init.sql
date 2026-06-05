-- Users and RBAC
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    role TEXT CHECK (role IN ('admin','analyst','viewer')),
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Projects (group scans per organization/team)
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Scans – generic record linking to specific scan types
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    scan_type TEXT CHECK (scan_type IN ('prompt','poisoning','owasp','cloud','github','agent')),
    status TEXT CHECK (status IN ('queued','running','completed','failed')),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    result_json JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Prompt attack specifics
CREATE TABLE prompt_attacks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    risk_score INT CHECK (risk_score BETWEEN 0 AND 100),
    severity TEXT CHECK (severity IN ('Low','Medium','High','Critical')),
    details JSONB
);

-- Poisoning reports
CREATE TABLE poisoning_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    probability FLOAT,
    confidence FLOAT,
    affected_components TEXT[],
    details JSONB
);

-- OWASP LLM Top-10 reports
CREATE TABLE owasp_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    compliance_json JSONB,
    overall_score INT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Multi-agent results
CREATE TABLE agent_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    agent_name TEXT,
    findings JSONB,
    confidence FLOAT
);

-- Audit logs
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    action TEXT,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ DEFAULT now()
);

-- Indexes for performance
CREATE INDEX idx_scans_project_id ON scans(project_id);
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
