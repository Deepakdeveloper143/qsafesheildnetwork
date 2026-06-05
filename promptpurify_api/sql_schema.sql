-- PromptPurify AI Supabase schema (PostgreSQL)
-- Users and projects
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  display_name text,
  role text DEFAULT 'user',
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner uuid REFERENCES users(id),
  name text NOT NULL,
  description text,
  created_at timestamptz DEFAULT now()
);

-- Scans and reports
CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid REFERENCES projects(id),
  scan_type text,
  prompt text,
  result jsonb,
  risk_score int,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS prompt_attacks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id),
  attack_type text,
  details jsonb,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS poisoning_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id),
  probability float,
  confidence float,
  affected_components jsonb,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS owasp_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id),
  compliance jsonb,
  overall_score int,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id),
  agent_name text,
  result jsonb,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor text,
  action text,
  details jsonb,
  created_at timestamptz DEFAULT now()
);
