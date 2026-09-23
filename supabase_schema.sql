-- PrivacyGuard Supabase / PostgreSQL Schema Setup
-- Copy and run this script in your Supabase SQL Editor (https://supabase.com/dashboard/project/avbgpvggtcsrelcsqeux/sql)

-- 1. Create scan_sessions table
CREATE TABLE IF NOT EXISTS scan_sessions (
    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'manual',
    total_urls INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Create url_scans table
CREATE TABLE IF NOT EXISTS url_scans (
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    domain TEXT,
    score REAL NOT NULL,
    risk_label TEXT NOT NULL,
    is_tracker BOOLEAN DEFAULT FALSE,
    is_phishing BOOLEAN DEFAULT FALSE,
    matched_brand TEXT,
    predicted_label TEXT,
    confidence REAL,
    verdict TEXT,
    explanation TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Enable Row Level Security (RLS) and grant full access to anonymous API requests
ALTER TABLE scan_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow all on scan_sessions" ON scan_sessions;
CREATE POLICY "Allow all on scan_sessions" ON scan_sessions FOR ALL USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Allow all on url_scans" ON url_scans;
CREATE POLICY "Allow all on url_scans" ON url_scans FOR ALL USING (true) WITH CHECK (true);
