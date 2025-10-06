-- Custom Cashu PostgreSQL Schema
-- This schema includes the keyset_u32 column that cdk-postgres expects

-- Create mint_keysets table with keyset_u32 column
CREATE TABLE IF NOT EXISTS mint_keysets (
    id TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    unit TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    keyset_u32 BIGINT,  -- This is the missing column!
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create mints table
CREATE TABLE IF NOT EXISTS mints (
    url TEXT PRIMARY KEY,
    data BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create proofs table
CREATE TABLE IF NOT EXISTS proofs (
    y TEXT PRIMARY KEY,
    amount BIGINT NOT NULL,
    secret TEXT NOT NULL,
    c TEXT NOT NULL,
    mint_url TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create mint_keys table
CREATE TABLE IF NOT EXISTS mint_keys (
    id TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    data BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create mint_quotes table
CREATE TABLE IF NOT EXISTS mint_quotes (
    id TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    request TEXT NOT NULL,
    quote TEXT NOT NULL,
    paid BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create melt_quotes table
CREATE TABLE IF NOT EXISTS melt_quotes (
    id TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    request TEXT NOT NULL,
    quote TEXT NOT NULL,
    paid BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create pending_proofs table
CREATE TABLE IF NOT EXISTS pending_proofs (
    secret TEXT PRIMARY KEY,
    mint_url TEXT NOT NULL,
    data BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create used_secrets table
CREATE TABLE IF NOT EXISTS used_secrets (
    secret TEXT PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_mint_keysets_mint_url ON mint_keysets(mint_url);
CREATE INDEX IF NOT EXISTS idx_proofs_mint_url ON proofs(mint_url);
CREATE INDEX IF NOT EXISTS idx_mint_keys_mint_url ON mint_keys(mint_url);
CREATE INDEX IF NOT EXISTS idx_mint_quotes_mint_url ON mint_quotes(mint_url);
CREATE INDEX IF NOT EXISTS idx_melt_quotes_mint_url ON melt_quotes(mint_url);
CREATE INDEX IF NOT EXISTS idx_pending_proofs_mint_url ON pending_proofs(mint_url);
