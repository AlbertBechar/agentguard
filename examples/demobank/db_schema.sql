CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT NOT NULL, name TEXT, email TEXT, phone TEXT);
CREATE TABLE accounts (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, iban TEXT, balance REAL, card_number TEXT);
CREATE TABLE transactions (id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, amount REAL, memo TEXT, created_at TEXT);
CREATE TABLE tickets (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, text TEXT);
