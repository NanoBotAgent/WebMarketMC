#!/usr/bin/env python3
"""Set up Astra DB tables for WebMarketMC"""
import json
import urllib.request
import urllib.error
import os

ASTRA_TOKEN = os.environ.get("ASTRA_TOKEN", "")
DB_ID = "165b585e-7ece-4015-987f-165032706b56"
REGION = "us-east-2"
BASE = f"https://{DB_ID}-{REGION}.apps.astra.datastax.com"

def cql(query):
    """Execute CQL via the REST v2 CQL endpoint"""
    url = f"{BASE}/api/rest/v2/cql"
    req = urllib.request.Request(
        url,
        data=query.encode("utf-8"),
        headers={
            "Authorization": f"Bearer {ASTRA_TOKEN}",
            "Content-Type": "text/plain",
            "X-Cassandra-Token": ASTRA_TOKEN,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            print(f"OK: {query[:80]}... -> {resp.status}")
            if body:
                print(f"  Response: {body[:200]}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"ERR {e.code}: {query[:80]}... -> {body[:300]}")
        return False

# Create tables
tables = [
    # Servers table - stores MC server registration + synced market data
    """CREATE TABLE IF NOT EXISTS webmarketmc.servers (
        server_id text PRIMARY KEY,
        api_key text,
        server_name text,
        last_sync bigint,
        categories_json text,
        items_json text,
        auctions_json text,
        orders_json text,
        stocks_json text,
        price_history_json text
    )""",

    # Sessions table - player web sessions
    # NOTE: 'token' is a reserved CQL keyword, use 'session_token'
    """CREATE TABLE IF NOT EXISTS webmarketmc.sessions (
        session_token text PRIMARY KEY,
        server_id text,
        player_uuid text,
        player_name text,
        balances_json text,
        default_currency text,
        expires bigint
    )""",

    # Purchases table - pending/completed purchases
    """CREATE TABLE IF NOT EXISTS webmarketmc.purchases (
        purchase_id text PRIMARY KEY,
        server_id text,
        player_uuid text,
        type text,
        item_key text,
        auction_id int,
        order_id int,
        amount text,
        status text,
        created_at bigint,
        result_json text
    )""",

    # Index: find sessions by server+player (for session-update)
    """CREATE INDEX IF NOT EXISTS ON webmarketmc.sessions (server_id)""",

    # Index: find purchases by server (for sync pending)
    """CREATE INDEX IF NOT EXISTS ON webmarketmc.purchases (server_id)""",
]

print("Creating Astra DB tables for WebMarketMC...")
for q in tables:
    cql(q)

print("\nDone! Verifying tables exist...")
cql("SELECT table_name FROM system_schema.tables WHERE keyspace_name = 'webmarketmc'")
