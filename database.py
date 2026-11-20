import sqlite3
from config import DB_PATH, DATA_DIR


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS spent_tokens (
                token_hash TEXT PRIMARY KEY,
                redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS system_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                issuance_requests INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("""
            INSERT OR IGNORE INTO system_stats (id, issuance_requests)
            VALUES (1, 0)
        """)
        connection.commit()


def record_issuance_request():
    with get_connection() as connection:
        connection.execute("""
            UPDATE system_stats
            SET issuance_requests = issuance_requests + 1
            WHERE id = 1
        """)
        connection.commit()


def redeem_once(token_hash: str):
    """Insert the token hash once. A primary-key conflict means it was spent."""
    try:
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO spent_tokens (token_hash) VALUES (?)",
                (token_hash,)
            )
            connection.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_statistics():
    with get_connection() as connection:
        row = connection.execute("""
            SELECT issuance_requests FROM system_stats WHERE id = 1
        """).fetchone()
        spent = connection.execute("""
            SELECT COUNT(*) AS total FROM spent_tokens
        """).fetchone()["total"]

    return {
        "total_requests": row["issuance_requests"],
        "redeemed_tokens": spent
    }
