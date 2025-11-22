import os

import psycopg


def ensure_database_exists():
    dbname = os.environ.get("PACKAGEDB_DB_NAME", "packagedb")
    host = os.environ.get("PACKAGEDB_DB_HOST", "db")
    port = os.environ.get("PACKAGEDB_DB_PORT", "5432")
    user = os.environ.get("PACKAGEDB_DB_USER", "")
    password = os.environ.get("PACKAGEDB_DB_PASSWORD", "")

    conn = psycopg.connect(host=host, port=port, dbname="postgres", user=user, password=password)
    conn.autocommit = True

    with conn.cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_database WHERE datname=%s", (dbname,))
        exists = cursor.fetchone()

        if not exists:
            cursor.execute(f'CREATE DATABASE "{dbname}" OWNER "{user}"')

    conn.close()


def main():
    ensure_database_exists()


if __name__ == "__main__":
    main()

