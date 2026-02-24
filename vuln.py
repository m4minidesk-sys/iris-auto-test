import sqlite3

def login(username, password):
    conn = sqlite3.connect("users.db")
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = conn.execute(query)
    return result.fetchone()
# Second trigger Tue Feb 24 21:58:59 JST 2026
