import sqlite3


def login(username: str, password: str):
    """ユーザーログイン認証。

    パラメータ化クエリを使用してSQLインジェクションを防止。

    Args:
        username: ユーザー名
        password: パスワード

    Returns:
        認証成功時はユーザーレコード、失敗時はNone
    """
    conn = sqlite3.connect("users.db")
    # パラメータ化クエリ（SQLインジェクション防止）
    query = "SELECT * FROM users WHERE username=? AND password=?"
    result = conn.execute(query, (username, password))
    return result.fetchone()
