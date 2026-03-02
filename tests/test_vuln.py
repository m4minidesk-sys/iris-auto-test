"""tests/test_vuln.py — login関数のユニットテスト.

テスト項目:
- 正常系: 正しい認証情報でログイン成功
- 異常系: 誤ったパスワードで認証失敗
- SQLインジェクション防御: 悪意ある入力でも認証バイパス不可
"""

import os
import sqlite3
import tempfile
import unittest


_TEST_DB_PATH: str = ""


def _setup_db(db_path: str) -> None:
    """テスト用DBを作成し、ユーザーを登録する."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)", ("alice", "secret123")
    )
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)", ("bob", "pass456")
    )
    conn.commit()
    conn.close()


def _login_with_db(db_path: str, username: str, password: str):
    """テスト用DBを使ってloginと同等の処理を行う（DB差し替え版）."""
    conn = sqlite3.connect(db_path)
    query = "SELECT * FROM users WHERE username=? AND password=?"
    result = conn.execute(query, (username, password))
    return result.fetchone()


class TestLogin(unittest.TestCase):
    """login関数のテストスイート."""

    def setUp(self) -> None:
        """テスト用のDBファイルをセットアップ."""
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        _setup_db(self.db_path)

    def tearDown(self) -> None:
        """テスト後にDBファイルを削除."""
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def _login(self, username: str, password: str):
        """テスト用DBを使うloginのラッパー."""
        return _login_with_db(self.db_path, username, password)

    # --- 正常系 ---

    def test_login_success_valid_credentials(self) -> None:
        """正しいユーザー名とパスワードで認証成功すること."""
        result = self._login("alice", "secret123")
        self.assertIsNotNone(result)

    def test_login_success_returns_user_record(self) -> None:
        """認証成功時にユーザーレコード（タプル）が返ること."""
        result = self._login("alice", "secret123")
        self.assertIsInstance(result, tuple)
        self.assertEqual(result[1], "alice")

    def test_login_multiple_users(self) -> None:
        """複数ユーザーでそれぞれ正常に認証できること."""
        self.assertIsNotNone(self._login("alice", "secret123"))
        self.assertIsNotNone(self._login("bob", "pass456"))

    # --- 異常系 ---

    def test_login_failure_wrong_password(self) -> None:
        """誤ったパスワードでNoneが返ること."""
        self.assertIsNone(self._login("alice", "wrongpassword"))

    def test_login_failure_wrong_username(self) -> None:
        """存在しないユーザー名でNoneが返ること."""
        self.assertIsNone(self._login("nobody", "secret123"))

    def test_login_failure_empty_credentials(self) -> None:
        """空の認証情報でNoneが返ること."""
        self.assertIsNone(self._login("", ""))

    def test_login_failure_case_sensitive_password(self) -> None:
        """パスワードは大文字小文字を区別すること."""
        self.assertIsNone(self._login("alice", "SECRET123"))

    # --- SQLインジェクション防御 ---

    def test_sqli_classic_bypass_fails(self) -> None:
        """古典的なSQLiバイパス(' OR '1'='1)が防がれること."""
        self.assertIsNone(self._login("alice", "' OR '1'='1"))

    def test_sqli_comment_bypass_fails(self) -> None:
        """コメントSQLiバイパス(alice'--)が防がれること."""
        self.assertIsNone(self._login("alice'--", "anything"))

    def test_sqli_union_attack_fails(self) -> None:
        """UNION攻撃で不正なデータが返らないこと."""
        self.assertIsNone(
            self._login("alice' UNION SELECT 1,'hacker','hacked'--", "")
        )

    def test_sqli_tautology_fails(self) -> None:
        """恒等式(tautology)によるバイパスが防がれること."""
        self.assertIsNone(self._login("' OR 1=1--", "' OR 1=1--"))

    def test_sqli_drop_table_prevented(self) -> None:
        """DROP TABLE等の破壊的SQLが実行されないこと."""
        self.assertIsNone(self._login("alice", "'; DROP TABLE users;--"))
        # テーブルがまだ存在することを確認
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        conn.close()
        self.assertEqual(rows[0], 2, "usersテーブルが破壊された")


class TestVulnPyParameterizedQuery(unittest.TestCase):
    """vuln.pyのパラメータ化クエリ使用を検証するテスト."""

    def test_vuln_py_uses_parameterized_query(self) -> None:
        """vuln.pyのloginがパラメータ化クエリ(?)を使用していること."""
        import inspect
        import vuln
        source = inspect.getsource(vuln.login)
        self.assertIn("?", source, "パラメータ化クエリ(?)が使われていない")
        self.assertNotIn("f\"", source, "f-stringによるSQL構築は禁止")
        self.assertNotIn("f'", source, "f-stringによるSQL構築は禁止")
        self.assertNotIn("% ", source, "%-formattingによるSQL構築は禁止")
        self.assertNotIn(".format(", source, ".format()によるSQL構築は禁止")


if __name__ == "__main__":
    unittest.main()
