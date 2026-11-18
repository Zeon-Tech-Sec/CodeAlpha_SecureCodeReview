import sqlite3
import unittest

import jwt
import yaml

from fixes import patterns as p


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE customer (first_name TEXT, last_name TEXT, username TEXT)")
    conn.executemany("INSERT INTO customer VALUES (?, ?, ?)",
                     [("Ana", "Khan", "ana"), ("Bilal", "Shah", "bilal"), ("Cara", "Ali", "cara")])
    return conn


class SqlInjection(unittest.TestCase):
    payload = "nobody' OR '1'='1"

    def test_vulnerable_query_returns_every_row(self):
        self.assertEqual(len(p.search_vulnerable(make_db(), self.payload)), 3)

    def test_parameterised_query_treats_input_as_data(self):
        self.assertEqual(p.search_fixed(make_db(), self.payload), [])

    def test_parameterised_query_still_finds_real_users(self):
        self.assertEqual(p.search_fixed(make_db(), "ana"), [("Ana", "Khan", "ana")])


class YamlDeserialisation(unittest.TestCase):
    doc = "!!python/object/apply:os.getcwd []"

    def test_unsafe_loader_runs_the_function_named_in_the_file(self):
        self.assertIsInstance(p.load_yaml_vulnerable(self.doc), str)

    def test_safe_loader_refuses_python_tags(self):
        with self.assertRaises(yaml.YAMLError):
            p.load_yaml_fixed(self.doc)

    def test_safe_loader_reads_normal_yaml(self):
        self.assertEqual(p.load_yaml_fixed("name: demo\nitems: [1, 2]"), {"name": "demo", "items": [1, 2]})


class TemplateInjection(unittest.TestCase):
    def test_vulnerable_page_evaluates_template_syntax(self):
        self.assertEqual(p.not_found_vulnerable("{{ 7 * 7 }}"), "<h3>49</h3>")

    def test_fixed_page_prints_input_as_text(self):
        self.assertEqual(p.not_found_fixed("{{ 7 * 7 }}"), "<h3>{{ 7 * 7 }}</h3>")

    def test_fixed_page_escapes_html(self):
        self.assertNotIn("<script>", p.not_found_fixed("<script>alert(1)</script>"))


class JwtVerification(unittest.TestCase):
    def forged(self):
        return jwt.encode({"user": "admin", "iss": p.ISSUER}, "attacker-key", algorithm="HS256")

    def valid(self):
        return jwt.encode({"user": "ana", "iss": p.ISSUER}, p.SECRET, algorithm="HS256")

    def test_vulnerable_check_accepts_a_token_signed_with_any_key(self):
        self.assertEqual(p.verify_vulnerable(self.forged())["user"], "admin")

    def test_fixed_check_rejects_wrong_signature(self):
        with self.assertRaises(jwt.InvalidSignatureError):
            p.verify_fixed(self.forged())

    def test_fixed_check_rejects_unsigned_token(self):
        token = jwt.encode({"user": "admin", "iss": p.ISSUER}, None, algorithm="none")
        with self.assertRaises(jwt.InvalidTokenError):
            p.verify_fixed(token)

    def test_fixed_check_accepts_a_genuine_token(self):
        self.assertEqual(p.verify_fixed(self.valid())["user"], "ana")


class PasswordStorage(unittest.TestCase):
    def test_hash_is_not_the_password_and_is_salted(self):
        a, b = p.hash_password("hunter2"), p.hash_password("hunter2")
        self.assertNotIn("hunter2", a)
        self.assertNotEqual(a, b)

    def test_check_accepts_right_and_rejects_wrong(self):
        stored = p.hash_password("hunter2")
        self.assertTrue(p.check_password(stored, "hunter2"))
        self.assertFalse(p.check_password(stored, "hunter3"))


if __name__ == "__main__":
    unittest.main()
