import sqlite3

import jwt
import yaml
from jinja2 import Environment
from werkzeug.security import check_password_hash, generate_password_hash

SECRET = "replace-with-a-long-random-value-from-the-environment"
ISSUER = "we45"


def search_vulnerable(conn: sqlite3.Connection, term: str) -> list:
    query = "SELECT first_name, last_name, username FROM customer WHERE username = '%s';" % term
    return conn.execute(query).fetchall()


def search_fixed(conn: sqlite3.Connection, term: str) -> list:
    query = "SELECT first_name, last_name, username FROM customer WHERE username = ?;"
    return conn.execute(query, (term,)).fetchall()


def load_yaml_vulnerable(text: str):
    return yaml.load(text, Loader=yaml.UnsafeLoader)


def load_yaml_fixed(text: str):
    return yaml.safe_load(text)


def not_found_vulnerable(url: str) -> str:
    page = "<h3>%s</h3>" % url
    return Environment(autoescape=False).from_string(page).render()


def not_found_fixed(url: str) -> str:
    return Environment(autoescape=True).from_string("<h3>{{ url }}</h3>").render(url=url)


def verify_vulnerable(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def verify_fixed(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=["HS256"], issuer=ISSUER)


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def check_password(stored: str, password: str) -> bool:
    return check_password_hash(stored, password)
