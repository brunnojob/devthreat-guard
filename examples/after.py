"""Local-only secure query example. sqlite parameter binding is the defense."""
import json
import sqlite3

def lookup(connection, raw_id):
    if not isinstance(raw_id, str) or not raw_id.isascii() or not raw_id.isdigit() or len(raw_id) > 9:
        raise ValueError('Expected numeric ID')
    return connection.execute('SELECT name FROM users WHERE id = ?', (int(raw_id),)).fetchall()

def parse_profile(raw):
    if len(raw.encode('utf-8')) > 65536:
        raise ValueError('Payload too large')
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get('name'), str) or len(value['name']) > 120:
        raise ValueError('Invalid profile')
    return value
