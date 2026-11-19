import importlib.util
import sqlite3
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('after', Path(__file__).parents[1] / 'examples' / 'after.py')
after = importlib.util.module_from_spec(spec)
spec.loader.exec_module(after)
class DefenseTests(unittest.TestCase):
    def test_query_and_input_boundary(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE users(id INTEGER, name TEXT)')
            db.execute('INSERT INTO users VALUES (?, ?)', (1, 'Brunno'))
            self.assertEqual(after.lookup(db, '1'), [('Brunno',)])
            for value in ['1 OR 1=1', '-1', '１', '1; DROP TABLE users', None]:
                with self.assertRaises(ValueError):
                    after.lookup(db, value)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM users').fetchone()[0], 1)
    def test_profile(self):
        self.assertEqual(after.parse_profile('{"name":"Brunno"}'), {'name':'Brunno'})
        for raw in ['[]', '{"name":42}', 'null', '{"name":"' + 'a'*121 + '"}']:
            with self.assertRaises(ValueError):
                after.parse_profile(raw)
if __name__ == '__main__':
    unittest.main()
