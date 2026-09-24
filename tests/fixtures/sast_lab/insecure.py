# Deliberately insecure fixture. Read as text only; never import or execute.
import os
import subprocess
import sqlite3
import pickle
import hashlib
import yaml

PASSWORD = 'LocalLabCredential-83-not-valid'
API_KEY = 'YOUR_API_KEY'

def assess(user, blob, cursor):
    eval(user)
    exec(user)
    os.system(user)
    subprocess.run(user, shell=True)
    query = 'SELECT * FROM users WHERE name = ' + user
    cursor.execute(query)
    pickle.loads(blob)
    yaml.load(blob)
    hashlib.md5(blob)

def safe(user, cursor):
    cursor.execute('SELECT * FROM users WHERE name = ?', (user,))
    yaml.safe_load(user)
    eval('1 + 1')
