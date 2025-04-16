import sqlite3
from flask import Flask, request

app = Flask(__name__)

def create_database():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
    c.execute("INSERT INTO users (username, password) VALUES ('user1', 'pass1')")
    conn.commit()
    conn.close()

@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    #  Intentionally insecure query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print("Executing query:", query)

    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    try:
        c.execute(query)
        result = c.fetchone()
    except Exception as e:
        return f"Error in SQL query: {str(e)}"
    finally:
        conn.close()

    if result:
        return "Login successful"
    else:
        return "Login failed"

if __name__ == '__main__':
    create_database()
    app.run(debug=True)
