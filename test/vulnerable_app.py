import sqlite3
import subprocess

API_KEY = "hardcoded-secret-123"

def run():
    user_input = input()

    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user_input + "'")

    subprocess.run(["bash", "-c", f"ls {user_input}"])

if __name__ == "__main__":
    run()