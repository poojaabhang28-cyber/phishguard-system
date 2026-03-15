import sqlite3
from werkzeug.security import generate_password_hash

# Path to your DB
db_path = r"C:\Users\admin\Desktop\phishguard-system\phishing.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Delete plain-text password users
c.execute("DELETE FROM users WHERE password NOT LIKE 'pbkdf2:%' AND password NOT LIKE 'scrypt:%'")
deleted = conn.total_changes
conn.commit()
print(f"{deleted} plain-text users deleted.")

# Add test user with hashed password
c.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
          ('testuser','test@example.com', generate_password_hash('test123')))
conn.commit()
print("Test user added: username='testuser', password='test123'")

conn.close()