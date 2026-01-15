import os
import pymysql
from dotenv import load_dotenv

# Load konfigurasi dari file .env
load_dotenv()

def get_connection():
    try:
        # Mengambil variabel dari .env
        return pymysql.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASS", ""),
            database=os.getenv("DB_NAME", "nail_beauty"),
            port=int(os.getenv("DB_PORT", 3306)),
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True 
        )
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

# Blok ini hanya untuk tes koneksi kalau file ini dijalankan langsung
if __name__ == "__main__":
    conn = get_connection()
    if conn:
        print("✅ Koneksi db.py ke database berhasil!")
        conn.close()
    else:
        print("❌ Koneksi db.py gagal.")