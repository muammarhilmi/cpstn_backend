from app import app, db

print("Sedang mereset database...")

# Masuk ke konteks aplikasi agar db tau settingan database-nya
with app.app_context():
    # 1. Hapus semua tabel lama (termasuk yang error tadi)
    db.drop_all()
    print("Tabel lama dihapus.")
    
    # 2. Buat ulang tabel baru sesuai kodingan terbaru
    db.create_all()
    print("Tabel baru berhasil dibuat!")

print("Selesai! Database nail_beauty sudah bersih dan update.")