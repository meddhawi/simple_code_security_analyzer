# Cyber Security Log Analyzer

## Deskripsi Aplikasi
Cyber Security Log Analyzer adalah aplikasi sederhana untuk menganalisis log aktivitas jaringan dengan tujuan mendeteksi aktivitas mencurigakan dan potensial serangan cyber. Aplikasi ini dirancang untuk implementasi struktur data fundamental (array, queue, stack, linked list, dan tree) dalam konteks keamanan siber.

## Fitur Utama
- Menerima dan menyimpan log aktivitas jaringan
- Memproses log secara berurutan menggunakan queue
- Melacak aktivitas mencurigakan dengan stack
- Menyimpan dan mengelola IP mencurigakan menggunakan linked list
- Membuat keputusan tentang tingkat ancaman menggunakan decision tree
- Menyimpan dan memuat log dari file

**Menambahkan Log dari File**

Aplikasi ini mendukung pemuatan log dari file CSV. Ikuti langkah-langkah berikut:

1.  **Buat file CSV**: Buat file teks baru (misalnya `mylogs.csv`) dengan format berikut:
    ```csv
    timestamp,ipAddress,action,status
    ```
    Setiap baris mewakili satu entri log. Pastikan data dipisahkan dengan koma.

    Contoh:
    ```csv
    2024-03-20 10:30:45,192.168.1.1,HTTP GET /login,200
    2024-03-20 10:31:00,10.0.0.1,HTTPS POST /api/data,200
    2024-03-20 10:32:15,345.67.89.10,HTTP POST /admin,403
    ```

2.  **Jalankan Aplikasi**: Kompilasi dan jalankan aplikasi jika belum berjalan.

3.  **Pilih Menu**: Di menu utama aplikasi, pilih opsi **"2. Load Log dari File"**.

4.  **Masukkan Nama File**: Ketika diminta, masukkan nama file CSV yang Anda buat (misalnya `mylogs.csv`) dan tekan Enter.

Aplikasi akan membaca log dari file tersebut dan menambahkannya ke dalam sistem untuk diproses. Jika berhasil, Anda akan melihat pesan "Log berhasil dimuat dari file.".

## Implementasi Struktur Data
Aplikasi ini mengimplementasikan berbagai struktur data dasar:

1. **Array**: 
   - Implementasi: `vector<LogEntry> logArray`
   - Kegunaan: Menyimpan semua log aktivitas jaringan
   - Kelebihan: Akses cepat dan random untuk semua log

2. **Queue**:
   - Implementasi: `queue<LogEntry> logQueue`
   - Kegunaan: Antrian pemrosesan log yang masuk (FIFO)
   - Kelebihan: Menjamin log diproses secara berurutan sesuai waktu kedatangan

3. **Stack**:
   - Implementasi: `stack<LogEntry> alertStack`
   - Kegunaan: Melacak history aktivitas mencurigakan (LIFO)
   - Kelebihan: Memudahkan akses ke alert terbaru

4. **Linked List**:
   - Implementasi: Class `SuspiciousIPList` dengan nodes yang terhubung
   - Kegunaan: Menyimpan daftar IP yang mencurigakan
   - Kelebihan: Efisien untuk operasi penambahan dan penghapusan dinamis

5. **Tree**:
   - Implementasi: Class `AttackClassifier` dengan struktur pohon keputusan
   - Kegunaan: Klasifikasi tingkat bahaya berdasarkan atribut log
   - Kelebihan: Menyediakan algoritma pengambilan keputusan yang terstruktur

## Alur Kerja Aplikasi
1. Log aktivitas jaringan diterima dan disimpan dalam array
2. Log kemudian dimasukkan ke dalam queue untuk diproses
3. Log diproses menggunakan decision tree untuk klasifikasi tingkat ancaman
4. Jika log dianggap mencurigakan:
   - IP ditambahkan ke dalam linked list IP mencurigakan
   - Log ditambahkan ke dalam stack alert
5. User dapat melihat IP mencurigakan dan alert terbaru kapan saja

## Kompilasi dan Menjalankan
```bash
# Kompilasi program
g++ -o CyberSecurityLogAnalyzer CyberSecurityLogAnalyzer.cpp

# Menjalankan program
./CyberSecurityLogAnalyzer
```

## Screenshot Aplikasi
[Screenshots akan ditambahkan setelah implementasi]

## Pengembangan Lanjutan
Beberapa ide untuk pengembangan aplikasi di masa depan:

- Implementasi algoritma machine learning untuk deteksi ancaman yang lebih canggih
- Interface grafis untuk visualisasi data yang lebih baik
- Koneksi database untuk penyimpanan data yang persisten
- Integrasi dengan sistem alerting seperti email atau notifikasi
- Analisis log real-time dari jaringan aktif

## Kontribusi
Kontribusi untuk meningkatkan aplikasi ini sangat diterima. Mohon buat branch baru dan submit pull request untuk perubahan yang diusulkan.

## Lisensi
[Tambahkan informasi lisensi jika diperlukan]

---

Dibuat untuk memenuhi tugas mata kuliah Struktur Data dan Algoritma.

## File 