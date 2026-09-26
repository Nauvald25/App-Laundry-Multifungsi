# LaundryPro Multi-Usaha

Versi pengembangan dari prototipe `coba.html`: aplikasi web multi-usaha dengan database SQLite di server, akun pemilik/kasir, pembayaran parsial, manajemen laundry, dashboard, laporan CSV, serta struk cetak 80 mm. Ini **bukan layanan publik yang sudah di-deploy**.

## Mulai di komputer

1. Instal Node.js versi 20 atau lebih baru.
2. Unduh tiga berkas hasil: `laundrypro_server.js`, `laundrypro.html`, dan `laundrypro_package.json` ke **folder yang sama**.
3. Ubah nama `laundrypro_package.json` menjadi `package.json`.
4. Dari terminal pada folder tersebut jalankan `npm install`, lalu `npm start`.
5. Buka `http://localhost:3000` di browser. Pilih **Daftar gratis** dan buat akun pemilik usaha. Tidak ada username/password bawaan.

Database `laundrypro.sqlite` tercipta otomatis di folder kerja saat server pertama berjalan. Untuk memakai aplikasi dari perangkat lain, host server pada mesin yang bisa dijangkau kedua perangkat; untuk akses internet publik siapkan domain dan HTTPS serta penyimpanan yang persisten. Jangan mengunggah database SQLite ke repositori publik.

## Fitur

- Multi-tenant: usaha A dan usaha B memiliki data yang terpisah di server, dengan pemilik dan akun kasir sendiri.
- Login dengan kata sandi bcrypt, cookie sesi HttpOnly; tidak memakai password statis di JavaScript.
- Dashboard dan grafik pembayaran menurut tanggal pesanan untuk 7 hari, peringatan stok minimum.
- Kasir dengan beberapa layanan, diskon member otomatis, voucher tervalidasi server, tukar poin, pembayaran penuh/sebagian/piutang, dan struk 80 mm.
- Status pesanan diubah manual secara berurutan, pencarian nota/pelanggan, tautan WhatsApp yang membuka draf pesan (tidak mengirim otomatis).
- Pelanggan dan tingkatan loyalitas; stok dengan mutasi; voucher terbatas dan kedaluwarsa; aktivitas; layanan & harga; profil usaha; akun kasir.
- Laporan tanggal terpilih, CSV dengan BOM agar terbaca baik di spreadsheet, arsip JSON baca-saja, tampilan mobile dan tema gelap.

## Penting sebelum dipakai secara publik

- **Ini MVP, bukan layanan SaaS siap produksi.** Jalankan uji fungsional, uji keamanan, pengujian beban, audit perlindungan data, monitoring, dan peninjauan kebutuhan bisnis sebelum melayani pelanggan nyata.
- **Wajib HTTPS** di depan server bila tersedia di internet; `NODE_ENV=production` membuat cookie Secure sehingga login di HTTP tidak akan bekerja. Gunakan reverse proxy terpercaya dan set `TRUST_PROXY=1` hanya jika benar berada di belakang satu proxy yang terkontrol.
- Gunakan volume disk persisten dan backup terjadwal database SQLite, termasuk file WAL bila sedang aktif; alternatif paling aman adalah backup API SQLite saat operasional atau menghentikan server sebelum menyalin file DB. Arsip JSON aplikasi bersifat baca-saja dan **tidak mendukung restore otomatis**. Uji prosedur pemulihan secara berkala.
- Tidak ada migrasi data otomatis dari `coba.html`; data lama dalam localStorage browser tidak dipindahkan otomatis.
- SQLite cocok untuk deployment sederhana satu instance. Untuk skala banyak instance dan pengguna serentak tinggi, pertimbangkan migrasi terencana ke PostgreSQL dan sistem autentikasi, observabilitas, serta backup yang lebih matang.
- Grafik menggunakan Chart.js via CDN sehingga butuh koneksi internet untuk memuat grafik. Fungsi utama aplikasi tetap berjalan tanpa grafik.
- Data pendapatan di dashboard menjumlahkan pembayaran yang tercatat pada pesanan menurut tanggal pembuatan pesanan, **bukan tanggal pembayaran**. Laporan pembayaran periode tertentu pun menggunakan tanggal pembuatan pesanan dan jumlah yang telah dibayar hingga saat laporan dibuka; belum ada buku kas berbasis tanggal penerimaan pembayaran. Untuk akuntansi bisnis yang akurat, buat tabel transaksi pembayaran terpisah dan laporan berdasarkan tanggal pembayaran.
- Nomor telepon pelanggan merupakan data pribadi; batasi akses, definisikan masa simpan dan prosedur penghapusan, lalu pastikan kepatuhan aturan perlindungan data yang berlaku.
- Pengiriman WhatsApp tidak otomatis: pengguna harus menekan tombol bagikan dan mengirim sendiri di WhatsApp. Integrasi otomatis memerlukan API resmi, biaya, izin, dan tata kelola template.
- Struk dicetak dari browser; hasil nyata pada printer thermal berbeda-beda dan harus diuji terhadap printer target.
- Pengguna kasir dapat menambah pelanggan, membuat pesanan, mengubah status, mencatat pembayaran, dan mutasi stok. Pengaturan, voucher, laporan penuh, aktivitas, dan unduh backup hanya untuk pemilik.

## Masalah yang perlu diprioritaskan berikutnya

1. Ledger pembayaran per transaksi dan waktu pembayaran, pembatalan/refund, dan koreksi kas dengan jejak audit.
2. Verifikasi email/reset password dan pengelolaan sesi perangkat.
3. Kunci migrasi dan strategi backup terotomasi beserta uji pemulihan.
4. Pagination server-side, validasi bisnis lanjut, tes otomatis, CSRF defense eksplisit, dan pembatasan laju pada endpoint sensitif.
5. Pendaftaran usaha terkendali (anti-spam/kuota) dan kepatuhan privasi sebelum membuka registrasi ke publik.
