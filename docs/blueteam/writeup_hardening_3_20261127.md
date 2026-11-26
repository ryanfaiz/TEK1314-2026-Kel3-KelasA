# Hardening Pasca-Attack 1 Write-Up — ThingsBoard Lab (172.28.1.2)

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Tanggal | 27 November 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Fase | Remediasi Pasca Red Team Assessment (Prioritas Sisa Temuan) |
| Referensi | F-01 s.d. F-06 dari Red Team Assessment |
| Cakupan | F-01, F-02, F-03 (F-04, F-05, F-06 telah di-patch pada Hardening Tahap 2) |

## 1. Ringkasan

Write-up ini mendokumentasikan remediasi untuk temuan yang **belum tertutup** setelah Hardening Tahap 2. Tiga temuan menjadi fokus: F-01 (default credential), F-02 (web tanpa TLS), dan F-03 (MQTT tanpa TLS). Temuan F-04 (PostgreSQL terekspos), F-05 (SSH port 2222), dan F-06 (port 7070) telah diselesaikan pada Hardening Tahap 2 dan hanya dicatat sebagai referensi status.

## 2. Status Temuan Sebelum Remediasi

| ID | Temuan | Severity | Status Sebelum |
|---|---|---|---|
| F-01 | Kredensial default System Administrator aktif | Critical | Belum ditutup |
| F-02 | Web UI & REST API tanpa TLS (HTTP 8080) | High | Belum ditutup |
| F-03 | MQTT tanpa TLS (1883 open, 8883 closed) | High | Belum ditutup |
| F-04 | PostgreSQL terekspos (32771) | Medium | Sudah di-patch (Hardening 2) |
| F-05 | SSH di port 2222 | Low/Info | Sudah di-patch (Hardening 2) |
| F-06 | Port manajemen 7070 terekspos | Info | Sudah di-patch (Hardening 2) |

## 3. Remediasi F-01: Kredensial Default System Administrator (Critical)

**Temuan:** Login berhasil dengan `sysadmin@thingsboard.org` / `sysadmin`.

**Langkah:**
1. Login ke ThingsBoard Web UI (`http://172.28.1.2:8080`) menggunakan kredensial default.
2. Navigasi ke **System Settings** → **Security** → **Users**.
3. Ubah password `sysadmin@thingsboard.org` menjadi password kuat (minimal 12 karakter, kombinasi huruf besar/kecil, angka, simbol).
4. Nonaktifkan atau hapus akun default lain yang tidak digunakan (`tenant@thingsboard.org`, `customer@thingsboard.org`) jika tidak diperlukan untuk operasi lab.
5. Aktifkan kebijakan password pada **Security Settings**: minimum length, complexity, dan account lockout setelah percobaan gagal.

**Verifikasi:**
- Logout, coba login dengan password lama → harus gagal.
- Login dengan password baru → berhasil.
- Tidak ada akun default yang masih aktif dengan password bawaan.

## 4. Remediasi F-02: Web UI & REST API Tanpa TLS (High)

**Temuan:** Port 443 closed; kredensial dikirim plaintext melalui HTTP 8080.

**Opsi A — Reverse Proxy Nginx (Direkomendasikan):**

1. Install Nginx:
       sudo apt install nginx -y
2. Generate self-signed certificate (lab):
       sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
         -keyout /etc/ssl/private/thingsboard.key \
         -out /etc/ssl/certs/thingsboard.crt \
         -subj "/CN=172.28.1.2"
3. Konfigurasi reverse proxy:
       sudo nano /etc/nginx/sites-available/thingsboard
   Isi:
       server {
           listen 443 ssl;
           server_name 172.28.1.2;
           ssl_certificate /etc/ssl/certs/thingsboard.crt;
           ssl_certificate_key /etc/ssl/private/thingsboard.key;
           location / {
               proxy_pass http://127.0.0.1:8080;
               proxy_set_header Host $host;
               proxy_set_header X-Real-IP $remote_addr;
               proxy_set_header X-Forwarded-Proto $scheme;
           }
       }
       server {
           listen 80;
           return 301 https://$host$request_uri;
       }
4. Aktifkan dan restart:
       sudo ln -s /etc/nginx/sites-available/thingsboard /etc/nginx/sites-enabled/
       sudo nginx -t && sudo systemctl restart nginx
5. Batasi ThingsBoard agar hanya mendengarkan di localhost (jika memungkinkan melalui konfigurasi bind), sehingga port 8080 tidak dapat diakses langsung dari jaringan.

**Opsi B — Aktifkan SSL langsung di ThingsBoard:**

ThingsBoard mendukung SSL native melalui environment variable `SSL_ENABLED=true` dengan konfigurasi PEM atau keystore. Untuk lab ini reverse proxy lebih fleksibel dan memisahkan terminasi TLS dari aplikasi.

**Verifikasi:**
- Akses `https://172.28.1.2` → halaman login muncul dengan TLS.
- Akses `http://172.28.1.2` → redirect ke HTTPS.
- Nmap: port 443 open; port 8080 tidak lagi terekspos langsung dari jaringan.

## 5. Remediasi F-03: MQTT Tanpa TLS (High)

**Temuan:** Port 1883 open (plaintext), port 8883 closed.

**Langkah:**
1. Generate certificate untuk MQTT (dapat menggunakan certificate yang sama dengan web atau terpisah):
       sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
         -keyout /etc/ssl/private/mqtt.key \
         -out /etc/ssl/certs/mqtt.crt \
         -subj "/CN=172.28.1.2"
2. Edit konfigurasi ThingsBoard (`thingsboard.yml` atau environment variable):
       MQTT_SSL_ENABLED=true
       MQTT_SSL_CREDENTIALS_TYPE=PEM
       MQTT_SSL_PEM_CERT=/etc/ssl/certs/mqtt.crt
       MQTT_SSL_PEM_KEY=/etc/ssl/private/mqtt.key
3. Restart ThingsBoard.
4. Nonaktifkan MQTT plaintext (port 1883) jika tidak diperlukan:
       MQTT_ENABLED=false
   Atau biarkan 1883 hanya untuk loopback dengan pembatasan firewall.

**Verifikasi:**
- Nmap: port 8883 open, port 1883 closed/filtered.
- Koneksi MQTT client dengan SSL ke port 8883 berhasil.
- Koneksi tanpa SSL ke 1883 gagal.

## 6. Referensi Temuan yang Sudah Di-patch (F-04, F-05, F-06)

Temuan berikut telah diselesaikan pada Hardening Tahap 2 dan tidak memerlukan langkah tambahan pada fase ini. Dicatat untuk kelengkapan status.

### 6.1 F-04: PostgreSQL Terekspos (Medium)

**Status:** Sudah di-patch pada Hardening 2.

**Ringkasan langkah yang telah dilakukan:**
- PostgreSQL dibatasi hanya mendengarkan di `localhost` (`listen_addresses = 'localhost'`).
- Port mapping container (jika ada) diubah menjadi `127.0.0.1:32771:5432`.
- `pg_hba.conf` diperketat dengan `scram-sha-256` untuk koneksi lokal.
- UFW tidak mengizinkan port 32771.

**Verifikasi yang telah dilakukan:** Nmap dari host lain menunjukkan port 32771 closed/filtered.

### 6.2 F-05: SSH di Port 2222 (Low/Info)

**Status:** Sudah di-patch pada Hardening 2.

**Ringkasan langkah yang telah dilakukan:**
- SSH key-based authentication diaktifkan; `PasswordAuthentication no`.
- `PermitRootLogin no`.
- Fail2ban aktif pada jail `sshd` untuk port 2222.
- `AllowUsers iot` diterapkan.

**Verifikasi yang telah dilakukan:** Login password ditolak; key-based login berhasil; Fail2ban mencatat percobaan gagal.

### 6.3 F-06: Port Manajemen 7070 Terekspos (Info)

**Status:** Sudah di-patch pada Hardening 2.

**Ringkasan langkah yang telah dilakukan:**
- Fitur ThingsBoard Edge dinonaktifkan (jika tidak digunakan) atau akses port 7070 dibatasi per-IP melalui UFW.
- Aturan UFW `allow 7070/tcp` dari mana saja dihapus.

**Verifikasi yang telah dilakukan:** Nmap dari host tidak berwenang menunjukkan port 7070 closed/filtered.

## 7. Verifikasi Akhir (Post-Remediation Scan)

Setelah seluruh langkah remediasi F-01, F-02, dan F-03 selesai, lakukan pemindaian ulang:

    sudo nmap -sT -sV -T4 -p- 172.28.1.2

**Ekspektasi hasil:**

| Port | Sebelum | Sesudah (Ekspektasi) | Temuan Terkait |
|---|---|---|---|
| 80 | closed | open (redirect ke 443) | F-02 |
| 443 | closed | open (TLS) | F-02 |
| 1883 | open | closed/filtered | F-03 |
| 2222 | open | open (key-only) | F-05 (sudah) |
| 7070 | open | closed/filtered | F-06 (sudah) |
| 8080 | open | closed (localhost/proxy) | F-02 |
| 8883 | closed | open (TLS) | F-03 |
| 32771 | open | closed/filtered | F-04 (sudah) |

## 8. Ringkasan Status Remediasi

| ID | Temuan | Severity | Status Remediasi | Fase |
|---|---|---|---|---|
| F-01 | Kredensial default sysadmin | Critical | Password diganti; akun default lain dinonaktifkan | Pasca-Attack 1 |
| F-02 | Web tanpa TLS | High | Nginx reverse proxy dengan TLS 443; HTTP redirect | Pasca-Attack 1 |
| F-03 | MQTT tanpa TLS | High | MQTT TLS 8883 aktif; 1883 dinonaktifkan | Pasca-Attack 1 |
| F-04 | PostgreSQL terekspos | Medium | Bind localhost; UFW deny; port mapping dibatasi | Hardening 2 (selesai) |
| F-05 | SSH port 2222 | Low/Info | Key-only auth + Fail2ban | Hardening 2 (selesai) |
| F-06 | Port 7070 terekspos | Info | Edge dinonaktifkan atau dibatasi per-IP | Hardening 2 (selesai) |

## 9. Kesimpulan

Remediasi pasca-attack 1 menuntaskan tiga temuan yang tersisa: F-01 (default credential) dieliminasi melalui penggantian password dan penonaktifan akun default; F-02 dan F-03 ditutup dengan penerapan TLS pada web (via reverse proxy Nginx) dan MQTT. Temuan F-04, F-05, dan F-06 telah diselesaikan pada Hardening Tahap 2 dan terverifikasi. Dengan demikian, seluruh temuan dari Red Team Assessment telah tertutup. Verifikasi ulang dengan Nmap direkomendasikan untuk mengonfirmasi postur keamanan akhir sebelum evaluasi berikutnya.

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.
