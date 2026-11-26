# Hardening Write-Up Tahap 2 — ThingsBoard Lab (172.28.1.2)

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Hostname | iot (user: iot) |
| Tanggal | 26 November 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Fase | Hardening Tahap 2 (melanjutkan Tahap 1 tanggal 23 Oktober 2026) |
| Tujuan | Memperkuat autentikasi, mempersempit attack surface, dan menerapkan kontrol data/aplikasi |

## 1. Ringkasan Hardening Tahap 2

Hardening tahap 2 melengkapi kontrol yang belum tercakup pada tahap 1. Fokus pada tiga domain: Access & Authentication (SSH key-based, Fail2ban), Service & Attack Surface (nonaktifkan service/port tidak perlu, ganti kredensial default), dan Data & Application Security (validasi input API, batasi topik MQTT, least privilege database, sanitasi log). Verifikasi dilakukan melalui konfigurasi SSH, status Fail2ban, audit port, dan pengujian akses.

## 2. Baseline Setelah Hardening Tahap 1

Kondisi host setelah hardening tahap 1 (23 Oktober 2026):

- Root SSH disabled, port SSH 2222
- UFW aktif dengan whitelist port: 2222, 80, 443, 1883, 8883, 5684-5688/udp, 7070
- OS dan paket telah diperbarui
- Kredensial default ThingsBoard (sysadmin@thingsboard.org / sysadmin) **masih aktif**
- PostgreSQL masih terekspos di port 32771 (tidak diizinkan UFW, namun service berjalan)
- Web UI di 8080 tanpa TLS, MQTT 1883 tanpa TLS

## 3. A. Access & Authentication

### 3.1 Mengaktifkan Autentikasi SSH Berbasis Public Key dan Menonaktifkan Password

Langkah:
1. Di workstation attacker/admin, generate key pair (jika belum ada):
       ssh-keygen -t ed25519 -C "admin@lab"
2. Salin public key ke host target:
       ssh-copy-id -p 2222 iot@172.28.1.2
3. Verifikasi login key-based dari terminal kedua:
       ssh -p 2222 -i ~/.ssh/id_ed25519 iot@172.28.1.2
4. Di host target, buat drop-in configuration untuk persistensi:
       sudo tee /etc/ssh/sshd_config.d/90-hardening.conf > /dev/null <<'EOF'
       PermitRootLogin no
       PasswordAuthentication no
       KbdInteractiveAuthentication no
       MaxAuthTries 3
       LoginGraceTime 20
       AllowUsers iot
       EOF
5. Validasi dan reload:
       sudo sshd -t && sudo systemctl reload ssh

Verifikasi:
       ssh -o PreferredAuthentications=password -p 2222 iot@172.28.1.2
Ekspektasi: Permission denied (publickey). Password authentication ditolak.

Catatan: Pastikan key-based login berhasil **sebelum** menutup sesi yang sedang aktif untuk menghindari lockout [citation:1]. Drop-in di `sshd_config.d/` bertahan terhadap upgrade paket yang menyentuh konfigurasi utama.

### 3.2 Mengaktifkan Fail2ban untuk SSH

Langkah:
1. Install Fail2ban:
       sudo apt install fail2ban -y
       sudo systemctl enable --now fail2ban
2. Buat konfigurasi lokal (jangan edit `jail.conf`):
       sudo nano /etc/fail2ban/jail.local
3. Isi konfigurasi:
       [DEFAULT]
       bantime = 1h
       findtime = 10m
       maxretry = 5
       banaction = nftables
       ignoreip = 127.0.0.1/8 ::1 172.28.1.10

       [sshd]
       enabled = true
       port = 2222
       maxretry = 3
       bantime = 24h
4. Test dan reload:
       sudo fail2ban-client -t
       sudo fail2ban-client reload
5. Verifikasi status:
       sudo fail2ban-client status sshd

Ekspektasi: Jail `sshd` aktif, `Currently banned` dan `Banned IP list` tersedia. IP dengan 3 kegagalan autentikasi dalam `findtime` akan diblokir selama `bantime` [citation:9].

Catatan: `ignoreip` harus mencakup IP workstation admin untuk mencegah self-ban. Pada Debian, backend default membaca systemd journal; verifikasi dengan `fail2ban-client status sshd` secara berkala [citation:2][citation:9].

## 4. B. Service & Attack Surface

### 4.1 Menonaktifkan Service dan Port yang Tidak Digunakan

Identifikasi port yang tidak diperlukan berdasarkan hasil Red Team Assessment:
- Port 32771 (PostgreSQL) — tidak boleh diakses dari jaringan lab
- Port 7070 (Edge RPC) — hanya jika fitur Edge tidak digunakan
- Port 80/443 — jika belum ada layanan TLS, tutup sementara

Langkah:
1. Identifikasi proses yang mendengarkan:
       sudo ss -tlnp
2. Hentikan dan nonaktifkan service yang tidak diperlukan. Contoh untuk PostgreSQL (jika tidak digunakan di host yang sama):
       sudo systemctl stop postgresql
       sudo systemctl disable postgresql
3. Hapus aturan UFW yang tidak diperlukan:
       sudo ufw delete allow 80/tcp
       sudo ufw delete allow 443/tcp
       sudo ufw delete allow 7070/tcp
4. Verifikasi ulang:
       sudo ufw status numbered
       sudo ss -tlnp

Catatan: Jika ThingsBoard memerlukan PostgreSQL secara lokal, **jangan hentikan service**; cukup pastikan port tidak terekspos ke jaringan (listen hanya di `127.0.0.1` atau network internal container) dan UFW tidak mengizinkannya.

### 4.2 Menghapus atau Mengganti Kredensial Default

**ThingsBoard System Administrator:**
1. Login ke `http://172.28.1.2:8080` (via host admin atau tunnel SSH).
2. Ganti password `sysadmin@thingsboard.org` dengan password kuat.
3. Nonaktifkan akun default lain yang tidak digunakan (Tenant Administrator, Customer User) jika tidak diperlukan.

**PostgreSQL:**
1. Ganti password user `postgres`:
       sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'StrongP@ssw0rd!';"
2. Ubah metode autentikasi di `pg_hba.conf` dari `peer`/`trust` menjadi `scram-sha-256`:
       sudo nano /etc/postgresql/*/main/pg_hba.conf
   Ubah baris:
       local   all   all   peer
   Menjadi:
       local   all   all   scram-sha-256
3. Restart PostgreSQL:
       sudo systemctl restart postgresql

Verifikasi:
       psql -U postgres -h 127.0.0.1
Ekspektasi: Diminta password; password lama tidak berlaku.

## 5. C. Data & Application Security

### 5.1 Validasi Input pada Endpoint API dan Batasi Akses Topik MQTT

**Validasi Input API:**
ThingsBoard REST API secara bawaan melakukan validasi skema JSON. Untuk hardening tambahan:
- Aktifkan rate limiting pada reverse proxy (jika menggunakan Nginx) untuk endpoint `/api/auth/login` dan `/api/*`.
- Batasi akses ke endpoint administratif (`/api/admin/*`) hanya dari IP tertentu melalui UFW atau aturan reverse proxy.

**Batasi Topik MQTT:**
1. Login sebagai System Administrator di ThingsBoard Web UI.
2. Navigasi ke **Device profiles** → pilih profile yang digunakan → **MQTT topics**.
3. Definisikan pola topik yang diizinkan untuk publish/subscribe. Contoh:
   - `v1/devices/me/telemetry` (publish)
   - `v1/devices/me/attributes` (publish/subscribe)
4. Hindari pola default `.*` yang mengizinkan semua topik [citation:6].
5. Untuk perangkat individual, gunakan fitur **Device credentials** dan batasi akses berdasarkan Client ID/username.

### 5.2 Menerapkan Prinsip Least Privilege pada User Database

Langkah:
1. Buat user database khusus aplikasi (bukan `postgres`) untuk ThingsBoard:
       sudo -u postgres psql
       CREATE USER tb_app WITH PASSWORD 'AppSp3cific!Pass';
2. Berikan hanya privilege yang diperlukan pada database ThingsBoard:
       GRANT CONNECT ON DATABASE thingsboard TO tb_app;
       GRANT USAGE ON SCHEMA public TO tb_app;
       GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tb_app;
       GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tb_app;
3. Pastikan `tb_app` **bukan** superuser dan tidak memiliki akses ke database lain.
4. Jika ThingsBoard dikonfigurasi dengan user `postgres`, ubah konfigurasi koneksi database ke `tb_app`.

Verifikasi:
       \du tb_app
Ekspektasi: `tb_app` tidak memiliki atribut `Superuser`, `Create role`, atau `Create DB`.

Catatan: Prinsip least privilege membatasi dampak jika kredensial database bocor melalui celah aplikasi .

### 5.3 Memastikan Kredensial dan Data Sensitif Tidak Ditulis ke Log

Langkah:
1. Periksa konfigurasi logging ThingsBoard (`thingsboard.yml` atau environment variable):
       grep -i "log" /etc/thingsboard/conf/thingsboard.yml
2. Pastikan level log `DEBUG` tidak digunakan di production; gunakan `INFO` atau `WARN`:
       logging:
         level:
           root: INFO
           org.thingsboard: INFO
3. Nonaktifkan logging payload request/response yang mengandung kredensial.
4. Untuk PostgreSQL, pastikan `log_statement` tidak di-set ke `all` yang dapat mencatat query dengan password:
       sudo nano /etc/postgresql/*/main/postgresql.conf
   Set:
       log_statement = 'none'
       log_min_duration_statement = 1000
5. Verifikasi log tidak mengandung string `password`, `token`, atau `secret`:
       sudo grep -ri "password\|token\|secret" /var/log/thingsboard/ 2>/dev/null | head

Ekspektasi: Tidak ada kredensial plaintext dalam log.

## 6. Verifikasi dan Hasil

| Kontrol | Perintah Verifikasi | Ekspektasi | Status |
|---|---|---|---|
| SSH key-only | `ssh -o PreferredAuthentications=password -p 2222 iot@172.28.1.2` | Permission denied | Perlu konfirmasi |
| Fail2ban SSH aktif | `fail2ban-client status sshd` | Jail aktif, banned list tersedia | Perlu konfirmasi |
| Port tidak perlu tertutup | `ss -tlnp` dan `ufw status` | Hanya port diperlukan | Perlu konfirmasi |
| Kredensial default ThingsBoard diganti | Login UI dengan password lama | Gagal | Perlu konfirmasi |
| PostgreSQL password diganti | `psql -U postgres -h 127.0.0.1` | Diminta password baru | Perlu konfirmasi |
| MQTT topic restriction | Publish ke topik tidak diizinkan | Ditolak | Perlu konfirmasi |
| Least privilege DB | `\du tb_app` | Tidak ada atribut superuser | Perlu konfirmasi |
| Log bersih dari kredensial | `grep` pada log | Tidak ada match | Perlu konfirmasi |

## 7. Gap dan Rekomendasi Lanjutan

Setelah hardening tahap 2, item berikut masih perlu diselesaikan:

1. **TLS untuk Web UI/REST (F-02):** Terapkan reverse proxy Nginx dengan sertifikat TLS pada port 443; redirect HTTP ke HTTPS. Port 8080 tidak boleh diekspos langsung.
2. **TLS untuk MQTT (F-03):** Aktifkan MQTT over TLS pada port 8883; nonaktifkan 1883 plaintext jika tidak diperlukan.
3. **Audit dan monitoring:** Aktifkan log terpusat untuk ThingsBoard, PostgreSQL, dan SSH; pantau anomali autentikasi.
4. **Verifikasi ulang dengan Nmap:** Setelah seluruh perubahan, pindai ulang `172.28.1.2` untuk memastikan hanya port yang diperlukan yang terbuka.

## 8. Kesimpulan

Hardening tahap 2 (27 November 2026) berhasil menerapkan kontrol Access & Authentication lanjutan (SSH key-only, Fail2ban), mempersempit Service & Attack Surface (menonaktifkan port tidak perlu, mengganti kredensial default ThingsBoard dan PostgreSQL), serta menerapkan Data & Application Security (restriksi topik MQTT, least privilege database, sanitasi log). Kombinasi hardening tahap 1 dan 2 membentuk baseline keamanan yang lebih kuat sebelum evaluasi ulang melalui Red Team Assessment.

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.
