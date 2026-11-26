# Hardening Write-Up Tahap 1 — ThingsBoard Lab (172.28.1.2)

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Hostname | iot (user: iot) |
| Tanggal | 23 Oktober 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Fase | Hardening Tahap 1 (dilakukan sebelum Red Team Assessment) |
| Tujuan | Memperkuat Access & Authentication serta mempersempit Service & Attack Surface |

## 1. Ringkasan Hardening

Hardening tahap 1 dilakukan sebagai persiapan sebelum pelaksanaan Red Team Assessment. Fokus pada dua domain: Access & Authentication serta Service & Attack Surface. Perubahan utama meliputi penonaktifan login root via SSH, pemindahan port SSH ke 2222, pembaruan OS/paket, dan penerapan firewall UFW dengan whitelist port yang diperlukan. Verifikasi dilakukan melalui status UFW dan pengujian konektivitas.

## 2. Baseline Sebelum Hardening

Kondisi awal host sebelum hardening:

- SSH berjalan pada port default dengan login root belum dibatasi
- OS dan paket belum diperbarui secara menyeluruh
- Firewall belum aktif; seluruh port layanan terbuka ke jaringan lab
- ThingsBoard berjalan dengan kredensial default (belum diubah pada tahap ini)
- Web UI di 8080 tanpa TLS, MQTT 1883 tanpa TLS, PostgreSQL terekspos

## 3. A. Access & Authentication

### 3.1 Menonaktifkan Login Root Langsung via SSH

Langkah:
1. Edit konfigurasi SSH:
       sudo nano /etc/ssh/sshd_config
2. Pastikan baris berikut:
       PermitRootLogin no
3. Validasi konfigurasi:
       sudo sshd -t
4. Restart layanan:
       sudo systemctl restart ssh

Verifikasi:
       ssh root@172.28.1.2 -p 2222
Ekspektasi: Permission denied (publickey,password).

Catatan: Jika root perlu tugas administratif, gunakan sudo dari akun non-root (iot). Alternatif yang lebih ketat: AllowUsers iot.

### 3.2 Mengubah Port SSH Default ke 2222

Langkah:
1. Edit konfigurasi SSH:
       sudo nano /etc/ssh/sshd_config
2. Ubah baris Port:
       Port 2222
3. Validasi dan restart:
       sudo sshd -t
       sudo systemctl restart ssh
4. Buka port di firewall (lihat bagian 4.2).

Verifikasi:
       ssh iot@172.28.1.2 -p 2222
Ekspektasi: Login berhasil dengan kredensial/key akun iot.

Catatan: Port obscurity bukan kontrol keamanan utama; tetap terapkan key-based auth dan fail2ban pada tahap berikutnya.

## 4. B. Service & Attack Surface

### 4.1 Memperbarui OS dan Paket

Perintah:
    sudo apt update && sudo apt upgrade -y

Verifikasi:
    sudo apt list --upgradable
    uname -r

Ekspektasi: Tidak ada paket upgradable tersisa; kernel dan paket berada pada versi terbaru yang tersedia di repositori Debian 13.

Catatan: Pertimbangkan reboot jika kernel diperbarui:
    sudo reboot

### 4.2 Konfigurasi Firewall (UFW)

Status UFW setelah konfigurasi (dari host iot):

| No | To | Action | From | Keterangan |
|---|---|---|---|---|
| 1 | 2222/tcp | ALLOW IN | Anywhere | SSH |
| 2 | 80/tcp | ALLOW IN | Anywhere | HTTP |
| 3 | 443/tcp | ALLOW IN | Anywhere | HTTPS |
| 4 | 1883/tcp | ALLOW IN | Anywhere | MQTT |
| 5 | 8883/tcp | ALLOW IN | Anywhere | MQTT TLS |
| 6 | 5684:5688/udp | ALLOW IN | Anywhere | CoAP / LwM2M |
| 7 | 7070/tcp | ALLOW IN | Anywhere | Edge RPC |
| 8 | 2222/tcp (v6) | ALLOW IN | Anywhere (v6) | SSH |
| 9 | 80/tcp (v6) | ALLOW IN | Anywhere (v6) | HTTP |
| 10 | 443/tcp (v6) | ALLOW IN | Anywhere (v6) | HTTPS |
| 11 | 1883/tcp (v6) | ALLOW IN | Anywhere (v6) | MQTT |
| 12 | 8883/tcp (v6) | ALLOW IN | Anywhere (v6) | MQTT TLS |
| 13 | 5684:5688/udp (v6) | ALLOW IN | Anywhere (v6) | CoAP / LwM2M |
| 14 | 7070/tcp (v6) | ALLOW IN | Anywhere (v6) | Edge RPC |

Status: active.

Perintah yang digunakan (ringkas):
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 2222/tcp comment 'SSH'
    sudo ufw allow 80/tcp comment 'HTTP'
    sudo ufw allow 443/tcp comment 'HTTPS'
    sudo ufw allow 1883/tcp comment 'MQTT'
    sudo ufw allow 8883/tcp comment 'MQTT TLS'
    sudo ufw allow 5684:5688/udp comment 'CoAP / LwM2M'
    sudo ufw allow 7070/tcp comment 'Edge RPC'
    sudo ufw enable
    sudo ufw status numbered

Catatan penting:
- Port 32771 (PostgreSQL) tidak diizinkan. Pastikan tidak ada aturan lain yang membukanya.
- Port 8080 (web UI ThingsBoard) tidak diizinkan. Jika akses web diperlukan untuk administrasi, tambahkan aturan terbatas per source IP, misalnya:
      sudo ufw allow from 172.28.1.10 to any port 8080 proto tcp comment 'ThingsBoard UI (admin host)'
- Port 80/443 dibuka untuk persiapan reverse proxy TLS; jika belum ada layanan TLS, aturan dapat dihapus untuk meminimalkan permukaan serangan.
- Aturan IPv6 duplikat otomatis dibuat oleh UFW; pastikan kebijakan deny incoming juga berlaku untuk IPv6.

Verifikasi firewall:
    sudo ufw status verbose
    sudo nmap -sT -p- 172.28.1.2

Ekspektasi: Hanya port yang diizinkan (2222, 80, 443, 1883, 8883, 5684-5688/udp, 7070) yang berstatus open/filtered sesuai kebijakan; port 32771 dan 8080 tidak dapat diakses dari luar.

## 5. Gap dan Rekomendasi Tahap 2

Hardening tahap 1 belum menutup seluruh permukaan serangan. Item berikut disarankan untuk tahap 2:

1. Ubah password default akun ThingsBoard (sysadmin@thingsboard.org) dan nonaktifkan akun default yang tidak digunakan.
2. Terapkan TLS pada web UI/REST (443) melalui reverse proxy Nginx dengan sertifikat valid; redirect HTTP ke HTTPS.
3. Aktifkan MQTT over TLS (8883) dan nonaktifkan 1883 plaintext jika tidak diperlukan.
4. SSH hardening lanjutan: key-based auth, PasswordAuthentication no, fail2ban, dan AllowUsers iot.
5. Audit logging: aktifkan log autentikasi dan pantau percobaan login gagal.
6. Verifikasi ulang dengan Nmap setelah hardening untuk memastikan port 32771 dan 8080 benar-benar tertutup dari jaringan.

## 7. Kesimpulan

Hardening tahap 1 (23 Oktober 2026) berhasil menerapkan kontrol dasar Access & Authentication (root SSH disabled, port SSH 2222) dan Service & Attack Surface (OS/paket diperbarui, UFW aktif dengan whitelist port). Firewall UFW terkonfirmasi active dengan 14 aturan (IPv4 dan IPv6) yang membatasi akses ke port layanan yang diperlukan. Hardening ini menjadi baseline sebelum pelaksanaan Red Team Assessment; temuan yang masih tersisa (default credential dan ketiadaan TLS) akan diverifikasi pada fase assessment berikutnya.

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.
