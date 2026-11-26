# Hardening Final & Monitoring Write-Up — ThingsBoard Lab (172.28.1.2)

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Tanggal | 27 November 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Fase | Hardening Final + Monitoring Traffic (Pasca Attack Fase 2) |
| Referensi | Hanya temuan F2-01 s.d. F2-07 |
| Tujuan | Menutup temuan Attack Fase 2 dan menambahkan monitoring sederhana |

## 1. Ringkasan

Hardening final ini menindaklanjuti temuan dari Attack Fase 2. Hasil: banner SSH tidak berhasil diminimalkan (F2-02 not work), rate limiting berhasil diterapkan dan terverifikasi melalui DDOSIFY (F2-05), kontrol positif dipertahankan (F2-03, F2-04, F2-06), dan layer monitoring ditambahkan menggunakan **Wireshark** serta **watch** pada log akses HTTPS sebagai implementasi minimal visibilitas traffic.

## 2. Status Temuan Fase 2

| ID | Temuan | Severity | Status Final | Catatan |
|---|---|---|---|---|
| F2-01 | OS fingerprinting | Info | Diterima | Tidak dapat dihilangkan sepenuhnya |
| F2-02 | SSH banner | Low | **Not work** | `VersionAddendum none` tidak efektif pada OpenSSH 10.0p2 Debian |
| F2-03 | HTTP banner | Info (positif) | Dipertahankan | `server_tokens off` aktif |
| F2-04 | ARP spoofing | Info (positif) | Dipertahankan | Isolasi segmen |
| F2-05 | Rate limiting | Medium | **Berhasil** | Nginx `limit_req` + verifikasi DDOSIFY |
| F2-06 | MQTT tidak diakses | Info (positif) | Diverifikasi | Port ditutup |
| F2-07 | Kesalahan perintah | Info | Dokumentasi | — |
| F2-08 | Ketiadaan monitoring | Info | **Wireshark + watch** | Implementasi minimal |

## 3. Remediasi F2-02: SSH Banner Information Disclosure (Low) — Not Work

**Temuan:** Banner SSH menampilkan `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4`.

**Langkah yang dicoba:**
1. Edit konfigurasi SSH:
       sudo nano /etc/ssh/sshd_config.d/90-hardening.conf
2. Tambahkan baris:
       VersionAddendum none
3. Validasi dan reload:
       sudo sshd -t && sudo systemctl reload ssh
4. Verifikasi:
       nc -w 3 172.28.1.2 2222

**Hasil:** Banner **tidak berubah**. `VersionAddendum none` tidak efektif pada OpenSSH 10.0p2 Debian 13.

**Analisis:**
- Pada OpenSSH versi baru, `VersionAddendum` hanya menambahkan komentar setelah versi, bukan menggantikan string default. Debian mengompilasi OpenSSH dengan string versi yang sudah menyertakan `Debian-7+deb13u4` pada binary, sehingga tidak dapat diubah melalui `sshd_config`.
- Untuk benar-benar menyembunyikan versi, diperlukan patch source code dan rekompilasi (tidak direkomendasikan untuk lab).
- **Risiko:** Low. Informasi versi membantu penyerang mencocokkan CVE, tetapi akses SSH sudah dibatasi dengan key-only auth dan Fail2ban.

**Rekomendasi:** Terima sebagai risiko yang terkelola. Fokus pada kontrol akses (key-only, Fail2ban) yang sudah aktif.

## 4. Remediasi F2-05: Rate Limiting pada Endpoint Login (Medium) — Berhasil

**Temuan awal:** DDOSIFY mengirim 500 request ke `/login` tanpa satu pun respons 429/503.

**Langkah (Nginx):**

1. Tambahkan zona rate limiting di `nginx.conf`:
       limit_req_zone $binary_remote_addr zone=login_zone:10m rate=5r/s;
       limit_conn_zone $binary_remote_addr zone=conn_zone:10m;

2. Terapkan pada location login:
       location /api/auth/login {
           limit_req zone=login_zone burst=10 nodelay;
           limit_conn conn_zone 20;
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-Proto $scheme;
       }

3. Reload:
       sudo nginx -t && sudo systemctl reload nginx

**Verifikasi dengan DDOSIFY:**
    docker run -it --rm ddosify/ddosify:latest --target "https://172.28.1.2/login" -n 500 -d 30 -m GET -l linear -T 10 --insecure

**Hasil:**
- Total request: 500, durasi 30 detik.
- Outcomes: **ok 160**, **429 0**, **503 340 (68.0%)**, 5xx 0, timeout 0.
- Status Code: **200 (OK) 160**, **503 (Service Unavailable) 340**.
- Latency E2E: p50 5.6 ms, p90 8.3 ms, p99 16 ms.
- Success Count 500 (100%), Failed Count 0.

**Analisis:**
- **Rate limiting berhasil.** 340 dari 500 request (68%) ditolak dengan **503 Service Unavailable**, menunjukkan Nginx membatasi request setelah burst terlampaui.
- Tidak ada respons 429 karena konfigurasi `limit_req` default mengembalikan **503** (bukan 429). Untuk mengembalikan 429, tambahkan `limit_req_status 429;` pada konfigurasi Nginx.
- Latency tetap rendah (p99 16 ms), menunjukkan server tidak kewalahan karena request berlebih ditolak di layer Nginx sebelum mencapai ThingsBoard.
- **Kesimpulan:** F2-05 berhasil ditutup. Rate limiting efektif mencegah abuse pada endpoint login.

**Rekomendasi tambahan:** Ubah status code menjadi 429 agar lebih semantik:
    limit_req_status 429;

## 5. Verifikasi F2-06: MQTT Tidak Diakses (Info Positif)

**Langkah verifikasi:**
1. Konfirmasi status port:
       sudo nmap -sT -p 1883,8883 172.28.1.2
2. Konfirmasi kebijakan UFW:
       sudo ufw status numbered | grep -E "1883|8883"

**Hasil:** Port 1883 dan 8883 filtered/closed. MQTT tidak dapat diakses. Diverifikasi dan didokumentasikan sebagai kontrol yang disengaja.

## 6. Konfirmasi Kontrol Positif (F2-03, F2-04)

### 6.1 F2-03: HTTP Banner Tidak Mengekspos Versi

    curl -skI https://172.28.1.2 | grep -i server

**Hasil:** `Server: nginx` tanpa versi. `server_tokens off;` aktif. Dipertahankan.

### 6.2 F2-04: ARP Spoofing Tidak Efektif

    sudo arp-scan --interface=enp0s8 --localnet

**Hasil:** Hanya target `172.28.1.2` yang muncul. Isolasi segmen dipertahankan.

## 7. Implementasi Monitoring: Wireshark + watch HTTPS

Sebagai implementasi minimal visibilitas traffic (prinsip Cybersecurity Onion), digunakan dua alat sederhana yang sudah tersedia: **Wireshark** untuk capture dan analisis paket, serta **watch** untuk memantau log akses Nginx secara real-time.

### 7.1 Wireshark Capture

**Tujuan:** Merekam dan menganalisis traffic ke target `172.28.1.2`, khususnya koneksi HTTPS (443) dan SSH (2222).

**Langkah:**
1. Install Wireshark (jika belum ada):
       sudo apt install wireshark tshark -y
2. Capture traffic ke target:
       sudo tshark -i enp0s8 -f "host 172.28.1.2" -w /tmp/tb_monitor.pcap
3. Biarkan capture berjalan saat melakukan pengujian (misalnya DDOSIFY atau login).
4. Hentikan dengan Ctrl+C, lalu analisis:
       tshark -r /tmp/tb_monitor.pcap -Y "tcp.port == 443" -T fields -e ip.src -e ip.dst -e tcp.dstport | head -20

**Ekspektasi:** Terlihat koneksi dari attacker (`172.28.1.101`) ke target (`172.28.1.2`) pada port 443, termasuk volume dan timing. Metadata terlihat meskipun konten terenkripsi TLS.

**Analisis:** Wireshark membuktikan bahwa traffic dapat direkam dan dianalisis. Untuk HTTPS, konten tidak terbaca (TLS), tetapi metadata (IP, port, timing, SNI) tetap terlihat. Ini adalah layer visibilitas dasar.

### 7.2 Watch Log Akses HTTPS (Nginx)

**Tujuan:** Memantau log akses Nginx secara real-time untuk melihat request yang masuk, termasuk status code 503 dari rate limiting.

**Langkah:**
1. Di host target (atau via SSH), jalankan:
       watch -n 1 'sudo tail -n 20 /var/log/nginx/access.log'
2. Lakukan pengujian DDOSIFY atau akses login.
3. Amati munculnya baris log dengan status 200 dan 503.

**Ekspektasi:** Log menampilkan request dari attacker dengan status 200 (ok) dan 503 (rate limited). Contoh:
    172.28.1.101 - - [27/Nov/2026:01:30:00 +0700] "GET /login HTTP/1.1" 200 3266
    172.28.1.101 - - [27/Nov/2026:01:30:01 +0700] "GET /login HTTP/1.1" 503 0

**Analisis:** `watch` pada log akses memberikan visibilitas real-time terhadap request yang masuk dan efektivitas rate limiting. Ini melengkapi Wireshark (level paket) dengan level aplikasi (HTTP status).

### 7.3 Integrasi dengan Skenario Fase 2

- **DDOSIFY:** Wireshark menangkap lonjakan koneksi ke port 443; `watch` pada log Nginx menunjukkan 503 untuk request yang dibatasi.
- **SSH attempt:** Wireshark menangkap koneksi ke port 2222; Fail2ban log dapat dipantau dengan `watch`.
- **ARP spoofing:** Wireshark dapat mendeteksi anomali ARP jika capture dimulai sebelum serangan (filter `arp`).

## 8. Verifikasi Akhir

    sudo nmap -sT -sV -T4 -p- 172.28.1.2

**Ekspektasi:** Hanya port 80, 443, 2222 terbuka; 1883/8883/7070/8080/32771 filtered.

**Verifikasi rate limiting:** DDOSIFY menunjukkan 503 untuk sebagian request (terbukti: 340/500 = 68%).

**Verifikasi monitoring:**
- Wireshark: `/tmp/tb_monitor.pcap` berisi traffic ke `172.28.1.2`.
- `watch` pada `/var/log/nginx/access.log` menampilkan status 200 dan 503 secara real-time.

## 9. Ringkasan Status Remediasi Fase 2

| ID | Temuan | Severity | Status Final | Catatan |
|---|---|---|---|---|
| F2-01 | OS fingerprinting | Info | Diterima | Tidak dapat dihilangkan |
| F2-02 | SSH banner | Low | **Not work** | `VersionAddendum none` tidak efektif; terima risiko |
| F2-03 | HTTP banner | Info (positif) | Dipertahankan | `server_tokens off` |
| F2-04 | ARP spoofing | Info (positif) | Dipertahankan | Isolasi segmen |
| F2-05 | Rate limiting | Medium | **Berhasil** | 340/500 request 503 (68%) |
| F2-06 | MQTT tidak diakses | Info (positif) | Diverifikasi | Port ditutup |
| F2-07 | Kesalahan perintah | Info | Dokumentasi | — |
| F2-08 | Ketiadaan monitoring | Info | **Wireshark + watch** | Implementasi minimal |

## 10. Rekomendasi Lanjutan

1. **SSH banner (F2-02):** Terima sebagai risiko Low; fokus pada key-only auth dan Fail2ban yang sudah aktif. Jika benar-benar diperlukan, patch OpenSSH source (tidak direkomendasikan).
2. **Rate limiting:** Ubah `limit_req_status 429;` agar status code lebih semantik.
3. **Monitoring:** Perluas Wireshark dengan filter otomatis atau script `tshark` untuk alert sederhana (misalnya lonjakan koneksi).
4. **Log rotation:** Pastikan log Nginx dirotasi agar `watch` tidak membaca file yang terlalu besar.
5. **Red Team ulang:** Lakukan assessment ulang dengan rate limiting dan monitoring aktif untuk mengukur detection coverage.

## 11. Kesimpulan

Hardening final menindaklanjuti temuan Attack Fase 2 dengan hasil campuran: **F2-05 (rate limiting) berhasil** dengan bukti 340/500 request ditolak (503), sementara **F2-02 (SSH banner) tidak berhasil** karena keterbatasan OpenSSH 10.0p2 Debian dan diterima sebagai risiko Low. Kontrol positif (F2-03, F2-04, F2-06) dipertahankan dan diverifikasi. Layer monitoring ditambahkan menggunakan **Wireshark** (level paket) dan **watch** pada log akses Nginx (level aplikasi), memberikan visibilitas traffic ke target dan efektivitas rate limiting. Dengan demikian, seluruh temuan Fase 2 telah ditutup atau diterima sebagai risiko yang terkelola.

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.
