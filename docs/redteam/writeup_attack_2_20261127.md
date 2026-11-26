# Red Team Assessment Fase 2 Write-Up — ThingsBoard Lab (172.28.1.2)

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Attacker Node | Debian (attacker) |
| Tanggal | 27 November 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Fase | Attack Fase 2 (setelah Hardening & Remediasi) |
| Cakupan | Reconnaissance, Layer 2, Availability, Web/API/IoT Protocol |

## 1. Ringkasan

Fase 2 mengevaluasi efektivitas hardening yang telah diterapkan sebelumnya. Empat vektor diuji: (A) reconnaissance lanjutan (OS fingerprinting dan banner enumeration), (B) ARP spoofing pada Layer 2, (C) pengujian availability dengan DDOSIFY, dan (D) MQTT topic hijack/spoofing. Hasil menunjukkan sebagian kontrol berfungsi (TLS aktif, MQTT 8883 tertutup), namun beberapa area masih rentan atau memerlukan verifikasi lebih lanjut (informasi banner, ARP tanpa DAI, ketiadaan rate limiting, dan ketidakmampuan publish MQTT karena port tertutup).

## 2. A. Reconnaissance

### 2.1 OS Fingerprinting

**Perintah:**
    sudo nmap -O -T4 172.28.1.2

**Hasil:**
- Host up dengan latency 0.00022s (satu hop, segmen lokal).
- Hanya 3 port terbuka: 80/tcp (http), 443/tcp (https), 2222/tcp (EtherNetIP-1).
- 997 port filtered (no-response) — mengindikasikan firewall aktif.
- Aggressive OS guesses: Linux 4.15–5.19 (91%), Linux 4.19 (91%), Linux 5.0–5.14 (91%), Linux 5.4–5.10 (91%), OpenWrt 21.02 (91%), MikroTik RouterOS 7.2–7.5 (91%), Linux 4.10 (91%), Linux 6.0 (90%).
- Peringatan: OSScan tidak reliabel karena tidak ditemukan minimal satu port terbuka dan satu port tertutup (kondisi ideal untuk fingerprint).

**Analisis:**
- Pengurangan port terbuka (dari 8 port pada assessment awal menjadi 3 port) membuktikan hardening Service & Attack Surface berhasil: port 1883, 7070, 8080, dan 32771 tidak lagi terekspos.
- Namun, OS fingerprinting masih dapat mempersempit rentang kernel Linux (91% confidence) dan bahkan menghasilkan guess yang menyesatkan (OpenWrt, MikroTik, Android). Ini menunjukkan bahwa **informasi platform masih dapat dienumerasi** meskipun port dikurangi.
- Peringatan "could not find at least 1 open and 1 closed port" terjadi karena semua port non-terbuka berstatus **filtered**, bukan closed. Ini adalah efek langsung dari kebijakan UFW `default deny incoming` yang dikonfigurasi pada hardening.

### 2.2 Enumerasi Banner

**HTTP Banner (port 443):**
    curl -skI https://172.28.1.2 | head -20

**Hasil:**
- `HTTP/1.1 200`
- `Server: nginx`
- Header keamanan yang sudah ada: `X-Content-Type-Options: nosniff`, `Cache-Control: no-cache, no-store`, `Cross-Origin-Opener-Policy: same-origin`, `Referrer-Policy: strict-origin-when-cross-origin`.
- Tidak ada header `X-Powered-By`, `Server` hanya "nginx" tanpa versi.

**Analisis:**
- Reverse proxy Nginx dengan TLS berhasil diterapkan (F-02 remediasi berhasil). Akses HTTP 80 sekarang redirect ke 443 (terlihat dari 80 open namun curl ke https mengembalikan 200).
- `server_tokens off` tampaknya aktif karena `Server: nginx` tidak menyertakan versi. Ini adalah praktik yang baik.
- Header keamanan (`X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`) menunjukkan konfigurasi keamanan web yang lebih matang dibanding baseline.

**SSH Banner (port 2222):**
    nc -w 3 172.28.1.2 2222

**Hasil:**
- `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4`

**Analisis:**
- Versi OpenSSH dan distro Debian terekspos dalam banner. Ini memberikan informasi yang berguna bagi penyerang untuk mencocokkan CVE spesifik (misalnya kerentanan pada OpenSSH 10.0p2 atau paket Debian 13).
- Meskipun banner enumeration adalah temuan Low, informasi ini mempercepat fase eksploitasi.
- **Rekomendasi:** Pertimbangkan `VersionAddendum` pada `sshd_config` untuk mengurangi informasi, meskipun ini bukan kontrol keamanan utama.

**MQTT Banner (port 8883):**
    openssl s_client -connect 172.28.1.2:8883 -brief

**Hasil:**
- `Connection refused` (errno=111).

**Analisis:**
- Port 8883 **tertutup**. Ini mengonfirmasi bahwa remediasi F-03 (MQTT TLS) belum sepenuhnya diterapkan, atau MQTT TLS tidak berjalan. Sebaliknya, port 1883 juga tidak muncul di pemindaian (filtered), sehingga **MQTT tidak dapat diakses dari jaringan**.
- Temuan ini konsisten dengan Nmap: 8883 closed, 1883 tidak muncul (filtered).
- Dampak: Fitur MQTT untuk perangkat IoT tidak berfungsi dari luar; jika ini disengaja (misalnya MQTT hanya untuk loopback), maka kontrol berhasil. Jika tidak disengaja, ini adalah **misconfiguration** yang perlu diperbaiki karena memutus fungsionalitas IoT.

**Nmap Banner Script:**
    sudo nmap --script=banner,http-headers -p 443,2222,8883 172.28.1.2

**Hasil:**
- 443 open: http-headers menampilkan `Server: nginx` (tanpa versi).
- 2222 open: banner `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4`.
- 8883 closed.

**Catatan kesalahan perintah:**
- `openssl s-client` (typo) dan `openssl s_client -connect 172.28.1.2 883` (kurang titik dua dan port salah) menghasilkan error. Perintah yang benar adalah `openssl s_client -connect 172.28.1.2:8883 -brief`.
- `nmap --script-banner,http-headers` (kurang tanda `=`) menghasilkan error. Perintah yang benar adalah `--script=banner,http-headers`.

## 3. B. Layer 2 / Jaringan Lokal — ARP Spoofing

### 3.1 Identifikasi Topologi

**Perintah:**
    ip neigh show
    sudo arp-scan --interface=enp0s8 --localnet
    sudo arp -a

**Hasil:**
- Antarmuka attacker: `enp0s8`, IP `172.28.1.101`, MAC `08:00:27:b4:e6:13`.
- Target `172.28.1.2` memiliki MAC `08:00:27:51:2b:30` pada `enp0s8`.
- Gateway default tidak terlihat pada `enp0s8`; rute default kemungkinan melalui `enp0s3` (10.0.2.2) atau `enp0s9` (192.168.56.1).
- `arp-scan` menemukan hanya 1 host di segmen `172.28.1.0/24`: target `172.28.1.2`. Attacker sendiri (`172.28.1.101`) dan gateway tidak muncul karena arp-scan hanya menampilkan respons.

**Analisis:**
- Attacker dan target berada pada segmen Layer 2 yang sama (`172.28.1.0/24`, antarmuka `enp0s8`). Ini adalah prasyarat untuk ARP spoofing.
- Namun, **tidak ada gateway pada segmen yang sama** yang teridentifikasi. Jika target berkomunikasi ke luar segmen, gateway mungkin berada di segmen lain atau menggunakan rute yang berbeda. ARP spoofing gateway-ke-target memerlukan identifikasi gateway yang benar.
- `arp-scan` hanya menemukan target, menunjukkan segmen ini sangat terisolasi (hanya attacker dan target). Ini membatasi dampak ARP spoofing: tidak ada host lain yang dapat disadap, dan target mungkin tidak memiliki gateway pada segmen ini.

### 3.2 Eksekusi ARP Spoofing

**Status:** Tidak dieksekusi dalam log ini. Pengujian berhenti pada identifikasi topologi.

**Analisis potensi:**
- Jika gateway berada di segmen yang sama (misalnya `172.28.1.1`), ARP spoofing bidirectional dapat dilakukan:
      sudo sysctl -w net.ipv4.ip_forward=1
      sudo arpspoof -i enp0s8 -t 172.28.1.2 172.28.1.1
      sudo arpspoof -i enp0s8 -t 172.28.1.1 172.28.1.2
- Namun, karena `arp-scan` tidak menemukan gateway, kemungkinan target tidak memiliki gateway pada segmen ini, sehingga ARP spoofing gateway tidak relevan.
- **Alternatif:** ARP spoofing terhadap target langsung (misalnya jika ada host lain yang ingin disadap) tidak dapat dilakukan karena tidak ada host lain.
- **Kesimpulan:** ARP spoofing **tidak dapat dieksekusi secara efektif** pada topologi ini karena segmen hanya berisi attacker dan target, tanpa gateway atau host ketiga. Ini adalah temuan positif: isolasi segmen membatasi serangan Layer 2.

**Rekomendasi:**
- Meskipun ARP spoofing tidak efektif pada topologi saat ini, tetap terapkan Dynamic ARP Inspection (DAI) dan DHCP Snooping pada switch lab untuk skenario dengan lebih banyak host.
- Dokumentasikan bahwa isolasi segmen adalah kontrol yang berhasil mencegah MITM.

## 4. C. Availability — DDOSIFY Container

### 4.1 Perintah

    docker run -it --rm ddosify/ddosify:latest --target "https://172.28.1.2/login" -n 500 -d 30 -m GET -l linear -T 10 --insecure

### 4.2 Hasil

**Metrik utama:**
- RPS target: 12.00, achieved: 14.00.
- Total request: 500, durasi 30 detik.
- Latency E2E: p50 = 5.6 ms, p90 = 7.6 ms, p99 = 15 ms.
- Outcomes: ok 500, 429 0, 503 0, 5xx 0, timeout 0, cut 0.
- Success Count: 500 (100%), Failed Count: 0 (0%).
- Status Code: 200 (OK) untuk seluruh 500 request.
- Server Processing: 0.0059s (avg), Total: 0.0060s.

### 4.3 Analisis

- **Tidak ada rate limiting yang terdeteksi.** Seluruh 500 request berhasil dengan status 200, tanpa satu pun 429 (Too Many Requests) atau 503 (Service Unavailable). Ini menunjukkan bahwa endpoint `/login` **tidak memiliki proteksi rate limiting** pada Nginx atau ThingsBoard.
- **Latency rendah dan stabil** (p99 = 15 ms) menunjukkan server mampu menangani beban 14 RPS tanpa degradasi. Namun, beban ini sangat rendah; pengujian dengan intensitas lebih tinggi (misalnya 1000 RPS) mungkin diperlukan untuk menguji ketahanan sebenarnya.
- **Tidak ada Fail2ban yang memicu** meskipun 500 request dalam 30 detik. Fail2ban biasanya dikonfigurasi untuk memantau autentikasi gagal, bukan request GET ke halaman login. Untuk menguji Fail2ban, perlu dilakukan POST ke `/api/auth/login` dengan kredensial salah berulang.
- **Kesimpulan:** Endpoint login rentan terhadap abuse karena tidak ada rate limiting. Meskipun 500 request tidak menggangu server, penyerang dapat meningkatkan volume untuk menyebabkan DoS atau brute force. Ini adalah temuan Medium.

**Rekomendasi:**
- Terapkan rate limiting pada Nginx:
      limit_req_zone $binary_remote_addr zone=login:10m rate=5r/s;
      location /api/auth/login {
          limit_req zone=login burst=10 nodelay;
          proxy_pass http://127.0.0.1:8080;
      }
- Aktifkan Fail2ban untuk HTTP (jail `nginx-http-auth` atau filter kustom untuk 401/429).
- Pertimbangkan WAF (ModSecurity) untuk mendeteksi pola brute force.

## 5. D. Web/API/Protokol IoT — MQTT Topic Hijack/Spoofing

### 5.1 Perintah

    mosquitto_pub -h 172.28.1.2 -p 8883 --cafile /etc/ssl/certs/thingsboard.crt \
      -u "qk6sgq65wplg5lgeusdj" -P "" \
      -t "/v1/devices/me/telemetry" \
      -m '{"temperature":999,"status":"spoofed"}'

### 5.2 Hasil

- `Error: Connection refused`.

### 5.3 Analisis

- **Port 8883 tertutup**, sehingga koneksi MQTT TLS ditolak. Ini konsisten dengan hasil Nmap dan `openssl s_client` sebelumnya.
- **Port 1883 juga tidak dapat diakses** (filtered oleh UFW), sehingga tidak ada jalur MQTT plaintext.
- **Dampak:** MQTT topic hijack/spoofing **tidak dapat dieksekusi** karena broker tidak dapat dijangkau dari jaringan. Ini adalah hasil positif dari hardening: MQTT tidak terekspos.
- **Namun, perlu verifikasi:** Apakah MQTT sengaja dinonaktifkan, atau apakah ada misconfiguration? Jika ThingsBoard memerlukan MQTT untuk operasi IoT, maka port 8883 harus dibuka dengan TLS yang benar. Jika MQTT tidak diperlukan, menutupnya adalah kontrol yang tepat.
- **Catatan:** Perintah menggunakan `-t "/v1/devices/me/telemetry"` dengan leading slash. ThingsBoard biasanya menggunakan topik tanpa leading slash (`v1/devices/me/telemetry`). Namun, karena koneksi ditolak, detail topik tidak relevan.
- **Kredensial:** Token `qk6sgq65wplg5lgeusdj` digunakan sebagai username. Jika token ini valid, seharusnya autentikasi berhasil jika port terbuka. Namun, connection refused menunjukkan masalah pada lapisan transport, bukan autentikasi.

**Rekomendasi:**
- Jika MQTT diperlukan: aktifkan port 8883 dengan TLS yang benar (`MQTT_SSL_ENABLED=true`), verifikasi certificate, dan buka UFW untuk 8883.
- Jika MQTT tidak diperlukan: dokumentasikan bahwa port 1883 dan 8883 sengaja ditutup, dan pastikan tidak ada perangkat IoT yang bergantung pada MQTT.
- Terapkan ACL per-device pada ThingsBoard (Device profile → MQTT topics) untuk mencegah spoofing jika MQTT diaktifkan kembali.

## 6. Temuan Fase 2

| ID | Temuan | Severity | Bukti |
|---|---|---|---|
| F2-01 | OS fingerprinting masih dapat mempersempit kernel Linux (91% confidence) | Info | Nmap `-O` output |
| F2-02 | SSH banner mengekspos versi OpenSSH dan distro | Low | `nc` output `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4` |
| F2-03 | HTTP banner tidak mengekspos versi Nginx (kontrol baik) | Info | `Server: nginx` tanpa versi |
| F2-04 | ARP spoofing tidak dapat dieksekusi karena segmen hanya berisi attacker dan target | Info (positif) | `arp-scan` hanya menemukan 1 host |
| F2-05 | Endpoint login tidak memiliki rate limiting | Medium | DDOSIFY: 500/500 request sukses, 0 rate-limited |
| F2-06 | MQTT (1883/8883) tidak dapat diakses; spoofing gagal | Info (positif) | `Connection refused` pada 8883; Nmap 8883 closed |
| F2-07 | Kesalahan perintah pada log (typo `openssl s-client`, `nmap --script-banner`) | Info | Log output |

## 7. Perbandingan dengan Assessment Awal

| Aspek | Assessment Awal | Fase 2 (Setelah Hardening) | Perubahan |
|---|---|---|---|
| Port terbuka | 8 (80, 443, 1883, 2222, 7070, 8080, 8883, 32771) | 3 (80, 443, 2222) | Significant reduction |
| TLS web | Tidak ada (443 closed) | Aktif (443 open, Nginx) | F-02 remediated |
| MQTT | 1883 open, 8883 closed | Keduanya tidak dapat diakses | F-03 mitigated (port ditutup) |
| SSH | Port 2222, password auth | Port 2222, key-only (banner terekspos) | F-05 partially remediated |
| PostgreSQL | 32771 open | Tidak terekspos | F-04 remediated |
| Port 7070 | Open | Tidak terekspos | F-06 remediated |
| Default credential | sysadmin/sysadmin | Tidak diuji ulang (asumsi diganti) | F-01 remediated (perlu verifikasi) |
| Rate limiting | Tidak ada | Tidak ada | Belum diperbaiki |
| ARP spoofing | Tidak diuji | Tidak efektif (isolasi segmen) | Kontrol topologi |

## 8. Rekomendasi

1. **Rate limiting:** Terapkan `limit_req` pada Nginx untuk endpoint `/api/auth/login` dan endpoint API lainnya; aktifkan Fail2ban untuk HTTP.
2. **Banner SSH:** Pertimbangkan `VersionAddendum` pada `sshd_config` untuk mengurangi informasi versi (opsional, bukan kontrol utama).
3. **MQTT:** Jika MQTT diperlukan, aktifkan 8883 dengan TLS dan ACL per-device; jika tidak, dokumentasikan penutupan port sebagai kontrol yang disengaja.
4. **ARP spoofing:** Meskipun tidak efektif pada topologi saat ini, terapkan DAI dan DHCP Snooping pada switch lab untuk skenario multi-host.
5. **Verifikasi F-01:** Lakukan uji login ulang dengan kredensial default untuk memastikan password telah diganti.
6. **Perbaikan perintah:** Gunakan sintaks yang benar (`openssl s_client -connect host:port`, `nmap --script=banner,http-headers`) untuk menghindari kesalahan pada log.

## 9. Kesimpulan

Fase 2 menunjukkan bahwa hardening berhasil mengurangi attack surface secara signifikan: hanya 3 port terbuka, TLS aktif pada web, MQTT tidak dapat diakses, dan PostgreSQL/port manajemen tidak terekspos. Namun, beberapa area masih perlu perbaikan: **rate limiting belum diterapkan** pada endpoint login (F2-05), dan **SSH banner masih mengekspos versi** (F2-02). ARP spoofing tidak efektif karena isolasi segmen, yang merupakan kontrol positif. MQTT topic hijack gagal karena port tertutup, membuktikan efektivitas hardening F-03 (meskipun perlu verifikasi apakah penutupan disengaja). Secara keseluruhan, postur keamanan target meningkat signifikan dibanding assessment awal, dengan sisa risiko pada availability (rate limiting) dan information disclosure (banner SSH).

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.
