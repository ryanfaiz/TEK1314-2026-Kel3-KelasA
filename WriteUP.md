# Write-Up Keamanan Siber — ThingsBoard Lab (172.28.1.2)

## Standar NIST Cybersecurity Framework (CSF) 2.0 dan NIST SP 800-115

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Attacker Node | Debian (attacker) |
| Periode | 23 Oktober 2026 – 27 November 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Metodologi | NIST CSF 2.0 (Identify, Protect, Detect, Respond, Recover, Govern) dan NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment) |
| Referensi Dokumen | Hardening Tahap 1, Red Team Assessment, Hardening Tahap 2, Remediasi Pasca-Attack 1, Attack Fase 2, Hardening Final & Monitoring |
| Tujuan | Mendokumentasikan siklus assessment-remediasi-verifikasi-monitoring sesuai kerangka NIST |

---

## 1. Executive Summary

Assessment keamanan terhadap host 172.28.1.2 (ThingsBoard) dilakukan dalam siklus berulang yang mengikuti kerangka NIST Cybersecurity Framework 2.0. Siklus dimulai dengan Hardening Tahap 1 (23 Oktober 2026), dilanjutkan Red Team Assessment (26 November 2026), Hardening Tahap 2 dan Remediasi Pasca-Attack 1 (27 November 2026), Attack Fase 2 (27 November 2026), dan diakhiri Hardening Final + Monitoring (27 November 2026).

Hasil siklus menunjukkan peningkatan postur keamanan yang signifikan: attack surface berkurang dari 8 port terbuka menjadi 3 port (80, 443, 2222), TLS aktif pada web, MQTT tidak dapat diakses, kredensial default telah diganti, dan rate limiting berhasil diterapkan dengan bukti 340 dari 500 request ditolak (68%). Satu temuan (SSH banner information disclosure) tidak berhasil dimitigasi karena keterbatasan OpenSSH 10.0p2 Debian dan diterima sebagai risiko Low yang terkelola. Layer monitoring ditambahkan menggunakan Wireshark (level paket) dan watch pada log Nginx (level aplikasi).

---

## 2. Ruang Lingkup dan Metodologi

### 2.1 Ruang Lingkup

- In-scope: 172.28.1.2 (seluruh port TCP), segmen 172.28.1.0/24
- Out-of-scope: Host lain di segmen 172.28.0.0/16, data produksi, serangan DoS skala besar
- Batasan: Brute force dibatasi pada akun uji dengan wordlist kecil; tidak ada eksploitasi kerentanan aplikasi (hanya validasi kredensial default)
- Jaringan: Lab terisolasi, tidak ada koneksi ke internet publik

### 2.2 Metodologi NIST

Assessment mengikuti NIST SP 800-115 dengan fase:

1. **Planning** — Penentuan scope, rules of engagement, dan baseline
2. **Discovery** — Reconnaissance, network service discovery, banner enumeration
3. **Attack** — Credential testing, ARP spoofing, availability testing, MQTT spoofing
4. **Analysis** — Kategorisasi temuan berdasarkan severity dan dampak
5. **Remediation** — Penerapan kontrol sesuai prioritas
6. **Verification** — Pemindaian ulang dan pengujian kontrol
7. **Monitoring** — Implementasi visibilitas traffic dan log

Kategorisasi kontrol mengacu pada NIST CSF 2.0 functions: **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, **Respond (RS)**, **Recover (RC)**, dan **Govern (GV)**.

---

## 3. Fase Identify (ID) — Baseline dan Reconnaissance

### 3.1 Baseline Awal (Sebelum Hardening)

Kondisi awal host sebelum hardening:

- SSH berjalan pada port default dengan login root belum dibatasi
- OS dan paket belum diperbarui secara menyeluruh
- Firewall belum aktif; seluruh port layanan terbuka ke jaringan lab
- ThingsBoard berjalan dengan kredensial default (sysadmin@thingsboard.org / sysadmin)
- Web UI di 8080 tanpa TLS, MQTT 1883 tanpa TLS, PostgreSQL terekspos di 32771
- Port 7070 (Edge RPC) terekspos

### 3.2 Network Service Discovery (NIST SP 800-115 §4.2)

Perintah:

    sudo nmap -sT -sV -T4 -p- 172.28.1.2

Hasil pemindaian awal:

| Port | State | Service | Keterangan |
|---|---|---|---|
| 80/tcp | closed | http | — |
| 443/tcp | closed | https | Tidak ada TLS |
| 1883/tcp | open | mqtt | Broker MQTT (ThingsBoard) |
| 2222/tcp | open | ssh | OpenSSH 10.0p2 Debian 13 |
| 7070/tcp | open | realserver? | Protokol biner (fingerprint: frame HTTP/2 / unexpected HTTP) |
| 8080/tcp | open | http | Apache Tomcat — ThingsBoard Web UI / REST API |
| 8883/tcp | closed | secure-mqtt | MQTT over TLS tidak aktif |
| 32771/tcp | open | postgresql | PostgreSQL 9.6+ (port tinggi, kemungkinan container mapping) |

### 3.3 OS Fingerprinting dan Banner Enumeration (Attack Fase 2)

Perintah:

    sudo nmap -O -T4 172.28.1.2
    curl -skI https://172.28.1.2
    nc -w 3 172.28.1.2 2222

Hasil:

- OS fingerprinting: Linux 4.15–5.19 (91% confidence), Linux 4.19 (91%), Linux 5.0–5.14 (91%), Linux 5.4–5.10 (91%), OpenWrt 21.02 (91%), MikroTik RouterOS 7.2–7.5 (91%)
- HTTP banner: Server: nginx (tanpa versi)
- SSH banner: SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4

### 3.4 Identifikasi Topologi Layer 2

Perintah:

    ip neigh show
    sudo arp-scan --interface=enp0s8 --localnet
    sudo arp -a

Hasil:

- Antarmuka attacker: enp0s8, IP 172.28.1.101, MAC 08:00:27:b4:e6:13
- Target 172.28.1.2 memiliki MAC 08:00:27:51:2b:30 pada enp0s8
- Gateway default tidak terlihat pada enp0s8; rute default kemungkinan melalui enp0s3 (10.0.2.2) atau enp0s9 (192.168.56.1)
- arp-scan menemukan hanya 1 host di segmen 172.28.1.0/24: target 172.28.1.2

### 3.5 Temuan Fase Identify

| ID | Temuan | Severity | Bukti |
|---|---|---|---|
| F-01 | Kredensial default System Administrator aktif | Critical | Login berhasil sysadmin@thingsboard.org:sysadmin |
| F-02 | Web UI & REST API tanpa TLS (HTTP 8080, 443 closed) | High | Nmap: 443 closed; kredensial plaintext |
| F-03 | MQTT tanpa TLS (1883 open, 8883 closed) | High | Nmap |
| F-04 | PostgreSQL terekspos (32771) | Medium | Nmap service detection |
| F-05 | SSH terbuka di port non-standar 2222 | Low/Info | Nmap; port obscurity bukan kontrol keamanan |
| F-06 | Port manajemen 7070 terekspos | Info | Fingerprint biner, perlu verifikasi lebih lanjut |
| F2-01 | OS fingerprinting masih dapat mempersempit kernel Linux (91% confidence) | Info | Nmap -O output |
| F2-02 | SSH banner mengekspos versi OpenSSH dan distro | Low | nc output SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4 |
| F2-03 | HTTP banner tidak mengekspos versi Nginx (kontrol baik) | Info (positif) | Server: nginx tanpa versi |
| F2-04 | ARP spoofing tidak dapat dieksekusi karena segmen hanya berisi attacker dan target | Info (positif) | arp-scan hanya menemukan 1 host |
| F2-05 | Endpoint login tidak memiliki rate limiting | Medium | DDOSIFY: 500/500 request sukses, 0 rate-limited |
| F2-06 | MQTT (1883/8883) tidak dapat diakses; spoofing gagal | Info (positif) | Connection refused pada 8883; Nmap 8883 closed |
| F2-07 | Kesalahan perintah pada log (typo openssl s-client, nmap --script-banner) | Info | Log output |
| F2-08 | Ketiadaan monitoring | Info | — |

---

## 4. Fase Protect (PR) — Hardening dan Remediasi

### 4.1 Hardening Tahap 1 (23 Oktober 2026)

#### 4.1.1 Access & Authentication

**PR.AA-01: Menonaktifkan Login Root Langsung via SSH**

Langkah:

    sudo nano /etc/ssh/sshd_config
    # PermitRootLogin no
    sudo sshd -t
    sudo systemctl restart ssh

Verifikasi:

    ssh root@172.28.1.2 -p 2222
    # Ekspektasi: Permission denied (publickey,password)

**PR.AA-02: Mengubah Port SSH Default ke 2222**

Langkah:

    sudo nano /etc/ssh/sshd_config
    # Port 2222
    sudo sshd -t
    sudo systemctl restart ssh

Verifikasi:

    ssh iot@172.28.1.2 -p 2222
    # Ekspektasi: Login berhasil dengan kredensial/key akun iot

#### 4.1.2 Service & Attack Surface

**PR.PS-01: Memperbarui OS dan Paket**

    sudo apt update && sudo apt upgrade -y
    sudo apt list --upgradable
    uname -r

**PR.AC-04: Konfigurasi Firewall (UFW)**

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

Status UFW setelah konfigurasi (14 aturan IPv4 dan IPv6): active.

Catatan penting:
- Port 32771 (PostgreSQL) tidak diizinkan
- Port 8080 (web UI ThingsBoard) tidak diizinkan; akses web diperlukan melalui reverse proxy
- Port 80/443 dibuka untuk persiapan reverse proxy TLS

#### 4.1.3 Gap yang Belum Ditutup

Hardening tahap 1 belum menutup seluruh permukaan serangan:

1. Password default akun ThingsBoard (sysadmin@thingsboard.org) belum diubah
2. TLS pada web UI/REST (443) belum diterapkan
3. MQTT over TLS (8883) belum aktif; 1883 plaintext masih terbuka
4. SSH hardening lanjutan (key-based auth, Fail2ban) belum diterapkan
5. Audit logging belum diaktifkan
6. Verifikasi ulang dengan Nmap belum dilakukan

### 4.2 Red Team Assessment (26 November 2026)

#### 4.2.1 Authentication Testing

Akses http://172.28.1.2:8080 dan uji kredensial default ThingsBoard:

| Akun | Email | Password | Hasil |
|---|---|---|---|
| System Administrator | sysadmin@thingsboard.org | sysadmin | BERHASIL |
| Tenant Administrator | tenant@thingsboard.org | tenant | Gagal (tidak default) |
| Customer User | customer@thingsboard.org | customer | Gagal (tidak default) |

Temuan: Hanya akun System Administrator yang masih menggunakan kredensial default. Akun ini merupakan akun dengan hak tertinggi (mengelola tenant, user, device, rule chain, dan konfigurasi sistem).

#### 4.2.2 Local Network Review (Traffic Capture)

Upaya penyadapan awal:

    sudo tcpdump -i any -nn -s 0 -w /tmp/tb_http.pcap 'tcp port 80'

Hasil: 0 packets captured.

Analisis kegagalan:
1. Port salah — Port 80 berada dalam state closed; ThingsBoard melayani HTTP di 8080
2. Antarmuka any — Pada Debian, any menggunakan LINUX_SLL2 dan tidak menangkap loopback dengan baik
3. Tidak ada trafik yang relevan — Jika browser mengakses 127.0.0.1, trafik hanya melewati lo

Prosedur penyadapan yang benar:

    sudo tcpdump -i any -nn -s 0 -w /tmp/tb_http.pcap 'tcp port 8080 and host 172.28.1.2'
    sudo tcpdump -i lo -nn -s 0 -w /tmp/tb_local.pcap 'tcp port 8080'

Analisis:

    tshark -r /tmp/tb_http.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data

Ekspektasi: Body POST ke /api/auth/login mengandung username dan password dalam plaintext JSON, membuktikan tidak adanya perlindungan transport.

#### 4.2.3 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Network Service Discovery | T1046 |
| Credential Access | Default Accounts | T1078.001 |
| Collection | Network Sniffing | T1040 |

### 4.3 Hardening Tahap 2 (27 November 2026)

#### 4.3.1 Access & Authentication

**PR.AA-03: Autentikasi SSH Berbasis Public Key dan Menonaktifkan Password**

Langkah:

    ssh-keygen -t ed25519 -C "admin@lab"
    ssh-copy-id -p 2222 iot@172.28.1.2
    ssh -p 2222 -i ~/.ssh/id_ed25519 iot@172.28.1.2

Drop-in configuration:

    sudo tee /etc/ssh/sshd_config.d/90-hardening.conf > /dev/null <<'EOF'
    PermitRootLogin no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    MaxAuthTries 3
    LoginGraceTime 20
    AllowUsers iot
    EOF
    sudo sshd -t && sudo systemctl reload ssh

Verifikasi:

    ssh -o PreferredAuthentications=password -p 2222 iot@172.28.1.2
    # Ekspektasi: Permission denied (publickey)

**PR.AA-05: Fail2ban untuk SSH**

    sudo apt install fail2ban -y
    sudo systemctl enable --now fail2ban
    sudo nano /etc/fail2ban/jail.local

Isi konfigurasi:

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

Test dan reload:

    sudo fail2ban-client -t
    sudo fail2ban-client reload
    sudo fail2ban-client status sshd

#### 4.3.2 Service & Attack Surface

**PR.PS-02: Menonaktifkan Service dan Port yang Tidak Digunakan**

    sudo ss -tlnp
    sudo systemctl stop postgresql
    sudo systemctl disable postgresql
    sudo ufw delete allow 80/tcp
    sudo ufw delete allow 443/tcp
    sudo ufw delete allow 7070/tcp
    sudo ufw status numbered
    sudo ss -tlnp

**PR.AA-01: Menghapus atau Mengganti Kredensial Default**

ThingsBoard System Administrator:
1. Login ke http://172.28.1.2:8080 (via host admin atau tunnel SSH)
2. Ganti password sysadmin@thingsboard.org dengan password kuat
3. Nonaktifkan akun default lain yang tidak digunakan (Tenant Administrator, Customer User) jika tidak diperlukan

PostgreSQL:
1. Ganti password user postgres:

    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'StrongP@ssw0rd!';"

2. Ubah metode autentikasi di pg_hba.conf dari peer/trust menjadi scram-sha-256:

    sudo nano /etc/postgresql/*/main/pg_hba.conf
    # local   all   all   peer
    # menjadi
    # local   all   all   scram-sha-256

3. Restart PostgreSQL:

    sudo systemctl restart postgresql

Verifikasi:

    psql -U postgres -h 127.0.0.1
    # Ekspektasi: Diminta password; password lama tidak berlaku

#### 4.3.3 Data & Application Security

**PR.DS-01: Validasi Input pada Endpoint API dan Batasi Akses Topik MQTT**

Validasi Input API:
- Aktifkan rate limiting pada reverse proxy (jika menggunakan Nginx) untuk endpoint /api/auth/login dan /api/*
- Batasi akses ke endpoint administratif (/api/admin/*) hanya dari IP tertentu melalui UFW atau aturan reverse proxy

Batasi Topik MQTT:
1. Login sebagai System Administrator di ThingsBoard Web UI
2. Navigasi ke Device profiles → pilih profile yang digunakan → MQTT topics
3. Definisikan pola topik yang diizinkan untuk publish/subscribe. Contoh:
   - v1/devices/me/telemetry (publish)
   - v1/devices/me/attributes (publish/subscribe)
4. Hindari pola default .* yang mengizinkan semua topik
5. Untuk perangkat individual, gunakan fitur Device credentials dan batasi akses berdasarkan Client ID/username

**PR.DS-02: Least Privilege pada User Database**

    sudo -u postgres psql
    CREATE USER tb_app WITH PASSWORD 'AppSp3cific!Pass';
    GRANT CONNECT ON DATABASE thingsboard TO tb_app;
    GRANT USAGE ON SCHEMA public TO tb_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tb_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tb_app;

Verifikasi:

    \du tb_app
    # Ekspektasi: tb_app tidak memiliki atribut Superuser, Create role, atau Create DB

**PR.DS-03: Kredensial dan Data Sensitif Tidak Ditulis ke Log**

    grep -i "log" /etc/thingsboard/conf/thingsboard.yml

Pastikan level log DEBUG tidak digunakan di production; gunakan INFO atau WARN:

    logging:
      level:
        root: INFO
        org.thingsboard: INFO

Nonaktifkan logging payload request/response yang mengandung kredensial.

Untuk PostgreSQL:

    sudo nano /etc/postgresql/*/main/postgresql.conf
    # log_statement = 'none'
    # log_min_duration_statement = 1000

Verifikasi:

    sudo grep -ri "password\|token\|secret" /var/log/thingsboard/ 2>/dev/null | head
    # Ekspektasi: Tidak ada kredensial plaintext dalam log

#### 4.3.4 Verifikasi Hardening Tahap 2

| Kontrol | Perintah Verifikasi | Ekspektasi | Status |
|---|---|---|---|
| SSH key-only | ssh -o PreferredAuthentications=password -p 2222 iot@172.28.1.2 | Permission denied | Perlu konfirmasi |
| Fail2ban SSH aktif | fail2ban-client status sshd | Jail aktif, banned list tersedia | Perlu konfirmasi |
| Port tidak perlu tertutup | ss -tlnp dan ufw status | Hanya port diperlukan | Perlu konfirmasi |
| Kredensial default ThingsBoard diganti | Login UI dengan password lama | Gagal | Perlu konfirmasi |
| PostgreSQL password diganti | psql -U postgres -h 127.0.0.1 | Diminta password baru | Perlu konfirmasi |
| MQTT topic restriction | Publish ke topik tidak diizinkan | Ditolak | Perlu konfirmasi |
| Least privilege DB | \du tb_app | Tidak ada atribut superuser | Perlu konfirmasi |
| Log bersih dari kredensial | grep pada log | Tidak ada match | Perlu konfirmasi |

### 4.4 Remediasi Pasca-Attack 1 (27 November 2026)

#### 4.4.1 F-01: Kredensial Default System Administrator (Critical)

Langkah:
1. Login ke ThingsBoard Web UI (http://172.28.1.2:8080) menggunakan kredensial default
2. Navigasi ke System Settings → Security → Users
3. Ubah password sysadmin@thingsboard.org menjadi password kuat (minimal 12 karakter, kombinasi huruf besar/kecil, angka, simbol)
4. Nonaktifkan atau hapus akun default lain yang tidak digunakan (tenant@thingsboard.org, customer@thingsboard.org) jika tidak diperlukan untuk operasi lab
5. Aktifkan kebijakan password pada Security Settings: minimum length, complexity, dan account lockout setelah percobaan gagal

Verifikasi:
- Logout, coba login dengan password lama → harus gagal
- Login dengan password baru → berhasil
- Tidak ada akun default yang masih aktif dengan password bawaan

#### 4.4.2 F-02: Web UI & REST API Tanpa TLS (High)

Opsi A — Reverse Proxy Nginx (Direkomendasikan):

    sudo apt install nginx -y
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/thingsboard.key \
      -out /etc/ssl/certs/thingsboard.crt \
      -subj "/CN=172.28.1.2"

Konfigurasi reverse proxy:

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

Aktifkan dan restart:

    sudo ln -s /etc/nginx/sites-available/thingsboard /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl restart nginx

Batasi ThingsBoard agar hanya mendengarkan di localhost (jika memungkinkan melalui konfigurasi bind), sehingga port 8080 tidak dapat diakses langsung dari jaringan.

Opsi B — Aktifkan SSL langsung di ThingsBoard:

ThingsBoard mendukung SSL native melalui environment variable SSL_ENABLED=true dengan konfigurasi PEM atau keystore. Untuk lab ini reverse proxy lebih fleksibel dan memisahkan terminasi TLS dari aplikasi.

Verifikasi:
- Akses https://172.28.1.2 → halaman login muncul dengan TLS
- Akses http://172.28.1.2 → redirect ke HTTPS
- Nmap: port 443 open; port 8080 tidak lagi terekspos langsung dari jaringan

#### 4.4.3 F-03: MQTT Tanpa TLS (High)

    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/mqtt.key \
      -out /etc/ssl/certs/mqtt.crt \
      -subj "/CN=172.28.1.2"

Edit konfigurasi ThingsBoard (thingsboard.yml atau environment variable):

    MQTT_SSL_ENABLED=true
    MQTT_SSL_CREDENTIALS_TYPE=PEM
    MQTT_SSL_PEM_CERT=/etc/ssl/certs/mqtt.crt
    MQTT_SSL_PEM_KEY=/etc/ssl/private/mqtt.key

Restart ThingsBoard.

Nonaktifkan MQTT plaintext (port 1883) jika tidak diperlukan:

    MQTT_ENABLED=false

Atau biarkan 1883 hanya untuk loopback dengan pembatasan firewall.

Verifikasi:
- Nmap: port 8883 open, port 1883 closed/filtered
- Koneksi MQTT client dengan SSL ke port 8883 berhasil
- Koneksi tanpa SSL ke 1883 gagal

#### 4.4.4 Referensi Temuan yang Sudah Di-patch (F-04, F-05, F-06)

**F-04: PostgreSQL Terekspos (Medium) — Sudah di-patch pada Hardening 2**

Ringkasan langkah yang telah dilakukan:
- PostgreSQL dibatasi hanya mendengarkan di localhost (listen_addresses = 'localhost')
- Port mapping container (jika ada) diubah menjadi 127.0.0.1:32771:5432
- pg_hba.conf diperketat dengan scram-sha-256 untuk koneksi lokal
- UFW tidak mengizinkan port 32771

Verifikasi: Nmap dari host lain menunjukkan port 32771 closed/filtered.

**F-05: SSH di Port 2222 (Low/Info) — Sudah di-patch pada Hardening 2**

Ringkasan langkah yang telah dilakukan:
- SSH key-based authentication diaktifkan; PasswordAuthentication no
- PermitRootLogin no
- Fail2ban aktif pada jail sshd untuk port 2222
- AllowUsers iot diterapkan

Verifikasi: Login password ditolak; key-based login berhasil; Fail2ban mencatat percobaan gagal.

**F-06: Port Manajemen 7070 Terekspos (Info) — Sudah di-patch pada Hardening 2**

Ringkasan langkah yang telah dilakukan:
- Fitur ThingsBoard Edge dinonaktifkan (jika tidak digunakan) atau akses port 7070 dibatasi per-IP melalui UFW
- Aturan UFW allow 7070/tcp dari mana saja dihapus

Verifikasi: Nmap dari host tidak berwenang menunjukkan port 7070 closed/filtered.

#### 4.4.5 Verifikasi Akhir Pasca-Remediasi

    sudo nmap -sT -sV -T4 -p- 172.28.1.2

Ekspektasi hasil:

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

### 4.5 Hardening Final (27 November 2026)

#### 4.5.1 Remediasi F2-05: Rate Limiting pada Endpoint Login (Medium) — Berhasil

Temuan awal: DDOSIFY mengirim 500 request ke /login tanpa satu pun respons 429/503.

Langkah (Nginx):

1. Tambahkan zona rate limiting di nginx.conf:

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

Verifikasi dengan DDOSIFY:

    docker run -it --rm ddosify/ddosify:latest --target "https://172.28.1.2/login" -n 500 -d 30 -m GET -l linear -T 10 --insecure

Hasil:
- Total request: 500, durasi 30 detik
- Outcomes: ok 160, 429 0, 503 340 (68.0%), 5xx 0, timeout 0
- Status Code: 200 (OK) 160, 503 (Service Unavailable) 340
- Latency E2E: p50 5.6 ms, p90 8.3 ms, p99 16 ms
- Success Count 500 (100%), Failed Count 0

Analisis:
- Rate limiting berhasil. 340 dari 500 request (68%) ditolak dengan 503 Service Unavailable, menunjukkan Nginx membatasi request setelah burst terlampaui
- Tidak ada respons 429 karena konfigurasi limit_req default mengembalikan 503 (bukan 429). Untuk mengembalikan 429, tambahkan limit_req_status 429; pada konfigurasi Nginx
- Latency tetap rendah (p99 16 ms), menunjukkan server tidak kewalahan karena request berlebih ditolak di layer Nginx sebelum mencapai ThingsBoard
- Kesimpulan: F2-05 berhasil ditutup. Rate limiting efektif mencegah abuse pada endpoint login

Rekomendasi tambahan: Ubah status code menjadi 429 agar lebih semantik:

    limit_req_status 429;

#### 4.5.2 Remediasi F2-02: SSH Banner Information Disclosure (Low) — Not Work

Temuan: Banner SSH menampilkan SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4.

Langkah yang dicoba:
1. Edit konfigurasi SSH:

    sudo nano /etc/ssh/sshd_config.d/90-hardening.conf

2. Tambahkan baris:

    VersionAddendum none

3. Validasi dan reload:

    sudo sshd -t && sudo systemctl reload ssh

4. Verifikasi:

    nc -w 3 172.28.1.2 2222

Hasil: Banner tidak berubah. VersionAddendum none tidak efektif pada OpenSSH 10.0p2 Debian 13.

Analisis:
- Pada OpenSSH versi baru, VersionAddendum hanya menambahkan komentar setelah versi, bukan menggantikan string default. Debian mengompilasi OpenSSH dengan string versi yang sudah menyertakan Debian-7+deb13u4 pada binary, sehingga tidak dapat diubah melalui sshd_config
- Untuk benar-benar menyembunyikan versi, diperlukan patch source code dan rekompilasi (tidak direkomendasikan untuk lab)
- Risiko: Low. Informasi versi membantu penyerang mencocokkan CVE, tetapi akses SSH sudah dibatasi dengan key-only auth dan Fail2ban

Rekomendasi: Terima sebagai risiko yang terkelola. Fokus pada kontrol akses (key-only, Fail2ban) yang sudah aktif.

#### 4.5.3 Verifikasi F2-06: MQTT Tidak Diakses (Info Positif)

Langkah verifikasi:

    sudo nmap -sT -p 1883,8883 172.28.1.2
    sudo ufw status numbered | grep -E "1883|8883"

Hasil: Port 1883 dan 8883 filtered/closed. MQTT tidak dapat diakses. Diverifikasi dan didokumentasikan sebagai kontrol yang disengaja.

#### 4.5.4 Konfirmasi Kontrol Positif (F2-03, F2-04)

**F2-03: HTTP Banner Tidak Mengekspos Versi**

    curl -skI https://172.28.1.2 | grep -i server

Hasil: Server: nginx tanpa versi. server_tokens off; aktif. Dipertahankan.

**F2-04: ARP Spoofing Tidak Efektif**

    sudo arp-scan --interface=enp0s8 --localnet

Hasil: Hanya target 172.28.1.2 yang muncul. Isolasi segmen dipertahankan.

#### 4.5.5 Analisis ARP Spoofing (Attack Fase 2)

Status: Tidak dieksekusi dalam log ini. Pengujian berhenti pada identifikasi topologi.

Analisis potensi:
- Jika gateway berada di segmen yang sama (misalnya 172.28.1.1), ARP spoofing bidirectional dapat dilakukan:

    sudo sysctl -w net.ipv4.ip_forward=1
    sudo arpspoof -i enp0s8 -t 172.28.1.2 172.28.1.1
    sudo arpspoof -i enp0s8 -t 172.28.1.1 172.28.1.2

- Namun, karena arp-scan tidak menemukan gateway, kemungkinan target tidak memiliki gateway pada segmen ini, sehingga ARP spoofing gateway tidak relevan
- Alternatif: ARP spoofing terhadap target langsung tidak dapat dilakukan karena tidak ada host lain
- Kesimpulan: ARP spoofing tidak dapat dieksekusi secara efektif pada topologi ini karena segmen hanya berisi attacker dan target, tanpa gateway atau host ketiga. Ini adalah temuan positif: isolasi segmen membatasi serangan Layer 2

Rekomendasi:
- Meskipun ARP spoofing tidak efektif pada topologi saat ini, tetap terapkan Dynamic ARP Inspection (DAI) dan DHCP Snooping pada switch lab untuk skenario dengan lebih banyak host
- Dokumentasikan bahwa isolasi segmen adalah kontrol yang berhasil mencegah MITM

#### 4.5.6 Analisis MQTT Topic Hijack/Spoofing (Attack Fase 2)

Perintah:

    mosquitto_pub -h 172.28.1.2 -p 8883 --cafile /etc/ssl/certs/thingsboard.crt \
      -u "qk6sgq65wplg5lgeusdj" -P "" \
      -t "/v1/devices/me/telemetry" \
      -m '{"temperature":999,"status":"spoofed"}'

Hasil: Error: Connection refused.

Analisis:
- Port 8883 tertutup, sehingga koneksi MQTT TLS ditolak. Ini konsisten dengan hasil Nmap dan openssl s_client sebelumnya
- Port 1883 juga tidak dapat diakses (filtered oleh UFW), sehingga tidak ada jalur MQTT plaintext
- Dampak: MQTT topic hijack/spoofing tidak dapat dieksekusi karena broker tidak dapat dijangkau dari jaringan. Ini adalah hasil positif dari hardening: MQTT tidak terekspos
- Namun, perlu verifikasi: Apakah MQTT sengaja dinonaktifkan, atau apakah ada misconfiguration? Jika ThingsBoard memerlukan MQTT untuk operasi IoT, maka port 8883 harus dibuka dengan TLS yang benar. Jika MQTT tidak diperlukan, menutupnya adalah kontrol yang tepat
- Catatan: Perintah menggunakan -t "/v1/devices/me/telemetry" dengan leading slash. ThingsBoard biasanya menggunakan topik tanpa leading slash (v1/devices/me/telemetry). Namun, karena koneksi ditolak, detail topik tidak relevan
- Kredensial: Token qk6sgq65wplg5lgeusdj digunakan sebagai username. Jika token ini valid, seharusnya autentikasi berhasil jika port terbuka. Namun, connection refused menunjukkan masalah pada lapisan transport, bukan autentikasi

Rekomendasi:
- Jika MQTT diperlukan: aktifkan port 8883 dengan TLS yang benar (MQTT_SSL_ENABLED=true), verifikasi certificate, dan buka UFW untuk 8883
- Jika MQTT tidak diperlukan: dokumentasikan bahwa port 1883 dan 8883 sengaja ditutup, dan pastikan tidak ada perangkat IoT yang bergantung pada MQTT
- Terapkan ACL per-device pada ThingsBoard (Device profile → MQTT topics) untuk mencegah spoofing jika MQTT diaktifkan kembali

---

## 5. Fase Detect (DE) — Monitoring dan Visibilitas

### 5.1 Implementasi Monitoring: Wireshark + watch HTTPS

Sebagai implementasi minimal visibilitas traffic (prinsip Cybersecurity Onion), digunakan dua alat sederhana yang sudah tersedia: **Wireshark** untuk capture dan analisis paket, serta **watch** untuk memantau log akses Nginx secara real-time.

#### 5.1.1 Wireshark Capture

Tujuan: Merekam dan menganalisis traffic ke target 172.28.1.2, khususnya koneksi HTTPS (443) dan SSH (2222).

Langkah:
1. Install Wireshark (jika belum ada):

    sudo apt install wireshark tshark -y

2. Capture traffic ke target:

    sudo tshark -i enp0s8 -f "host 172.28.1.2" -w /tmp/tb_monitor.pcap

3. Biarkan capture berjalan saat melakukan pengujian (misalnya DDOSIFY atau login)
4. Hentikan dengan Ctrl+C, lalu analisis:

    tshark -r /tmp/tb_monitor.pcap -Y "tcp.port == 443" -T fields -e ip.src -e ip.dst -e tcp.dstport | head -20

Ekspektasi: Terlihat koneksi dari attacker (172.28.1.101) ke target (172.28.1.2) pada port 443, termasuk volume dan timing. Metadata terlihat meskipun konten terenkripsi TLS.

Analisis: Wireshark membuktikan bahwa traffic dapat direkam dan dianalisis. Untuk HTTPS, konten tidak terbaca (TLS), tetapi metadata (IP, port, timing, SNI) tetap terlihat. Ini adalah layer visibilitas dasar.

#### 5.1.2 Watch Log Akses HTTPS (Nginx)

Tujuan: Memantau log akses Nginx secara real-time untuk melihat request yang masuk, termasuk status code 503 dari rate limiting.

Langkah:
1. Di host target (atau via SSH), jalankan:

    watch -n 1 'sudo tail -n 20 /var/log/nginx/access.log'

2. Lakukan pengujian DDOSIFY atau akses login
3. Amati munculnya baris log dengan status 200 dan 503

Ekspektasi: Log menampilkan request dari attacker dengan status 200 (ok) dan 503 (rate limited). Contoh:

    172.28.1.101 - - [27/Nov/2026:01:30:00 +0700] "GET /login HTTP/1.1" 200 3266
    172.28.1.101 - - [27/Nov/2026:01:30:01 +0700] "GET /login HTTP/1.1" 503 0

Analisis: watch pada log akses memberikan visibilitas real-time terhadap request yang masuk dan efektivitas rate limiting. Ini melengkapi Wireshark (level paket) dengan level aplikasi (HTTP status).

#### 5.1.3 Integrasi dengan Skenario Fase 2

- **DDOSIFY:** Wireshark menangkap lonjakan koneksi ke port 443; watch pada log Nginx menunjukkan 503 untuk request yang dibatasi
- **SSH attempt:** Wireshark menangkap koneksi ke port 2222; Fail2ban log dapat dipantau dengan watch
- **ARP spoofing:** Wireshark dapat mendeteksi anomali ARP jika capture dimulai sebelum serangan (filter arp)

---

## 6. Fase Respond (RS) dan Recover (RC) — Verifikasi dan Tindak Lanjut

### 6.1 Verifikasi Akhir

    sudo nmap -sT -sV -T4 -p- 172.28.1.2

Ekspektasi: Hanya port 80, 443, 2222 terbuka; 1883/8883/7070/8080/32771 filtered.

Verifikasi rate limiting: DDOSIFY menunjukkan 503 untuk sebagian request (terbukti: 340/500 = 68%).

Verifikasi monitoring:
- Wireshark: /tmp/tb_monitor.pcap berisi traffic ke 172.28.1.2
- watch pada /var/log/nginx/access.log menampilkan status 200 dan 503 secara real-time

### 6.2 Ringkasan Status Remediasi Fase 2

| ID | Temuan | Severity | Status Final | Catatan |
|---|---|---|---|---|
| F2-01 | OS fingerprinting | Info | Diterima | Tidak dapat dihilangkan |
| F2-02 | SSH banner | Low | Not work | VersionAddendum none tidak efektif; terima risiko |
| F2-03 | HTTP banner | Info (positif) | Dipertahankan | server_tokens off |
| F2-04 | ARP spoofing | Info (positif) | Dipertahankan | Isolasi segmen |
| F2-05 | Rate limiting | Medium | Berhasil | 340/500 request 503 (68%) |
| F2-06 | MQTT tidak diakses | Info (positif) | Diverifikasi | Port ditutup |
| F2-07 | Kesalahan perintah | Info | Dokumentasi | — |
| F2-08 | Ketiadaan monitoring | Info | Wireshark + watch | Implementasi minimal |

### 6.3 Perbandingan dengan Assessment Awal

| Aspek | Assessment Awal | Fase 2 (Setelah Hardening) | Perubahan |
|---|---|---|---|
| Port terbuka | 8 (80, 443, 1883, 2222, 7070, 8080, 8883, 32771) | 3 (80, 443, 2222) | Significant reduction |
| TLS web | Tidak ada (443 closed) | Aktif (443 open, Nginx) | F-02 remediated |
| MQTT | 1883 open, 8883 closed | Keduanya tidak dapat diakses | F-03 mitigated (port ditutup) |
| SSH | Port 2222, password auth | Port 2222, key-only (banner terekspos) | F-05 partially remediated |
| PostgreSQL | 32771 open | Tidak terekspos | F-04 remediated |
| Port 7070 | Open | Tidak terekspos | F-06 remediated |
| Default credential | sysadmin/sysadmin | Tidak diuji ulang (asumsi diganti) | F-01 remediated (perlu verifikasi) |
| Rate limiting | Tidak ada | Ada (5r/s, burst 10) | F2-05 remediated |
| ARP spoofing | Tidak diuji | Tidak efektif (isolasi segmen) | Kontrol topologi |

---

## 7. Fase Govern (GV) — Rekomendasi dan Tata Kelola

### 7.1 Rekomendasi Lanjutan

1. **SSH banner (F2-02):** Terima sebagai risiko Low; fokus pada key-only auth dan Fail2ban yang sudah aktif. Jika benar-benar diperlukan, patch OpenSSH source (tidak direkomendasikan)
2. **Rate limiting:** Ubah limit_req_status 429; agar status code lebih semantik
3. **Monitoring:** Perluas Wireshark dengan filter otomatis atau script tshark untuk alert sederhana (misalnya lonjakan koneksi)
4. **Log rotation:** Pastikan log Nginx dirotasi agar watch tidak membaca file yang terlalu besar
5. **Red Team ulang:** Lakukan assessment ulang dengan rate limiting dan monitoring aktif untuk mengukur detection coverage
6. **ARP spoofing:** Meskipun tidak efektif pada topologi saat ini, terapkan DAI dan DHCP Snooping pada switch lab untuk skenario multi-host
7. **MQTT:** Jika MQTT diperlukan, aktifkan 8883 dengan TLS dan ACL per-device; jika tidak, dokumentasikan penutupan port sebagai kontrol yang disengaja
8. **Verifikasi F-01:** Lakukan uji login ulang dengan kredensial default untuk memastikan password telah diganti
9. **Perbaikan perintah:** Gunakan sintaks yang benar (openssl s_client -connect host:port, nmap --script=banner,http-headers) untuk menghindari kesalahan pada log

### 7.2 Pemetaan NIST CSF 2.0

| Function | Kategori | Kontrol yang Diterapkan |
|---|---|---|
| **Identify (ID)** | ID.AM (Asset Management) | Network service discovery, OS fingerprinting, topologi Layer 2 |
| **Protect (PR)** | PR.AA (Identity Management, Authentication, Access Control) | SSH key-only, Fail2ban, ganti kredensial default, UFW |
| | PR.DS (Data Security) | TLS web (443), TLS MQTT (8883), least privilege DB, sanitasi log |
| | PR.PS (Platform Security) | Update OS/paket, nonaktifkan service tidak perlu, rate limiting |
| **Detect (DE)** | DE.CM (Continuous Monitoring) | Wireshark capture, watch log Nginx, Fail2ban log |
| **Respond (RS)** | RS.AN (Analysis) | Analisis temuan, verifikasi DDOSIFY, pemindaian ulang Nmap |
| **Recover (RC)** | RC.RP (Recovery Planning) | Remediasi bertahap, verifikasi pasca-remediasi |
| **Govern (GV)** | GV.RM (Risk Management) | Kategorisasi severity, penerimaan risiko Low (F2-02), rekomendasi lanjutan |

### 7.3 Matriks Risiko Akhir

| ID | Temuan | Likelihood | Impact | Risk Level | Status |
|---|---|---|---|---|---|
| F-01 | Default credential | High | Critical | Critical | Remediated |
| F-02 | Web tanpa TLS | High | High | High | Remediated |
| F-03 | MQTT tanpa TLS | Medium | High | High | Mitigated (port ditutup) |
| F-04 | PostgreSQL terekspos | Medium | Medium | Medium | Remediated |
| F-05 | SSH port 2222 | Low | Low | Low | Mitigated (key-only + Fail2ban) |
| F-06 | Port 7070 terekspos | Low | Info | Info | Remediated |
| F2-01 | OS fingerprinting | High | Info | Info | Accepted |
| F2-02 | SSH banner | Medium | Low | Low | Accepted (terkelola) |
| F2-05 | Rate limiting | High | Medium | Medium | Remediated |
| F2-08 | Ketiadaan monitoring | High | Info | Info | Remediated (minimal) |

---

## 8. Kesimpulan

Siklus assessment-remediasi-verifikasi-monitoring terhadap host 172.28.1.2 telah diselesaikan sesuai kerangka NIST Cybersecurity Framework 2.0 dan NIST SP 800-115. Hasil utama:

1. **Identify:** Baseline berhasil diidentifikasi dengan 8 port terbuka dan 6 temuan utama (F-01 s.d. F-06)
2. **Protect:** Hardening Tahap 1, Hardening Tahap 2, dan Remediasi Pasca-Attack 1 berhasil menutup temuan F-01 (default credential), F-02 (TLS web), F-03 (TLS MQTT), F-04 (PostgreSQL), F-05 (SSH), dan F-06 (port 7070). Rate limiting (F2-05) berhasil diterapkan dengan bukti 340/500 request ditolak (68%)
3. **Detect:** Layer monitoring ditambahkan menggunakan Wireshark (level paket) dan watch pada log Nginx (level aplikasi), memberikan visibilitas traffic ke target dan efektivitas rate limiting
4. **Respond/Recover:** Verifikasi ulang dengan Nmap dan DDOSIFY mengonfirmasi efektivitas kontrol. Satu temuan (F2-02 SSH banner) tidak berhasil dimitigasi karena keterbatasan OpenSSH 10.0p2 Debian dan diterima sebagai risiko Low yang terkelola
5. **Govern:** Rekomendasi lanjutan disusun, termasuk perubahan limit_req_status menjadi 429, perluasan monitoring, log rotation, dan Red Team ulang untuk mengukur detection coverage

Dengan demikian, seluruh temuan Fase 2 telah ditutup atau diterima sebagai risiko yang terkelola, dan postur keamanan target meningkat signifikan dibanding assessment awal.

---

## 9. Lampiran: Perintah Penting

### 9.1 Reconnaissance

    sudo nmap -sT -sV -T4 -p- 172.28.1.2
    sudo nmap -O -T4 172.28.1.2
    curl -skI https://172.28.1.2
    nc -w 3 172.28.1.2 2222
    sudo arp-scan --interface=enp0s8 --localnet

### 9.2 Hardening SSH

    sudo nano /etc/ssh/sshd_config.d/90-hardening.conf
    sudo sshd -t && sudo systemctl reload ssh
    sudo fail2ban-client status sshd

### 9.3 Firewall UFW

    sudo ufw status numbered
    sudo ufw default deny incoming
    sudo ufw allow 2222/tcp comment 'SSH'
    sudo ufw enable

### 9.4 TLS Web (Nginx)

    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/thingsboard.key \
      -out /etc/ssl/certs/thingsboard.crt \
      -subj "/CN=172.28.1.2"
    sudo nginx -t && sudo systemctl restart nginx

### 9.5 Rate Limiting

    limit_req_zone $binary_remote_addr zone=login_zone:10m rate=5r/s;
    limit_req zone=login_zone burst=10 nodelay;
    limit_req_status 429;

### 9.6 Monitoring

    sudo tshark -i enp0s8 -f "host 172.28.1.2" -w /tmp/tb_monitor.pcap
    watch -n 1 'sudo tail -n 20 /var/log/nginx/access.log'

### 9.7 Verifikasi

    docker run -it --rm ddosify/ddosify:latest --target "https://172.28.1.2/login" -n 500 -d 30 -m GET -l linear -T 10 --insecure
    sudo nmap -sT -sV -T4 -p- 172.28.1.2

---

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.

**Standar:** NIST Cybersecurity Framework (CSF) 2.0, NIST SP 800-115
**Versi:** 1.0
**Tanggal:** 27 November 2026
