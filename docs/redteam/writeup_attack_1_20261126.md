# Red Team Write-Up — ThingsBoard Lab Assessment

| Item | Keterangan |
|---|---|
| Target | 172.28.1.2 (ThingsBoard, lab terisolasi) |
| Attacker Node | Debian fresh install (attacker) |
| Tanggal | 26 November 2026 |
| Klasifikasi | Latihan Akademik — Keamanan Siber (Lab Terotorisasi) |
| Metodologi | PTES / MITRE ATT&CK (Recon, Credential Access, Collection) |

## 1. Executive Summary

Assessment terhadap host 172.28.1.2 menemukan bahwa kredensial default akun System Administrator ThingsBoard masih aktif (sysadmin@thingsboard.org / sysadmin). Akun ini memiliki hak penuh atas platform IoT. Selain itu, ditemukan beberapa layanan terekspos ke jaringan (MQTT, SSH, PostgreSQL, dan port manajemen 7070) yang memperluas attack surface. Tidak ditemukan penggunaan TLS pada antarmuka web (port 8080 HTTP), sehingga kredensial dapat ditransmisikan dalam bentuk plaintext.

Temuan kritis: Default credential pada akun privileged berpotensi menyebabkan full compromise platform ThingsBoard.

## 2. Scope & Rules of Engagement

- In-scope: 172.28.1.2 (seluruh port TCP)
- Out-of-scope: Host lain di segmen 172.28.0.0/16, data produksi, serangan DoS
- Batasan: Brute force dibatasi pada akun uji & wordlist kecil; tidak ada eksploitasi kerentanan aplikasi (hanya validasi kredensial default)
- Jaringan: Lab terisolasi, tidak ada koneksi ke internet publik

## 3. Reconnaissance

### 3.1 Perintah

    sudo nmap -sT -sV -T4 -p- 172.28.1.2

### 3.2 Hasil Pemindaian

| Port | State | Service | Keterangan |
|---|---|---|---|
| 80/tcp | closed | http | — |
| 443/tcp | closed | https | Tidak ada TLS |
| 1883/tcp | open | mqtt | Broker MQTT (ThingsBoard) |
| 2222/tcp | open | ssh | OpenSSH 10.0p2 Debian 13 |
| 7070/tcp | open | realserver? | Protokol biner (fingerprint: frame HTTP/2 / unexpected HTTP), kemungkinan port internal ThingsBoard |
| 8080/tcp | open | http | Apache Tomcat — ThingsBoard Web UI / REST API |
| 8883/tcp | closed | secure-mqtt | MQTT over TLS tidak aktif |
| 32771/tcp | open | postgresql | PostgreSQL 9.6+ (port tinggi, kemungkinan container mapping) |

Catatan:
- Port 80 dan 443 closed, tidak ada reverse proxy / TLS termination di depan ThingsBoard.
- Port 8883 closed, MQTT berjalan tanpa enkripsi (port 1883).
- Port 32771 mengindikasikan deployment berbasis container (Docker port mapping), relevan untuk analisis antarmuka penyadapan.

### 3.3 Analisis

Attack surface mencakup empat vektor utama: web (8080), MQTT (1883), SSH (2222), dan database (32771). Tidak adanya TLS pada web dan MQTT berarti seluruh kredensial dan payload dapat disadap pada segmen jaringan yang sama.

## 4. Authentication Testing

### 4.1 Validasi Kredensial Default (Manual)

Akses http://172.28.1.2:8080 dan uji kredensial default ThingsBoard:

| Akun | Email | Password | Hasil |
|---|---|---|---|
| System Administrator | sysadmin@thingsboard.org | sysadmin | BERHASIL |
| Tenant Administrator | tenant@thingsboard.org | tenant | Gagal (tidak default) |
| Customer User | customer@thingsboard.org | customer | Gagal (tidak default) |

Temuan: Hanya akun System Administrator yang masih menggunakan kredensial default. Akun ini merupakan akun dengan hak tertinggi (mengelola tenant, user, device, rule chain, dan konfigurasi sistem).

### 4.2 Brute Force Terbatas (opsional, akun uji)

Tidak dilakukan brute force lebih lanjut karena kredensial default sudah memberikan akses privileged. Untuk kelengkapan metodologi, disarankan menggunakan Burp Intruder / skrip requests terhadap akun uji dengan wordlist ≤ 10 entri dan rate limit rendah, guna menghindari lockout.

## 5. Local Network Review (Traffic Capture)

### 5.1 Upaya Penyadapan Awal

    sudo tcpdump -i any -nn -s 0 -w /tmp/tb_http.pcap 'tcp port 80'

Hasil: 0 packets captured.

Analisis kegagalan:
1. Port salah — Port 80 berada dalam state closed (lihat Nmap). ThingsBoard melayani HTTP di 8080, sehingga filter tcp port 80 tidak akan pernah menangkap trafik aplikasi.
2. Antarmuka any — Pada Debian, any menggunakan LINUX_SLL2 dan tidak menangkap loopback dengan baik; peringatan promiscuous mode juga muncul.
3. Tidak ada trafik yang relevan — Jika browser mengakses 127.0.0.1, trafik hanya melewati lo.

### 5.2 Prosedur Penyadapan yang Benar

Karena target menggunakan HTTP plaintext di 8080:

    # Tangkap trafik web ThingsBoard
    sudo tcpdump -i any -nn -s 0 -w /tmp/tb_http.pcap 'tcp port 8080 and host 172.28.1.2'

    # Alternatif jika trafik melalui loopback / reverse proxy lokal
    sudo tcpdump -i lo -nn -s 0 -w /tmp/tb_local.pcap 'tcp port 8080'

Lakukan login melalui http://172.28.1.2:8080 saat capture berjalan, lalu analisis:

    tshark -r /tmp/tb_http.pcap -Y 'http.request.method == "POST"' -T fields -e http.file_data

Ekspektasi: Body POST ke /api/auth/login mengandung username dan password dalam plaintext JSON, membuktikan tidak adanya perlindungan transport.

Catatan: Jika target berjalan di Docker dengan port mapping (indikasi port 32771), trafik dapat terlihat pada antarmuka bridge (docker0 / br-xxxx). Verifikasi dengan ip addr dan sesuaikan -i.

## 6. Findings

| ID | Temuan | Severity | Bukti |
|---|---|---|---|
| F-01 | Kredensial default System Administrator aktif | Critical | Login berhasil sysadmin@thingsboard.org:sysadmin |
| F-02 | Web UI & REST API tanpa TLS (HTTP 8080, 443 closed) | High | Nmap: 443 closed; kredensial plaintext |
| F-03 | MQTT tanpa TLS (1883 open, 8883 closed) | High | Nmap |
| F-04 | PostgreSQL terekspos (32771) | Medium | Nmap service detection |
| F-05 | SSH terbuka di port non-standar 2222 | Low/Info | Nmap; port obscurity bukan kontrol keamanan |
| F-06 | Port manajemen 7070 terekspos | Info | Fingerprint biner, perlu verifikasi lebih lanjut |

## 7. Risk & Impact

Dengan kredensial default F-01, penyerang memperoleh kontrol penuh atas platform ThingsBoard: membuat/menghapus tenant dan user, mengakses semua device dan telemetri, memodifikasi rule chain (potensi eksekusi aksi otomatis), serta mengakses kredensial integrasi. Kombinasi F-02/F-03 memungkinkan penyadapan kredensial dan data telemetri pada segmen jaringan yang sama. Eksposur database (F-04) berpotensi menjadi jalur akses langsung ke data bila autentikasi lemah.

## 8. Recommendations

1. Segera ubah password sysadmin@thingsboard.org dan terapkan kebijakan password kuat; nonaktifkan akun default yang tidak digunakan.
2. Aktifkan TLS pada web UI/REST (443) dan MQTT (8883). Gunakan reverse proxy (Nginx) dengan sertifikat valid dan redirect HTTP ke HTTPS.
3. Batasi akses jaringan ke 8080, 1883, 2222, 32771, dan 7070 menggunakan firewall/security group; hanya izinkan host manajemen.
4. Jangan ekspos PostgreSQL ke jaringan aplikasi; gunakan network internal container.
5. Aktifkan audit logging login dan perubahan konfigurasi; pantau percobaan autentikasi gagal.
6. Ganti port SSH bukan solusi; terapkan key-based auth, disable password login, dan fail2ban.

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Network Service Discovery | T1046 |
| Credential Access | Default Accounts | T1078.001 |
| Collection | Network Sniffing | T1040 |

## 10. Kesimpulan

Host 172.28.1.2 rentan terhadap kompromi penuh melalui default credential pada akun System Administrator. Tidak adanya TLS pada web dan MQTT memperburuk risiko karena kredensial dan data dapat disadap. Upaya penyadapan awal gagal karena filter port 80 yang salah (port closed); koreksi prosedur dengan filter tcp port 8080 dan antarmuka yang tepat (any/lo/bridge Docker) diperlukan untuk menyelesaikan bukti F-02.

Status latihan: Selesai, temuan kritis terdokumentasi, rekomendasi disusun.

Dokumen ini dibuat untuk keperluan akademik dalam lingkungan laboratorium terisolasi yang terotorisasi. Tidak untuk digunakan terhadap sistem tanpa izin tertulis.
