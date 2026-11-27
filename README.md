# TEK1314-2026-Kel3-KelasA
# Logbook & Write-Up PBL Keamanan Siber — Kelompok 3 (`TEK1314-2026-Kel3-KelasA`)

**TEK1314 Keamanan Siber** | **Kelas A** | **Teknologi Rekayasa Komputer — Sekolah Vokasi IPB University**

**Simulated Purple Team Engagement — ThingsBoard IoT Platform Lab (`172.28.1.0/24`)**

> **Framework & Standar:** NIST Cybersecurity Framework (CSF) 2.0 & NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*)

## Meet The Team — Kelompok 3

| Nama Lengkap | NIM | Peran | 
| ----- | ----- | ----- | 
| **Faiz Satria Budi** | `J0404241019` | Blue Team | 
| **Ryan Faiz Sanie** | `J0404241078` | Red Team | 
| **Fakhriyatullahi Zahwa Khaerunnisa** | `J0404241147` | Lead Team and Technical Writer | 

## Topologi & Pengalamatan IP Lab

Lingkungan pengujian dijalankan pada jaringan laboratorium terisolasi (`172.28.1.0/24`, Subnet Mask `255.255.255.0`, Gateway `172.28.1.1`) dengan rincian node sebagai berikut:

| Hostname | IP Address | Sistem Operasi | Peran (Role) | Layanan Utama | 
| ----- | ----- | ----- | ----- | ----- | 
| **IOT-SRV** | `172.28.1.2/24` | Debian 13 | Target Server | ThingsBoard IoT, Nginx TLS Reverse Proxy, PostgreSQL, OpenSSH | 
| **MONITOR-SRV** | `172.28.1.10/24` | Security Onion | Monitoring / Blue Team | Wireshark / Tshark, Log Watcher (`access.log`), Security Onion | 
| **ATTACKER** | `172.28.1.101/24` | Debian 13 | Attacker / Red Team | Nmap, Tshark, DDOSIFY, Mosquitto Client, ARP-Scan | 

## Skenario Assessment & Eksploitasi Terpilih

Pengujian keamanan dilakukan dalam dua siklus iteratif (*Red Team Assessment 1* dan *Purple Team Loop Fase 2*) mengacu pada panduan **NIST SP 800-115** dan **MITRE ATT&CK**:

| \# | Port | Service | Teknik & Vektor Serangan | MITRE ATT&CK | Tool | 
| ----- | ----- | ----- | ----- | ----- | ----- | 
| **1** | `8080`, `1883`, `32771`, `7070` | ThingsBoard, MQTT, PostgreSQL | Network Service Discovery & OS/Banner Fingerprinting | `T1046` | `nmap`, `curl`, `nc` | 
| **2** | `8080` | ThingsBoard Web UI / REST API | Default Credentials Exploitation (`sysadmin@thingsboard.org`) | `T1078.001` | Browser, `curl` | 
| **3** | `8080` | HTTP Plaintext Traffic | Network Sniffing & Cleartext Credential Harvesting | `T1040` | `tcpdump`, `tshark` | 
| **4** | `443` | Nginx Reverse Proxy (`/login`) | Application-Layer DoS / Rate-Limit Stress Testing (500 req/30s) | `T1499` | `ddosify` (Docker) | 
| **5** | `1883`, `8883` & Layer 2 | MQTT Broker & Segmen ARP | MQTT Topic Spoofing & Layer 2 ARP Spoofing Verification | `T1557.002` | `mosquitto_pub`, `arp-scan` | 

## Ringkasan Siklus & Hasil Remediasi (NIST CSF 2.0)

Siklus *assessment–remediation–verification–monitoring* dilaksanakan pada periode **23 Oktober 2026 – 27 November 2026**:

| Aspek Keamanan | Baseline Awal | Kondisi Final | Status & Tindak Lanjut | 
| ----- | ----- | ----- | ----- | 
| **Attack Surface (Port)** | 8 port terbuka (`80`, `443`, `1883`, `2222`, `7070`, `8080`, `8883`, `32771`) | **3 port aktif** (`80`, `443`, `2222`) | **Remediated** (Port internal & MQTT ditutup) | 
| **Autentikasi & Kredensial** | Login `sysadmin/sysadmin` aktif; SSH password aktif | Password diganti; **SSH Key Ed25519** + **Fail2ban** | **Remediated** (`PasswordAuthentication no`) | 
| **Enkripsi Transport** | Web UI `8080` & MQTT `1883` berjalan plaintext | **Nginx HTTPS TLS (`443`)** aktif; HTTP redirect `301` | **Remediated** | 
| **Database Hardening** | PostgreSQL `32771` terekspos ke jaringan | Bind `localhost`, `scram-sha-256`, user `tb_app` least privilege | **Remediated** | 
| **Availability & Rate Limit** | 500/500 request DDOSIFY lolos tanpa hambatan | Nginx `limit_req` (`5r/s`, `burst 10`) menolak **340/500 (68%)** | **Remediated** (Rekomendasi: set `HTTP 429`) | 
| **SSH Banner (`F2-02`)** | `OpenSSH_10.0p2 Debian-7+deb13u4` terlihat | Tidak dapat diubah via `sshd_config` (`VersionAddendum`) | **Accepted Risk (Low)** — terkompensasi key-only | 
| **Visibilitas & Monitoring** | Belum tersedia mekanisme deteksi | Capture paket **Wireshark/Tshark** + real-time `watch` log Nginx | **Implemented** (Rekomendasi: log rotation) | 

## Daftar Luaran & Timeline Pengerjaan

| Tahap / Minggu | Fokus Kegiatan | Status | Deliverable / Tautan | 
| ----- | ----- | ----- | ----- | 
| **Setup Lab VM** | Instalasi Cybersecurity Lab VM & Security Onion pada perangkat utama | Selesai | `docs/LaptopUtama/Bukti_CybersecurityLabVM_Laptop Utama.jpg` · `docs/LaptopUtama/Bukti_SecurityOnion_Laptop Utama.jpg` | 
| **Desain Jaringan** | Perancangan topologi jaringan & pengalamatan IP segmen `172.28.1.0/24` | Selesai | [`topologi.png`](./topologi.png) · [`docs/design/ip-plan.md`](./docs/design/ip-plan.md) | 
| **Checkpoint Minggu 9** | Deklarasi tech stack, hardening tahap 1 (23 Okt 2026), dan bukti before-after | Selesai | [`docs/presentation-minggu9/slides.pdf`](./docs/presentation-minggu9/slides.pdf) · [`docs/presentation-minggu9/tech_stack_declaration.md`](./docs/presentation-minggu9/tech_stack_declaration.md) | 
| **Hardening & Blue Team** | Checklist kontrol hardening & dokumentasi tahapan hardening 1–3 | Selesai | [`docs/blueteam/hardening_checklist.md`](./docs/blueteam/hardening_checklist.md) · [`writeup_hardening_1_20261023.md`](./docs/blueteam/writeup_hardening_1_20261023.md) · [`writeup_hardening_2_20261126.md`](./docs/blueteam/writeup_hardening_2_20261126.md) · [`writeup_hardening_3_20261127.md`](./docs/blueteam/writeup_hardening_3_20261127.md) | 
| **Red Team & Purple Loop** | Eksekusi Attack 1 (26 Nov), Attack 2 & Hardening Final 4 (27 Nov) | Selesai | [`docs/redteam/writeup_attack_1_20261126.md`](./docs/redteam/writeup_attack_1_20261126.md) · [`docs/redteam/writeup_attack_2_20261127.md`](./docs/redteam/writeup_attack_2_20261127.md) · [`docs/redteam/writeup_hardening_4_20261127.md`](./docs/redteam/writeup_hardening_4_20261127.md) | 
| **Laporan & Presentasi Akhir** | Konsolidasi Write-Up NIST CSF 2.0 & slide presentasi Minggu 14 | Selesai | [`WriteUP.md`](./WriteUP.md) · [`docs/presentation-minggu14/Slides.pdf`](./docs/presentation-minggu14/Slides.pdf) | 

## Struktur Repositori

* `docs/blueteam/` — Checklist hardening kontrol keamanan dan dokumentasi write-up hardening bertahap (Tahap 1–3).

* `docs/redteam/` — Laporan teknis eksploitasi fase serangan (Attack 1 & 2) serta hasil verifikasi Purple Loop / Hardening Final.

* `docs/design/` — Dokumen rencana pengalamatan IP (`ip-plan.md`) dan konfigurasi segmen jaringan lab.

* `docs/LaptopUtama/` — Bukti tangkapan layar instalasi dan kesiapan Cybersecurity Lab VM serta Security Onion.

* `docs/presentation-minggu9/` — Deklarasi tech stack, bukti gambar *before–after* hardening awal, dan slide checkpoint Minggu 9.

* `docs/presentation-minggu14/` — Materi slide presentasi akhir kelompok.

* `topologi.png` — Diagram topologi jaringan laboratorium yang digunakan selama pengujian.

* `WriteUP.md` — Dokumen write-up utama yang mengonsolidasikan seluruh siklus berdasarkan standar NIST CSF 2.0.

## Lampiran & Dokumentasi Demo

* **Laporan Teknis Lengkap:** [`WriteUP.md`](./WriteUP.md)

* **Slide Presentasi Akhir (Minggu 14):** [`docs/presentation-minggu14/Slides.pdf`](./docs/presentation-minggu14/Slides.pdf)

* **Video Demo Siklus Purple Team Loop:** [Playlist YouTube Demo Kelompok 3](https://www.youtube.com/playlist?list=PLH60jz9YBBiQ)

*Dokumen ini disusun untuk keperluan akademik mata kuliah **TEK1314 Keamanan Siber** dalam lingkungan laboratorium terisolasi yang terotorisasi.*
