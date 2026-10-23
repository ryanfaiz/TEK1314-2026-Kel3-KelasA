
# Checklist Hardening Sistem IoT

## A. Access & Authentication

- [x] Menonaktifkan login root secara langsung melalui SSH.
- [ ] Mengaktifkan autentikasi SSH berbasis public key dan menonaktifkan autentikasi password.
- [x] Mengubah port SSH default.
- [ ] Mengaktifkan Fail2ban atau rate limiting untuk membatasi percobaan login berulang.
- [ ] Mengaktifkan MFA pada dashboard monitoring, jika tersedia.

## B. Service & Attack Surface

- [ ] Menonaktifkan service dan port yang tidak digunakan.
- [x] Mengonfigurasi firewall (UFW/iptables) untuk mengizinkan hanya port yang diperlukan.
- [x] Memperbarui OS dan paket ke versi yang aman.
- [ ] Menghapus atau mengganti akun dan kredensial default, termasuk user dan password database bawaan.

## C. Data & Application Security

- [x] Memindahkan kredensial dari source code ke environment variable atau secrets.
- [ ] Memvalidasi input pada endpoint API dan/atau membatasi akses ke topik MQTT.
- [ ] Menerapkan prinsip *least privilege* pada user database.
- [x] Mengaktifkan logging untuk mendeteksi aktivitas mencurigakan.
- [ ] Memastikan kredensial dan data sensitif tidak ditulis ke dalam log.
