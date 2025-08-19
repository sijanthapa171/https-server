## Minimal HTTPS server in C

### Requirements
- OpenSSL dev libraries (e.g., `libssl-dev` on Debian/Ubuntu)
- A C compiler

### Build
```bash
make -C /home/sijan/https
```

### Generate a self-signed certificate (dev only)
```bash
cd /home/sijan/https
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj "/CN=localhost" -days 365
```

### Run
```bash
make -C /home/sijan/https run
# or
./bin/https_server 0.0.0.0 8443 cert.pem key.pem
```

### Test
```bash
curl -k https://localhost:8443
```


