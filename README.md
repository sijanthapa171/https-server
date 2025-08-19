## Minimal HTTPS server in C

### Requirements
- OpenSSL development headers (e.g., `libssl-dev` on Debian/Ubuntu)
- A C compiler and `make`

Install on Debian/Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y build-essential libssl-dev openssl curl
```

### Build
```bash
make
```

### Generate a self-signed certificate (development only)
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj "/CN=localhost" -days 365
```

### Run
```bash
# Default: HOST=0.0.0.0 PORT=8443
make run

# Or specify host/port
make run HOST=127.0.0.1 PORT=9443

# Or run the binary directly
./bin/https_server 0.0.0.0 8443 cert.pem key.pem
```

### Stop/Restart
```bash
make stop
make restart
```

### Test
```bash
curl -k https://localhost:8443
```

### Notes
- If you accidentally send plain HTTP to the TLS port, the server replies with `400` explaining to use HTTPS.
- Do not commit real certificates/keys. `cert.pem` and `key.pem` are ignored via `.gitignore`.
