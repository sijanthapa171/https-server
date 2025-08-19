.PHONY: all clean run

CC := cc
CFLAGS := -Wall -Wextra -O2
LDFLAGS := -lssl -lcrypto

SRC := src/https_server.c
BIN := bin/https_server

# Configurable runtime parameters
HOST ?= 0.0.0.0
PORT ?= 8443
CERT ?= cert.pem
KEY  ?= key.pem

all: $(BIN)

bin:
	mkdir -p bin

$(BIN): bin $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

clean:
	rm -rf bin

run: all
	./bin/https_server $(HOST) $(PORT) $(CERT) $(KEY)

.PHONY: stop restart
stop:
	@PID=$$(ss -lptn 'sport = :$(PORT)' 2>/dev/null | awk 'NR>1{print $$6}' | sed -E 's/.*pid=([0-9]+),.*/\1/' | head -n1); \
	if [ -n "$$PID" ]; then \
		echo "Killing PID $$PID on port $(PORT)"; \
		kill $$PID || true; \
	else \
		echo "No process listening on port $(PORT)"; \
	fi

restart: stop run


