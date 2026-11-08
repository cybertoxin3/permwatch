CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -Werror -std=gnu11 -mmacosx-version-min=13.0
LDFLAGS := -lEndpointSecurity -lbsm
BIN     := permwatch
SRCS    := src/main.c src/json.c

all: $(BIN)

$(BIN): $(SRCS) src/json.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	codesign --force --sign - --entitlements entitlements.plist $@

tests/test_json: tests/test_json.c src/json.c src/json.h
	$(CC) $(CFLAGS) -o $@ tests/test_json.c src/json.c

test: tests/test_json
	./tests/test_json

run: $(BIN)
	sudo ./$(BIN)

app:
	./app/build.sh

clean:
	rm -f $(BIN) tests/test_json
	rm -rf app/build

# Uygulama testleri (paket ayrıştırıcı, açıklamalar, izleyiciler)
test-app:
	swiftc -import-objc-header app/shared/bridge.h -lpcap \
	    app/shared/Packets.swift app/Sources/Explain.swift app/Sources/L10n.swift app/tests/main.swift \
	    -o tests/test_app && ./tests/test_app

.PHONY: all test test-app run clean app
