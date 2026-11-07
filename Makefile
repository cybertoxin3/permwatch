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

clean:
	rm -f $(BIN) tests/test_json

.PHONY: all test run clean
