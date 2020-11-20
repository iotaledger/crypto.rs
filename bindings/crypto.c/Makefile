ifeq ($(shell uname),Darwin)
    LDFLAGS := -Wl
	LD_LIBRARY_PATH := target/debug/libcrypto.dylib
else
    LDFLAGS := -Wl,--gc-sections -lpthread -ldl
	LD_LIBRARY_PATH := target/debug/libcrypto.so
endif

all: target/crypto
	target/crypto

target:
	mkdir -p $@

target/crypto: target/main.o $(LD_LIBRARY_PATH)
	$(CC) -o $@ $^ $(LDFLAGS)

$(LD_LIBRARY_PATH): src/lib.rs Cargo.toml
	cargo build

target/main.o: main.c include/iota_crypto.h | target
	$(CC) -o $@ -c $<

clean:
	rm -rf target