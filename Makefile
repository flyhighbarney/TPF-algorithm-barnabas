CC      ?= gcc
CFLAGS  ?= -O3 -march=native -shared -fPIC -Wall -Wextra
SRC     := src/tpf_core.c
OUT     := src/tpf_core.so

.PHONY: build clean test demo

build: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

test: build
	python -m pytest tests/ -v

demo: build
	python examples/demo.py

clean:
	rm -f $(OUT) src/*.o
