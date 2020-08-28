.phony: all clean

all: DakesProtocol.pb-c.c DakesProtocol.pb-c.h

DakesProtocol.pb-c.c: DakesProtocol.proto
	protoc-c --c_out=. DakesProtocol.proto

DakesProtocol.pb-c.h: DakesProtocol.pb-c.c

clean:
	rm DakesProtocol.pb-c.c DakesProtocol.pb-c.h
