SIGNAL_SRC := libsignal-protocol-c/src
AXC_SRC := axc/src
SIGNAL_TEST := libsignal-protocol-c/tests
SIGNAL_BUILD := libsignal-protocol-c/build
SIGNAL_INC := -I$(SIGNAL_SRC) -I$(SIGNAL_SRC)/curve25519 -I$(SIGNAL_SRC)/curve25519/ed25519 -I$(SIGNAL_SRC)/curve25519/ed25519/additions -I$(SIGNAL_SRC)/curve25519/ed25519/nacl_includes -I$(AXC_SRC)/
SIGNAL_TEST_INC := -I$(SIGNAL_TEST)
RSIG_OBJS := src/hasher_signal.o src/keymap.o src/rsig.o
SRC_OBJS := $(RSIG_OBJS) src/idake.o src/odake.o src/signal_query_id.o src/axc_helper.o src/idake2session.o src/clinklst.o src/sigaddr_holder.o src/pbdumper.o protobuf/DakesProtocol.pb-c.o
SIGNAL_SHARED_LIB := $(SIGNAL_BUILD)/src/libsignal-protocol-c.so.2.3.2
SIGNAL_TEST_OBJS_DIR := $(SIGNAL_TEST)/CMakeFiles/test_curve25519.dir
SIGNAL_TEST_OBJS := $(SIGNAL_TEST_OBJS_DIR)/test_common_openssl.o $(SIGNAL_TEST_OBJS_DIR)/test_common.o
CFI_CFLAGS := -fvisibility=hidden -flto #-fsanitize=cfi  -fno-sanitize-trap=all
TESTAPP_OBJS := tests/sockevents.o tests/testapp_class.o tests/testapp_echo_ui.o tests/testapp_main.o tests/testapp_rl_ui.o tests/sexp.o tests/simpletlv.o tests/pbdumper_sexp.o

.phony: clean

%.o: %.c protobuf/DakesProtocol.pb-c.h
	$(CC) -g -c -o $@ $(SIGNAL_INC) -I$(SIGNAL_TEST) -Iinclude -Itests -Iprotobuf -DDUMPMSG $<

protobuf/DakesProtocol.pb-c.c: protobuf/DakesProtocol.proto
	make -C protobuf

protobuf/DakesProtocol.pb-c.h: protobuf/DakesProtocol.pb-c.c

libsignal-dakez.a: $(SRC_OBJS)
	ar cr $@ $(SRC_OBJS)

$(SIGNAL_SHARED_LIB): $(SIGNAL_SRC)
	mkdir -p $(SIGNAL_BUILD)
	cd $(SIGNAL_BUILD); cmake -DBUILD_SHARED_LIBS=yes -DCMAKE_C_COMPILER=$(CC) -DCMAKE_BUILD_TYPE=Debug ..
	make -C $(SIGNAL_BUILD)

$(SIGNAL_TEST)/test/test_curve25519: $(SIGNAL_TEST)
	cd $(SIGNAL_TEST); cmake -DBUILD_SHARED_LIBS=yes -DCMAKE_SYSTEM_LIBRARY_PATH=$(shell pwd)/$(SIGNAL_BUILD)/src -DCMAKE_C_COMPILER=$(CC) .
	make -C $(SIGNAL_TEST) test_curve25519

axc/build/libaxc.a:
	make -C axc

tests/test_rsig: tests/test_rsig.o $(SIGNAL_SHARED_LIB) $(RSIG_OBJS) $(SIGNAL_TEST)/test/test_curve25519
	$(CC) -o $@ $< $(RSIG_OBJS) $(SIGNAL_TEST_OBJS) -L$(SIGNAL_BUILD)/src $(CFI_CFLAGS) -lm -lcheck_pic -pthread -lrt -lm -lsubunit -lssl -lcrypto -lpthread -ldl -lsignal-protocol-c

tests/testapp: libsignal-dakez.a axc/build/libaxc.a $(TESTAPP_OBJS) $(SIGNAL_SHARED_LIB)
	$(CC) -o $@ $< $(TESTAPP_OBJS) -L. -L$(SIGNAL_BUILD)/src -Laxc/build -pthread -lm -lpthread -ldl -lsignal-protocol-c -laxc -lsignal-dakez -lsqlite3 -lgcrypt -levent -lreadline `pkg-config --libs glib-2.0`

clean:
	-rm -r $(SIGNAL_BUILD)
	-rm $(SIGNAL_TEST)/CMakeCache.txt
	-rm $(SRC_OBJS) $(SIGNAL_TEST_OBJS) $(SIGNAL_TEST_OBJS)
	-rm protobuf/DakesProtocol.pb-c.?
	make -C protobuf clean
