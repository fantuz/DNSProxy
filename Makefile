include modern.mk

# Historical build, available only when explicitly requested.
dnsp-h2: encode.o decode.o dnsp-h2.o
	$(CC) $^ $(CFLAGS) -rdynamic -lcurl -lrt -lnghttp2 -lssl -lbrotlidec -lz -lcrypto -lpthread -w -o $@

dnsp-h2.o: dnsp-h2.c deps/ok/ok.h deps/b64/b64.h
	$(CC) -w -g -c $< -o $@
