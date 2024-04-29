LDFLAGSS = -lcrypto
CC = clang
CFLAGS = -fsanitize=address
LDFLAGS = -fsanitize=address
all:
	$(CC) $(CFLAGS) $(LDFLAGS) -g  -fno-omit-frame-pointer -o nyufile nyufile.c $(LDFLAGSS)
#all:
#$(CC)  -o nyufile nyufile.c $(LDFLAGSS)