BOFNAME := remote_process_commandline
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -Wno-unused-variable -Wno-int-to-pointer-cast -o ../dist/$(BOFNAME).x64.o -c $(BOFNAME).c -masm=intel

clean:
	rm -f ../dist/$(BOFNAME).x64.o
