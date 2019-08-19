obj-y = flexsc.o hook.o init.o

all:
	make -C libflexsc
	make -C user

run:
	user/user-program

clean:
	rm *.o

lib:
	make -C libflexsc

u:
	make -C user

