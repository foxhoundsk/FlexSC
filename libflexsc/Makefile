CFLAGS = -Wall -pthread
SRC=flexsc.c flexsc_syscalls.c
OBJ_C=$(SRC:.c=.o)
INC=flexsc.h syscall_info.h flexsc_syscalls.h flexsc_cpu.h flexsc_types.h list.h
OBJ_H=$(INC:.h=.o) # or you can just include .h file seperately at gcc -o stage
LIB=libflexsc.a
LIBS= -L. -lflexsc
TARGET_BIN_NORM=/tmp/NORM_PERF
TARGET_BIN_FLEX=/tmp/FLEX_PERF
TARGET_SRC=perf.c

all: flexsc normal

# lib:
#	gcc -c $(SRC)
#	ar -r $(LIB) $(OBJ_C)
flexsc:
	gcc -o $(TARGET_BIN_FLEX) $(CFLAGS) -DFLEXSC $(TARGET_SRC) $(INC) $(SRC)

normal:
	gcc -o $(TARGET_BIN_NORM) $(CFLAGS) -DNORMAL $(TARGET_SRC) $(INC) $(SRC)

plot:
	gnuplot plot_perf.gp
	eog perf_measure.png
