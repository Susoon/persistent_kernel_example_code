LIB_INC := -I$(shell pwd)/lib -I$(shell pwd)/apps/lib

CUDA ?= /usr/local/cuda
CUDA_LIBPATH := -L$(CUDA)/lib64 -L$(CUDA)/lib -L/usr/lib64/nvidia -L/usr/lib/nvidia
CUDA_INC := -I$(CUDA)/include

#CUDAFLAGS = -O3

.PHONY: all clean

all: gdnio

gdnio : memory.o ipsec.o router.o nids.o link.o util.o main.o 
	@nvcc -o $@ -arch=compute_60 $^ $(LIB_INC) -L/usr/local/cuda/lib64 -lcudart -lcuda

memory.o : $(shell pwd)/lib/memory.cu
	@nvcc -arch=compute_60 --device-c $^ $(LIB_INC)

main.o : $(shell pwd)/test/main.cu
	@nvcc -arch=compute_60 --device-c $^ $(LIB_INC)

ipsec.o : $(shell pwd)/apps/ipsec_gw/ipsec.cu
	@nvcc -arch=compute_60 --device-c $^ $(LIB_INC)

router.o : $(shell pwd)/apps/router/router.cu
	@nvcc -arch=compute_60 --device-c $^ $(LIB_INC)

nids.o : $(shell pwd)/apps/nids/nids.cu
	@nvcc -arch=compute_60 --device-c $^ $(LIB_INC)

util.o : $(shell pwd)/lib/util.cu
	@nvcc -arch=compute_60 --device-c $^ $(LIB_INC)

link.o : main.o memory.o util.o ipsec.o router.o nids.o 
	@nvcc -arch=compute_60 --device-link $^ --output-file $@

clean:
	rm -rf *.o gdnio
	echo clean
