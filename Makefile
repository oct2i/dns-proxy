CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)
DEST = /lib/modules/$(CURRENT)
EXTRA_CFLAGS += -O3
TARGET = dnsproxy

obj-m := $(TARGET).o

all: default clean

default:
		$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
		sudo cp -v $(TARGET).ko $(DEST)
		sudo /sbin/insmod $(TARGET).ko
		sudo /sbin/lsmod | grep $(TARGET)

uninstall:
		sudo /sbin/rmmod $(TARGET)
		sudo rm -v $(DEST)/$(TARGET).ko

clean:
		@rm -f *.o .*.cmd .*.flags *.mod.c *.order
		@rm -f .*.*.cmd *.symvers *~ *.*~
		@rm -fR .tmp*
		@rm -rf .tmp_versions

disclean: clean
		@rm -f *.ko *.symvers
