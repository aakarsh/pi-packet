#!/bin/bash

make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

if [[ "hello" == $(lsmod | awk '{print $1}' | grep hello) ]]; then
    sudo rmmod hello
else
    sudo insmod hello.ko
fi
