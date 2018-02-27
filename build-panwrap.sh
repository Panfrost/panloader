cp ../cwabbotts-open-gpu-tools/common/libcommon.so /dev/shm
gcc -Iinclude/ -Ibuild/include -I../cwabbotts-open-gpu-tools/common/include panwrap/*.c -mfp16-format=ieee -o panwrap.so -ldl -lm -pthread /dev/shm/libcommon.so -fpic -shared
