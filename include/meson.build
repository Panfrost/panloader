conf_data = configuration_data()

conf_data.set('IS_64_BIT', cc.sizeof('void*') == 8)

# Check whether mmap64() and mmap() are the same symbols, or if one is just
# aliased to the other. Seperate mmap64() and mmap() functions are used before
# Android 21.
conf_data.set(
    'IS_MMAP64_SEPERATE_SYMBOL',
    cc.links(
        '''
        #include <sys/mman.h>

        void *mmap64(void *addr, size_t length, int prot, int flags, int fd,
                     off_t offset) {return 0x0;}
        void *mmap(void *addr, size_t length, int prot, int flags, int fd,
                   off_t offset) {return 0x0;}
        ''',
        name: 'Define both mmap() and mmap64()'
    )
)

configure_file(output: 'config.h',
               configuration: conf_data)
