conf_data = configuration_data()

# Linux also has linux/mman.h
conf_data.set('HAVE_LINUX_MMAN_H', cc.has_header('linux/mman.h'))

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
        name: 'Define both mmap() and mmap64()',
        args: ['-shared', '-fPIC']
    )
)
conf_data.set(
    'IS_OPEN64_SEPERATE_SYMBOL',
    cc.links(
        '''
        #include <sys/stat.h>
        #include <fcntl.h>

        int open(const char *path, int flags, ...) { return 0; }
        int open64(const char *path, int flags, ...) { return 0; }
        ''',
        name: 'Define both open() and open64()',
        args: ['-shared', '-fPIC']
    )
)

configure_file(output: 'config.h',
               configuration: conf_data)
