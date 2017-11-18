project('panloader', 'c',
        default_options: ['c_std=gnu11'])

if get_option('c_std') != 'gnu11'
    error('This project requires c_std be in gnu11 mode')
endif

cc = meson.get_compiler('c')

test_cc_flags = [
    '-Werror-implicit-function-declaration',
]
foreach flag: test_cc_flags
    if cc.has_argument(flag)
        add_global_arguments(flag, language: 'c')
    endif
endforeach

m_dep = cc.find_library('m', required: true)

common_dep = [
    m_dep,
]

test_c_attrs = [
    ['packed', 'struct s { int a; } __attribute__((packed)); main;'],
    ['constructor', 'void __attribute__((constructor)) f(){}main;'],
    ['format', 'void __attribute__((format (printf, 1, 2))) f(const char *, ...);main;'],
]
foreach t: test_c_attrs
    _attr = t[0]
    _src = t[1]
    message('Checking if compiler supports __attribute__((' + _attr + '))...')
    if not cc.compiles(_src)
        error('Compiler does not support __attribute__((' + _attr + '))')
    endif
endforeach

inc = include_directories('include')

subdir('src')
subdir('panwrap')
