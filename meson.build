project('panloader', 'c',
        default_options: ['c_std=gnu11'])

if get_option('c_std') != 'gnu11'
    error('This project requires c_std be in gnu11 mode')
endif

cc = meson.get_compiler('c')
is_android = cc.get_define('__ANDROID__') == '1'

test_cc_flags = [
    '-Werror-implicit-function-declaration',
    '-Werror-incompatible-pointer-types-discards-qualifiers',
    '-mfp16-format=ieee'
]
foreach flag: test_cc_flags
    if cc.has_argument(flag)
        add_global_arguments(flag, language: 'c')
    endif
endforeach

# Android only runs pie binaries
common_exec_largs = []
if is_android
    common_exec_largs += ['-pie']
endif

m_dep = cc.find_library('m', required: true)
dl_dep = cc.find_library('dl', required: false)

common_dep = [
    m_dep,
    dl_dep,
]

if not cc.has_argument('-Werror=attributes')
    error('Compiler does not support -Werror=attributes')
endif

test_c_srcs = [
    ['__attribute__((packed))',
     'struct s { int a; } __attribute__((packed));'],
    ['__attribute__((constructor))',
     'void __attribute__((constructor)) f(){}'],
    ['__attribute__((format))',
     'void __attribute__((format (printf, 1, 2))) f(const char *, ...);'],
    ['__attribute__((nonnull))',
     'void __attribute__((nonnull(1))) f(void *);'],
    ['__attribute__((noreturn))',
     'void __attribute__((noreturn)) f(void);'],
    ['__builtin_offsetof()',
     'struct s { int a; }; int o = __builtin_offsetof(struct s, a);'],
]
foreach t: test_c_srcs
    _feat = t[0]
    _src = t[1]
    if not cc.compiles(_src, name: _feat + ' test', args: '-Werror=attributes')
        error('Compiler does not support ' + _feat)
    endif
endforeach

inc = include_directories('include')

subdir('include')
subdir('src')
subdir('panwrap')
