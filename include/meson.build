conf_data = configuration_data()

conf_data.set('IS_64_BIT', cc.sizeof('void*') == 8)

configure_file(output: 'config.h',
               configuration: conf_data)
