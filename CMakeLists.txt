# SOCKETSX
set( srcs "socketsX.c" )
set( include_dirs "." )
set( requires buffers mbedtls )
set( priv_requires common hal_esp32 printfx rtos-support syslog systiming )
idf_component_register(SRCS ${srcs} INCLUDE_DIRS ${include_dirs} REQUIRES ${requires} PRIV_REQUIRES ${priv_requires})
