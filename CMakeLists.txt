# SOCKETSX
set( srcs "socketsX.c" )
set( include_dirs "." )
set( priv_include_dirs )
set( requires "buffers hal_esp32 mbedtls esp_netif" )
set( priv_requires "printfx syslog systiming")

idf_component_register(
	SRCS ${srcs}
	INCLUDE_DIRS ${include_dirs}
	PRIV_INCLUDE_DIRS ${priv_include_dirs}
	REQUIRES ${requires}
	PRIV_REQUIRES ${priv_requires}
)
