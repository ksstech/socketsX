idf_component_register(
	SRCS "socketsX.c"
	INCLUDE_DIRS "."
	PRIV_INCLUDE_DIRS
	REQUIRES hal_esp32 mbedtls
	PRIV_REQUIRES printfx rtos-support systiming
)
