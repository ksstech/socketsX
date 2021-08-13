/*
 * Copyright 2014-21 Andre M. Maree / KSS Technologies (Pty) Ltd.
 */

#pragma once

#include	"x_ubuf.h"				// FreeRTOS_Support

#include	"esp_netif.h"
#include	"sys/socket.h"			// "lwip/sockets.h"
#include	"netdb.h"				// "lwip/netdb.h"
#include	"lwip/ip_addr.h"
#include	"lwip/api.h"

#include	"mbedtls/net_sockets.h"
#include	"mbedtls/entropy.h"
#include	"mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

// #################################### BUILD configuration ########################################

#define		configXNET_MAX_RETRIES			200				// 250
#define		configXNET_MIN_TIMEOUT			20
#define		configXNET_MAX_TIMEOUT			30000			// mSec

#define		flagXNET_NONE					0
#define		flagXNET_BLOCKING				0UL
#define		flagXNET_NONBLOCK				1UL

// ######################################## IP well known ports ####################################

#define		IP_PORT_ICMPECHO				7				// TCP/UDP
#define 	IP_PORT_FTPDATA					20				// TCP/UDP
#define 	IP_PORT_FTPCNTL					21				// TCP
#define 	IP_PORT_SSH						22				// TCP/UDP
#define 	IP_PORT_TELNET					23				// TCP/UDP
#define		IP_PORT_TFTP					69				// UDP Trivial File Transfer Protocol
#define		IP_PORT_HTTP					80				// TCP

#define		IP_PORT_POP2					109				// TCP
#define		IP_PORT_POP3					110				// TCP

#define		IP_PORT_NNTP					119				// TCP
#define		IP_PORT_NTP						123				// UDP

#define		IP_PORT_IMAP					143				// TCP
#define		IP_PORT_SNMP					161				// UDP
#define		IP_PORT_SNMPTRAP				162				// TCP/UDP

#define		IP_PORT_HTTPS					443				// TCP

// Syslog support
#define		IP_PORT_SYSLOG_UDP				514				// syslog		514/UDP
#define		IP_PORT_SYSLOG_TCP				601				// syslog-conn	601/TCP -or- 601/UDP
#define		IP_PORT_SYSLOG_TLS				6514			// syslog-tls	6514/TCP
// CoAP support
#define		IP_PORT_COAP 					5683			// UDP Insecure datagram port
#define		IP_PORT_COAPS					5684			// UDP/DTLS Secure Datagram port
// MQTT support
#define		IP_PORT_MQTT 					1883			// TCP Insecure stream port
#define		IP_PORT_MQTTS					8883			// TCP/TLS Secure stream port

// ########################################### enumerations ########################################

enum {
	stateL1_STOPPED,				// NWP stopped, busy starting up..
	stateL2_STARTING,				// MAC started, waiting for MAC to associate to AP
	stateL3_STARTING,				// MAC layer done, waiting for DHCP completion
	stateL4_STARTING,				// IP layer 3 up, resolving SNTP, HTTP, TNET & cloud connectivity
	stateL4_RUNNING,
} ;

enum {
	selFLAG_READ,
	selFLAG_WRITE,
	selFLAG_EXCEPT,
	selFLAG_NUM,
} ;

// ########################################### structures ##########################################

typedef struct sock_sec_t {
	mbedtls_net_context			server_fd ;
	mbedtls_entropy_context		entropy ;
	mbedtls_ctr_drbg_context	ctr_drbg ;
	mbedtls_ssl_context			ssl ;
	mbedtls_ssl_config			conf ;
	mbedtls_x509_crt			cacert ;
	const char *				pcCert ;
	size_t						szCert ;
	int8_t						Verify ;
} sock_sec_t ;

typedef struct netx_t {
	union {
		struct	sockaddr_in	sa_in ;
		struct	sockaddr	sa ;
	} ;
	const char *	pHost ;							// name of host to connect to
	sock_sec_t *	psSec ;							// pointer to SSL/TLS config
	int				error ;							// error code return by last operation..
	int				flags ;							// Check implementation
	int16_t			sd ;							// socket descriptor
	uint16_t		tOut ;							// last timeout in mSec
	uint8_t  		type ;							// STREAM/TCP, DGRAM/UDP or RAW/RAW
	uint8_t			trymax ;						// max times to try read
	uint8_t			trynow ;						// times tried
	union {
		struct __attribute__((packed)) {
			uint8_t		connect	: 1 ;				// connected
			uint8_t		d_ndebug: 1 ;				// change syslog level in xNetGetError()
			uint8_t		d_eagain: 1 ;				// show EAGAIN errors
			uint8_t		d_open	: 1 ;				// debug control flags
			uint8_t		d_timing: 1 ;
			uint8_t		d_accept: 1 ;
			uint8_t		d_select: 1 ;
			uint8_t		d_write	: 1 ;
			uint8_t		d_read	: 1 ;
			uint8_t		d_data	: 1 ;
			uint8_t		d_close	: 1 ;
			uint8_t		d_secure: 1 ;				// Mbed TLS debug enable
			uint8_t		d_level	: 4 ;				// Mbed TLS 1+ value to set max level
		} ;
		uint16_t	d_flags ;
	} ;
	size_t			maxTx ;
	size_t			maxRx ;
} netx_t ;

// ####################################### Global variables ########################################


// ####################################### Global Functions ########################################

void xNetRestartStack( void ) ;
int	xNetReport(netx_t * psConn, const char * pFname, int Code, void * pBuf, int xLen) ;
int	xNetGetHost(netx_t * psConn) ;
int	xNetSetNonBlocking(netx_t * psConn, uint32_t mSecTime) ;
int	xNetSetRecvTimeOut(netx_t * psConn, uint32_t mSecTime) ;
int	xNetSelect(netx_t * psConn, uint8_t Flag) ;
int	xNetOpen(netx_t * psConn) ;
int	xNetAccept(netx_t * psServCtx, netx_t * psClntCtx, uint32_t mSecTime) ;

// read/write with traditional buffers
int	xNetWrite(netx_t * psConn, char * pBuf, int xLen) ;
int	xNetWriteBlocks(netx_t * psConn, char * pBuf, int xLen, uint32_t mSecTime) ;
int	xNetRead(netx_t * psConn, char * pBuf, int xLen) ;
int	xNetReadBlocks(netx_t * psConn, char * pBuf, int xLen, uint32_t mSecTime) ;

// read/write using managed buffers
int	xNetWriteFromBuf(netx_t *, ubuf_t *, uint32_t) ;
int	xNetReadToBuf(netx_t *, ubuf_t *, uint32_t) ;

int	xNetClose(netx_t * psConn) ;
void xNetReportStats(void) ;

#ifdef __cplusplus
}
#endif

/*
	if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
										 SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
		mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
		goto exit;
	}

	while ((iRV = mbedtls_ssl_handshake(&psConn->psSec->ssl)) != erSUCCESS) {
		if ((iRV != MBEDTLS_ERR_SSL_WANT_READ) && (iRV != MBEDTLS_ERR_SSL_WANT_WRITE)) {
		  	break ;
		}
	}
		// In real life, we probably want to bail out when ret != 0
			uint32_t flags ;
			if ((flags = mbedtls_ssl_get_verify_result(&psConn->psSec->ssl)) != erSUCCESS) {
				char vrfy_buf[512];
				mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
				mbedtls_printf( "%s\n", vrfy_buf );
			}
		}
*/
