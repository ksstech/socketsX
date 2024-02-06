/*
 * socketsX.h - Copyright (c) 2014-24 Andre M. Maree / KSS Technologies (Pty) Ltd.
 */

#pragma once

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "esp_crt_bundle.h"

#include "x_ubuf.h"

#ifdef __cplusplus
extern "C" {
#endif

// #################################### BUILD configuration ########################################

#define	configXNET_MAX_RETRIES		200					// 250
#define	configXNET_MIN_TIMEOUT		20
#define	configXNET_MAX_TIMEOUT		30000				// mSec

#define	flagXNET_BLOCKING			0UL
#define	flagXNET_NONBLOCK			1UL

// ######################################## IP well known ports ####################################

#define	IP_PORT_ICMPECHO			7					// TCP/UDP
#define IP_PORT_FTPDATA				20					// TCP/UDP
#define IP_PORT_FTPCNTL				21					// TCP
#define IP_PORT_SSH					22					// TCP/UDP
#define IP_PORT_TELNET				23					// TCP/UDP
#define	IP_PORT_TFTP				69					// UDP Trivial File Transfer Protocol
#define	IP_PORT_HTTP				80					// TCP

#define	IP_PORT_POP2				109					// TCP
#define	IP_PORT_POP3				110					// TCP

#define	IP_PORT_NNTP				119					// TCP
#define	IP_PORT_NTP					123					// UDP

#define	IP_PORT_IMAP				143					// TCP

#define	IP_PORT_SNMP				161					// UDP
#define	IP_PORT_SNMPTRAP			162					// TCP/UDP

#define	IP_PORT_HTTPS				443					// HTTPS (TCP)
#define	IP_PORT_MODBUS				502					// Modbus (TCP)
// Syslog support
#define	IP_PORT_SYSLOG_UDP			514					// syslog		514/UDP
#define	IP_PORT_SYSLOG_TCP			601					// syslog-conn	601/TCP -or- 601/UDP
#define	IP_PORT_SYSLOG_TLS			6514				// syslog-tls	6514/TCP
// CoAP support
#define	IP_PORT_COAP 				5683				// UDP Insecure datagram port
#define	IP_PORT_COAPS				5684				// UDP/DTLS Secure Datagram port
// MQTT support
#define	IP_PORT_MQTT 				1883				// TCP Insecure stream port
#define	IP_PORT_MQTTS				8883				// TCP/TLS Secure stream port

#define	NETX_DBG_FLAGS(O, H, BL, T, A, S, W, R, D, CL, SL, EA, VER, SEC, LVL, HTTP) (netx_dbg_t) {	\
	.o=O, .h=H, .bl=BL, .t=T, .a=A, .s=S, .w=W, .r=R, .d=D, .cl=CL, .sl=SL, .ea=EA,					\
	.ver=VER, .sec=SEC, .lvl=LVL, .http=HTTP }

// ########################################### enumerations ########################################

enum {
	stateL1_STOPPED,				// NWP stopped, busy starting up..
	stateL2_STARTING,				// MAC started, waiting for MAC to associate to AP
	stateL3_STARTING,				// MAC layer done, waiting for DHCP completion
	stateL4_STARTING,				// IP layer 3 up, resolving SNTP, HTTP, TNET & cloud connectivity
	stateL4_RUNNING,
};

enum {
	selFLAG_READ,
	selFLAG_WRITE,
	selFLAG_EXCEPT,
	selFLAG_NUM,
};

// ########################################### structures ##########################################

typedef struct sock_sec_t {
	const char *				pcCert;
	size_t						szCert;
	mbedtls_net_context			server_fd;
	mbedtls_entropy_context		entropy;
	mbedtls_ctr_drbg_context	ctr_drbg;
	mbedtls_ssl_context			ssl;
	mbedtls_ssl_config			conf;
	mbedtls_x509_crt			cacert;
} sock_sec_t;

typedef struct __attribute__((aligned(4))) netx_t {
	union {
//		struct sockaddr_storage ss;	// largest, ensure space for ANY type/size
		struct sockaddr_in sa_in;
		struct sockaddr sa;
	};
	const char * pHost;				// name of host to connect to
	sock_sec_t * psSec;				// pointer to SSL/TLS config
	int error;						// error code return by last operation..
	int flags;						// Check implementation
	size_t maxTx, maxRx;
	i16_t sd;						// socket descriptor
	u16_t tOut;						// last timeout in mSec
	struct __attribute__((packed)) {
		u8_t trymax;				// max times to try read
		u8_t trynow;				// times tried
		u8_t spare;
		u8_t type:3;				// valid 1->5, STREAM/TCP, DGRAM/UDP or RAW/RAW
		u8_t uu:5;
	};
	union netx_dbg_u {				// debug control flags
		struct __attribute__((packed)) {
			u8_t o:1;				// open & socket
			u8_t h:1;				// gethost & connect
			u8_t bl:1;				// bind & listen
			u8_t t:1;				// timeouts
			u8_t a:1;				// accept
			u8_t s:1;				// select
			u8_t w:1;				// write/send
			u8_t r:1;				// read/recv
			u8_t d:1;				// data (used with read & write)
			u8_t cl:1;				// close
			u8_t sl:1;				// change syslog level in xNetGetError()
			u8_t ea:1;				// show EAGAIN errors
			// TLS related
			u8_t ver:1;				// enable certificate verification
			u8_t sec:1;				// enable TLS debug
			u8_t lvl:2;				// Mbed TLS 1=0, 2=1, 3=2, 4=3 (0=no debug not allowed)
			// HTTP support
			u8_t http:1;
			u16_t spare:15;
		};
		u32_t val;
	} d;
} netx_t;
DUMB_STATIC_ASSERT( sizeof(netx_t) == (36 + sizeof(struct sockaddr_in)));

typedef union netx_dbg_u netx_dbg_t;

// ####################################### Global variables ########################################


// ####################################### Global Functions ########################################

void xNetRestartStack( void );
EventBits_t xNetWaitLx(EventBits_t ReqBits, TickType_t xTicks);
int	xNetSetRecvTO(netx_t * psConn, u32_t mSecTime);
int	xNetSelect(netx_t * psConn, u8_t Flag);
int	xNetOpen(netx_t * psConn);
int	xNetAccept(netx_t * psServCtx, netx_t * psClntCtx, u32_t mSecTime);

// read/write with traditional buffers
int	xNetSend(netx_t * psConn, u8_t * pBuf, int xLen);
int	xNetSendBlocks(netx_t * psConn, u8_t * pBuf, int xLen, u32_t mSecTime);
int	xNetRecv(netx_t * psConn, u8_t * pBuf, int xLen);
int	xNetRecvBlocks(netx_t * psConn, u8_t * pBuf, int xLen, u32_t mSecTime);

// read/write using managed buffers
int	xNetSendUBuf(netx_t *, ubuf_t *, u32_t);
int	xNetRecvUBuf(netx_t *, ubuf_t *, u32_t);

int	xNetClose(netx_t * psConn);

struct report_t;
int	xNetReport(struct report_t * psR, netx_t * psConn, const char * pFname, int Code, void * pBuf, int xLen);
void xNetReportStats(struct report_t * psR);

#ifdef __cplusplus
}
#endif

/*
	if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
										 SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 ) {
		mbedtls_printf( " failed\r\n  ! mbedtls_net_connect returned %d\r\n\n", ret );
		goto exit;
	}

	while ((iRV = mbedtls_ssl_handshake(&psConn->psSec->ssl)) != erSUCCESS) {
		if ((iRV != MBEDTLS_ERR_SSL_WANT_READ) && (iRV != MBEDTLS_ERR_SSL_WANT_WRITE)) {
		  	break;
		}
	}
		// In real life, we probably want to bail out when ret != 0
			u32_t flags;
			if ((flags = mbedtls_ssl_get_verify_result(&psConn->psSec->ssl)) != erSUCCESS) {
				char vrfy_buf[512];
				mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
				mbedtls_printf( "%s\r\n", vrfy_buf );
			}
		}
*/
