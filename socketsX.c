/*
 * Copyright 2014-21 Andre M. Maree / KSS Technologies (Pty) Ltd.
 */


#include	"hal_variables.h"
#include	"socketsX.h"

#include	"printfx.h"									// +x_definitions +stdarg +stdint +stdio
#include	"syslog.h"
#include	"systiming.h"
#include	"x_errors_events.h"

#include	"mbedtls/certs.h"
#include	"mbedtls/error.h"

#ifdef	CONFIG_MBEDTLS_DEBUG
	#include	"mbedtls/debug.h"
#endif

#include	<string.h>
#include	<errno.h>

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG					0xF000

#define	debugOPEN					(debugFLAG & 0x0001)
#define	debugCLOSE					(debugFLAG & 0x0002)
#define	debugREAD					(debugFLAG & 0x0004)
#define	debugWRITE					(debugFLAG & 0x0008)

#define	debugACCEPT					(debugFLAG & 0x0010)
#define	debugSELECT					(debugFLAG & 0x0020)
#define	debugMBEDTLS				(debugFLAG & 0x0040)

#define	debugTIMING					(debugFLAG_GLOBAL & debugFLAG & 0x1000)
#define	debugTRACK					(debugFLAG_GLOBAL & debugFLAG & 0x2000)
#define	debugPARAM					(debugFLAG_GLOBAL & debugFLAG & 0x4000)
#define	debugRESULT					(debugFLAG_GLOBAL & debugFLAG & 0x8000)

// ######################################## Build macros ###########################################

#define	xnetBUFFER_SIZE 			1024

// ######################################## Local constants ########################################


// ####################################### Private variables ########################################


// ###################################### Local only functions #####################################

/* The problem with printfx() or any of the variants are
 * a) if the channel, STDOUT or STDERR, is redirected to a UDP/TCP connection
 * b) and the network connection is dropped; then
 * c) the detection of the socket being closed (or other error)
 * 	will cause the system to want to send more data to the (closed) socket.....
 * In order to avoid recursing back into syslog in cases of network errors
 * encountered in the syslog connection, we check on the ndebug flag.
 * If set we change the severity to ONLY go to the console and
 * not attempt to go out the network, which would bring it back here
 *
 * Graceful close (unexpected) returns 0 but sets errno to 128
 * errno = 128 NOT defined in errno.h
 *		https://github.com/espressif/esp-idf/issues/2540
 */

/**
 *
 */
EventBits_t xNetWaitLx(EventBits_t ReqBits, TickType_t xTicks) {
	EventBits_t CurBits;
	xTicks = (xTicks < 100) ? 100 : (xTicks == portMAX_DELAY) ? portMAX_DELAY : (xTicks + 5) % 10;
	do {
		CurBits = xRtosWaitStatusANY(ReqBits, pdMS_TO_TICKS(10));
		if ((CurBits & flagLX_STA) == flagLX_STA)
			return flagLX_STA;
		if ((CurBits & flagLX_SAP) == flagLX_SAP)
			return flagLX_SAP;
		if (xTicks != portMAX_DELAY)
			xTicks -= 10;
	} while (xTicks);
	return CurBits;
}

/**
 * @brief
 * @param	psConn
 * @param	eCode
 * @return
 */
static int xNetGetError(netx_t * psConn, const char * pFname, int eCode) {
#if 0
	psConn->error = eCode;
	bool fAlloc = 0;
	char * pcMess = NULL ;
	 // Lowest	: MBEDTLS_ERR_SSL_HW_ACCEL_FAILED  			-0x7F80
	 // Highest	: MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT	-0x1080
	if (INRANGE(-0x7F80, eCode, -0x1080, int)) {
		if (eCode == MBEDTLS_ERR_SSL_WANT_READ || eCode == MBEDTLS_ERR_SSL_WANT_WRITE) {
			psConn->error = EAGAIN;
		} else {
			pcMess = pvRtosMalloc(xnetBUFFER_SIZE) ;
			mbedtls_strerror(eCode, pcMess, xnetBUFFER_SIZE);
			fAlloc = 1 ;
		}
	} else {
		pcMess = (char *) lwip_strerr(-eCode);
	}
	if (psConn->d_eagain || psConn->error != EAGAIN) {
		vSyslog(psConn->d_ndebug ? SL_SEV_DEBUG : SL_SEV_ERROR,
				pFname, "(%s:%d) err %d => %d (%s)", psConn->pHost,
				ntohs(psConn->sa_in.sin_port), eCode, psConn->error, pcMess);
		if (fAlloc)
			vRtosFree(pcMess);
	}
	/* XXX: strange & need further investigation, does not make sense. Specifically done to
	 * avoid Telnet closing connection when eCode = -1 but errno = 0 return erFAILURE ; */
	return psConn->error ? erFAILURE : erSUCCESS ;
#else
	psConn->error = eCode;
	if (psConn->d_eagain || eCode != EAGAIN) {
		// to ensure that Syslog related errors does not get logged again, lift the level
		int Level = psConn->d_ndebug ? ioB3GET(ioSLhost) + 1 : SL_SEV_ERROR;
		vSyslog(Level, pFname, "%s:%d err=%d (%s)",
			psConn->pHost, ntohs(psConn->sa_in.sin_port), eCode, esp_err_to_name(eCode));
	}
	/* XXX: strange & need further investigation, does not make sense. Specifically done to
	 * avoid Telnet closing connection when eCode = -1 but errno = 0 return erFAILURE ; */
	return psConn->error ? erFAILURE : erSUCCESS ;
#endif
}

// Based on example found at https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client1.c
static void vNetMbedDebug(void * ctx, int level, const char * file, int line, const char * str) {
	netx_t * psCtx = ctx ;
	if (psCtx->d_secure && psCtx->d_level >= level) {
		printfx("L=%d  %s", level, str ) ;
		if (level == 4)
			printfx("  %d:%s", line, file) ;
		printfx("\n") ;
	}
}

/**
 * Certificate verification callback for mbed TLS
 * Here we only use it to display information on each cert in the chain
 */
static int xNetMbedVerify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
	(void) data;
	printfx("xNetMbedVerify: Verifying certificate at depth %d:\n", depth);
	pi8_t pBuf = pvRtosMalloc(xnetBUFFER_SIZE) ;
	mbedtls_x509_crt_info(pBuf, xnetBUFFER_SIZE, "  ", crt);
	printfx(pBuf);
	if (*flags == 0) {
		printfx("xNetMbedVerify: No verification issue for this certificate\n");
	} else {
		mbedtls_x509_crt_verify_info(pBuf, xnetBUFFER_SIZE-1, "  ! ", *flags);
		printfx("xNetMbedVerify: %s\n", pBuf);
	}
	vRtosFree(pBuf) ;
	return 0 ;
}

static int xNetMbedInit(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn->psSec)) ;
	IF_myASSERT(debugPARAM, halCONFIG_inFLASH(psConn->psSec->pcCert)) ;
	IF_myASSERT(debugPARAM, psConn->psSec->szCert == strlen((const char *)psConn->psSec->pcCert) + 1) ;

	mbedtls_net_init(&psConn->psSec->server_fd) ;
	mbedtls_ssl_init(&psConn->psSec->ssl) ;
	mbedtls_entropy_init(&psConn->psSec->entropy ) ;
	mbedtls_ctr_drbg_init(&psConn->psSec->ctr_drbg) ;
	mbedtls_x509_crt_init(&psConn->psSec->cacert) ;
	mbedtls_ssl_config_init(&psConn->psSec->conf) ;

	i8_t random_key[xpfMAX_LEN_X64] ;
	int iRV = snprintfx(random_key, sizeof(random_key), "%llu", RunTime) ;
	iRV = mbedtls_ctr_drbg_seed(&psConn->psSec->ctr_drbg, mbedtls_entropy_func, &psConn->psSec->entropy, (pcu8_t) random_key, iRV) ;
	if (iRV != 0)
		return xNetGetError(psConn, "mbedtls_ctr_drbg_seed", iRV) ;
#if 1
	iRV = mbedtls_x509_crt_parse(&psConn->psSec->cacert, (pcu8_t) psConn->psSec->pcCert, psConn->psSec->szCert) ;
#else
	if (psConn->psSec->pcCert) {			// use provided certificate
		iRV = mbedtls_x509_crt_parse(&psConn->psSec->cacert, psConn->psSec->pcCert, psConn->psSec->szCert) ;
	} else {							// use default certificate list
		iRV = mbedtls_x509_crt_parse(&psConn->psSec->cacert, (pcu8_t) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len) ;
	}
#endif
	if (iRV != 0)
		return xNetGetError(psConn, "mbedtls_x509_crt_parse", iRV) ;
	iRV = mbedtls_ssl_setup( &psConn->psSec->ssl, &psConn->psSec->conf) ;
	if (iRV != 0)
		return xNetGetError(psConn, "mbedtls_ssl_setup", iRV) ;
	iRV = mbedtls_ssl_config_defaults(&psConn->psSec->conf,
			(psConn->pHost == 0)			? MBEDTLS_SSL_IS_SERVER			: MBEDTLS_SSL_IS_CLIENT,
			(psConn->type == SOCK_STREAM)	? MBEDTLS_SSL_TRANSPORT_STREAM	: MBEDTLS_SSL_TRANSPORT_DATAGRAM,
			MBEDTLS_SSL_PRESET_DEFAULT) ;
	if (iRV != 0)
		return xNetGetError(psConn, "mbedtls_ssl_config_defaults", iRV) ;
	mbedtls_ssl_conf_ca_chain(&psConn->psSec->conf, &psConn->psSec->cacert, NULL) ;
	mbedtls_ssl_conf_rng( &psConn->psSec->conf, mbedtls_ctr_drbg_random, &psConn->psSec->ctr_drbg );

#if	(CONFIG_MBEDTLS_DEBUG > 0)
	if (psConn->d_secure) {
		mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL) ;
		mbedtls_ssl_conf_dbg(&psConn->psSec->conf, vNetMbedDebug, psConn) ;
//		esp_log_level_set("", CONFIG_MBEDTLS_DEBUG_LEVEL) ;
	}
#endif
 	return iRV ;
}

static void vNetMbedDeInit(netx_t * psConn) {
	mbedtls_net_free(&psConn->psSec->server_fd) ;
	mbedtls_x509_crt_free(&psConn->psSec->cacert) ;
	mbedtls_ssl_free(&psConn->psSec->ssl) ;
	mbedtls_ssl_config_free(&psConn->psSec->conf) ;
	mbedtls_ctr_drbg_free(&psConn->psSec->ctr_drbg) ;
	mbedtls_entropy_free(&psConn->psSec->entropy) ;
}

/*
 * xNetReport()
 */
int xNetReport(netx_t * psConn, const char * pFname, int Code, void * pBuf, int xLen) {
	printfx("%C%-s%C\t%s  %s://%-I:%d (%s)  sd=%d  %s=%d  Try=%d/%d  tOut=%d  mode=0x%02x  flag=0x%x  error=%d\n",
			colourFG_CYAN, pFname, attrRESET,
			(psConn->sa_in.sin_family == AF_INET) ? "ip4" : (psConn->sa_in.sin_family == AF_INET6) ? "ip6" : "ip?",
			(psConn->type == SOCK_DGRAM) ? "udp" : (psConn->type == SOCK_STREAM) ? "tcp" : "raw",
			ntohl(psConn->sa_in.sin_addr.s_addr), ntohs(psConn->sa_in.sin_port),
			psConn->pHost, psConn->sd, Code < erFAILURE ? esp_err_to_name(Code) : (Code > 0) ? "Count" : "iRV",
			Code, psConn->trynow, psConn->trymax, psConn->tOut, psConn->d_flags, psConn->flags, psConn->error) ;
	if (psConn->d_data && pBuf && xLen)
		printfx("%!'+B", xLen, pBuf);
	return erSUCCESS ;
}

#define OPT_RESOLVE					1

static int xNetGetHost(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn));
	vRtosWaitStatus(flagLX_STA);
	#if (OPT_RESOLVE == 1)				// [lwip_]getaddrinfo 		WORKS!!!
	struct addrinfo * psAI;
	struct addrinfo sAI;
	memset (&sAI, 0, sizeof(sAI));
//	sAI.ai_flags = AI_PASSIVE;
	sAI.ai_family = psConn->sa_in.sin_family;
	sAI.ai_socktype = psConn->type;
	char portnum[16];
	snprintf(portnum, sizeof(portnum), "%d", ntohs(psConn->sa_in.sin_port));
	int iRV = getaddrinfo(psConn->pHost, portnum, &sAI, &psAI);
	if (iRV != 0 || psAI == NULL) {
//		P("Host=%s  iRV=%d\n", psConn->pHost, iRV);
		iRV = xNetGetError(psConn, __FUNCTION__, iRV);
	} else {
		psConn->error = 0;
		struct sockaddr_in * sa_in = (struct sockaddr_in *) psAI->ai_addr;
		psConn->sa_in.sin_addr.s_addr = sa_in->sin_addr.s_addr;
//		P("Host=%s  AddrLen=%d  IP=%#-I", psConn->pHost, psAI->ai_addrlen, psConn->sa_in.sin_addr.s_addr);
		if (debugOPEN || psConn->d_open)
			xNetReport(psConn, __FUNCTION__, 0, 0, 0);
	}
	if (psAI != NULL)
		freeaddrinfo(psAI);
	return iRV;
	#elif (OPT_RESOLVE == 2)			// [lwip_]gethostbyname()	UNRELIABLE

	static SemaphoreHandle_t GetHostMux;
	xRtosSemaphoreTake(&GetHostMux, portMAX_DELAY);
	int iRV = erSUCCESS;
	struct hostent * psHE = gethostbyname(psConn->pHost);
//	P("Host=:%s  psHE=%p\n", psConn->pHost, psHE);
//	IF_P(psHE, "Name=%s\n", psHE->h_name);
//	IF_P(psHE, "Type=%d\n", psHE->h_addrtype);
//	IF_P(psHE, "Len=%d\n", psHE->h_length);
//	IF_P(psHE, "List=%p\n", psHE->h_addr_list);
//	IF_P(psHE && psHE->h_addr_list, "List[0]=%p\n", psHE->h_addr_list[0]);
//	IF_P(psHE && psHE->h_addr_list && psHE->h_addr_list[0], "Addr[0]=%-#I\n", ((struct in_addr *) psHE->h_addr_list[0])->s_addr);
	if ((psHE == NULL) || (psHE->h_addrtype != AF_INET) ||
		(psHE->h_addr_list == NULL) || (psHE->h_addr_list[0] == NULL)) {
		iRV = xNetGetError(psConn, __FUNCTION__, h_errno);
	} else {
		psConn->error = iRV;
		struct in_addr * psIA = (struct in_addr *) psHE->h_addr_list[0];
		psConn->sa_in.sin_addr.s_addr = psIA->s_addr;
//		RP("IP Address: %-#I\n", psConn->sa_in.sin_addr.s_addr);
		if (debugOPEN || psConn->d_open)
			xNetReport(psConn, __FUNCTION__, 0, 0, 0);
	}
	xRtosSemaphoreGive(&GetHostMux);
	return iRV;

	#elif (OPT_RESOLVE == 3)			// [lwip_]gethostbyname_r()	UNRELIABLE
	struct hostent sHE, * psHE;
	size_t hstbuflen = 256;
	char *tmphstbuf;
	int iRV, psAI;
	/* Allocate buffer, remember to free it to avoid memory leakage.  */
	tmphstbuf = malloc (hstbuflen);
	while ((iRV = gethostbyname_r (psConn->pHost, &sHE, tmphstbuf, hstbuflen, &psHE, &psAI)) == ERANGE) {
		/* Enlarge the buffer.  */
		hstbuflen *= 2;
		tmphstbuf = realloc (tmphstbuf, hstbuflen);
	}
	P("Host=:%s psHE=%p Size=%d iRV=%d res=%d\n", psConn->pHost, psHE, hstbuflen, iRV, psAI);
	/*  Check for errors.  */
	if (psAI || psHE == NULL) {
		iRV = xNetGetError(psConn, __FUNCTION__, psAI) ;
	} else {
		IF_P(psHE, "Name=%s  Type=%d  Len=%d  List=%p",
				psHE->h_name, psHE->h_addrtype, psHE->h_length, psHE->h_addr_list);
		IF_P(psHE && psHE->h_addr_list, "  List[0]=%p", psHE->h_addr_list[0]);
		IF_P(psHE && psHE->h_addr_list && psHE->h_addr_list[0], "  Addr[0]=%-#I", ((struct in_addr *) psHE->h_addr_list[0])->s_addr);
		P("\n");
		psConn->error = 0 ;
		struct in_addr * psIA = (struct in_addr *) psHE->h_addr_list[0] ;
		psConn->sa_in.sin_addr.s_addr = psIA->s_addr;
		if (debugOPEN || psConn->d_open)
			xNetReport(psConn, __FUNCTION__, 0, 0, 0);
	}
	free(tmphstbuf);
	return iRV;
	#elif (OPT_RESOLVE == 4)			// netconn_gethostbyname_addrtype()
	ip_addr_t addr;
	int iRV = netconn_gethostbyname_addrtype(psConn->pHost, &addr, AF_INET);
	TRACK("Host=%s  iRV=%d  type=%d  so1=%d  so2=%d so3=%d\n", psConn->pHost, iRV, addr.type,
		sizeof(struct sockaddr_storage), sizeof(struct sockaddr), sizeof(struct sockaddr_in));
	if (iRV == ERR_OK) {
		TRACK();
		psConn->error = 0;
		struct sockaddr_in * psSAI = &psConn->sa_in;
//		psConn->sa_in.sin_addr.s_addr = addr.u_addr.ip4.addr;
		psSAI->sin_addr.s_addr = addr.u_addr.ip4.addr;
		if (debugOPEN || psConn->d_open)
			xNetReport(psConn, __FUNCTION__, 0, 0, 0);
	} else {
		TRACK();
		iRV = xNetGetError(psConn, __FUNCTION__, errno);
	}
	return iRV;
	#endif
}

static int xNetSocket(netx_t * psConn)  {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	int iRV = socket(psConn->sa_in.sin_family, psConn->type, IPPROTO_IP) ;
	/* Socket() can return any number from 0 upwards as a valid descriptor but since
	 * 0=stdin, 1=stdout & 2=stderr normal descriptor would be greater than 2 ie 3+ */
	if (iRV < 0)
		return xNetGetError(psConn, __FUNCTION__, errno);
	psConn->error = 0;
	psConn->sd = (int16_t) iRV;
	if (psConn->psSec)
		psConn->psSec->server_fd.fd = iRV;
	if (debugOPEN || psConn->d_open)
		xNetReport(psConn, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

#if	(netxBUILD_SPC == 1)
static int xNetSecurePreConnect(netx_t * psConn) {	return 0; }
#endif

/**
 * @brief
 * @return	0 if successful, -1 with error level set if not...
 */
static int xNetConnect(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
  	int iRV = connect(psConn->sd, &psConn->sa, sizeof(struct sockaddr_in)) ;
  	if (iRV != 0)
  		return xNetGetError(psConn, __FUNCTION__, errno) ;
	psConn->error	= 0 ;
	psConn->connect = 1 ;
	if (debugOPEN || psConn->d_open)
		xNetReport(psConn, __FUNCTION__, iRV, 0, 0) ;
	return iRV ;
}

/*
 * @brief
 * @return
 */
int xNetSetNonBlocking(netx_t * psConn, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	psConn->tOut = mSecTime ;
//	int iRV = ioctlsocket(psConn->sd, FIONBIO, &mSecTime) ;		// 0 = Disable, 1+ = Enable NonBlocking
	int iRV = ioctl(psConn->sd, FIONBIO, &mSecTime) ;		// 0 = Disable, 1+ = Enable NonBlocking
	if (iRV != 0)
		return xNetGetError(psConn, __FUNCTION__, iRV) ;
	psConn->error = 0 ;
	if (psConn->d_timing)
		SL_INFO("%d = %sBLOCKING", mSecTime, (mSecTime == 0) ? "" : "NON-") ;
	return iRV;
}

/*
 * xNetSetRecvTimeOut() -
 */
int	xNetSetRecvTimeOut(netx_t * psConn, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	if (mSecTime <= flagXNET_NONBLOCK)
		return xNetSetNonBlocking(psConn, mSecTime);
	psConn->tOut	= mSecTime ;
	struct timeval timeVal ;
	timeVal.tv_sec	= psConn->tOut / MILLIS_IN_SECOND ;
	timeVal.tv_usec = (psConn->tOut * MICROS_IN_MILLISEC ) % MICROS_IN_SECOND ;
	int iRV = setsockopt(psConn->sd, SOL_SOCKET, SO_RCVTIMEO, &timeVal, sizeof(timeVal));
	if (iRV < 0)
		return xNetGetError(psConn, __FUNCTION__, errno);
	psConn->error	= 0 ;
	if (psConn->d_timing) {
		socklen_t SockOptLen ;
		SockOptLen = sizeof(timeVal) ;
		getsockopt(psConn->sd, SOL_SOCKET, SO_RCVTIMEO, &timeVal, &SockOptLen) ;
		RP("tOut=%d mSec\n", (timeVal.tv_sec * MILLIS_IN_SECOND) + (timeVal.tv_usec / MICROS_IN_MILLISEC)) ;
	}
	return iRV ;
}

/*
 * xNetAdjustTimeout()
 */
uint32_t xNetAdjustTimeout(netx_t * psConn, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	psConn->trynow	= psConn->error	= 0 ;
	// must pass thru mSecTime of 0 (blocking) and 1 (non-blocking)
	if (mSecTime <= flagXNET_NONBLOCK) {
		psConn->trymax	= 1 ;
 		psConn->tOut = mSecTime;
		return mSecTime ;
	}
	// adjust the lower limit.
	if (mSecTime < configXNET_MIN_TIMEOUT)
		mSecTime = configXNET_MIN_TIMEOUT ;
	if ((mSecTime / configXNET_MIN_TIMEOUT) > configXNET_MAX_RETRIES)
		psConn->trymax = configXNET_MAX_RETRIES ;
	else
		psConn->trymax = (mSecTime + configXNET_MIN_TIMEOUT - 1) / configXNET_MIN_TIMEOUT ;

	psConn->tOut = (psConn->trymax > 0) ? (mSecTime / psConn->trymax) : mSecTime ;
	if (psConn->d_timing)
		xNetReport(psConn, __FUNCTION__, mSecTime, 0, 0) ;
	return 	psConn->tOut ;
}

int	xNetBindListen(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	int iRV = 0 ;
	if (psConn->flags & SO_REUSEADDR) {
		int enable = 1 ;
		iRV = setsockopt(psConn->sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) ;
	}
	if (iRV == 0) {
		iRV = bind(psConn->sd, &psConn->sa, sizeof(struct sockaddr_in)) ;
		if (iRV == 0 && psConn->type == SOCK_STREAM)
			iRV = listen(psConn->sd, 10) ;	// config for listen, max queue backlog of 10
	}
	if (iRV < 0)
		return xNetGetError(psConn, "bind/listen", errno) ;
	psConn->error = 0 ;
	if (debugOPEN || psConn->d_open)
		xNetReport(psConn, "bind/listen", iRV, 0, 0) ;
	return iRV ;
}

int	xNetSecurePostConnect(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	int iRV = mbedtls_ssl_set_hostname(&psConn->psSec->ssl, psConn->pHost) ;
	// OPTIONAL is not recommended for security but makes inter-operability easier
	mbedtls_ssl_conf_authmode(&psConn->psSec->conf, psConn->psSec->Verify
			? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL) ;
	if (psConn->psSec->Verify) {
		uint32_t Result ;
		iRV = mbedtls_x509_crt_verify(&psConn->psSec->cacert, &psConn->psSec->cacert,
			NULL, NULL, &Result, xNetMbedVerify, psConn) ;
	}
	mbedtls_ssl_set_bio(&psConn->psSec->ssl, &psConn->psSec->server_fd,
			mbedtls_net_send, mbedtls_net_recv, NULL) ;
	if (iRV != 0)
		return xNetGetError(psConn, __FUNCTION__, iRV) ;
	psConn->error = 0 ;
	if (psConn->d_secure)
		xNetReport(psConn, __FUNCTION__, iRV, 0, 0);
	return iRV ;
}

/*
 * @brief	open a UDP/TCP socket based on specific parameters
 * @param   psConn = pointer to connection context
 * @param	pHostanme = pointer to the host URL to connect to
 * @param	psSec = pointer to the SSL/TLS security parameters
 * @return	status of last socket operation (ie < erSUCCESS indicates error code)
 */
int	xNetOpen(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	int	iRV;
	xNetWaitLx(flagLX_ANY, portMAX_DELAY);
	// STEP 0: just for mBed TLS Initialize the RNG and the session data
	if (psConn->psSec) {
		iRV = xNetMbedInit(psConn) ;
		if (iRV != erSUCCESS) {
			vNetMbedDeInit(psConn) ;
			return iRV ;
		}
	}

	// STEP 1: if connecting as client, resolve the host name & IP address
	if (psConn->pHost) {							// Client type connection ?
		iRV = xNetGetHost(psConn) ;
		if (iRV < erSUCCESS)
			return iRV;
	} else {
		psConn->sa_in.sin_addr.s_addr = htonl(INADDR_ANY) ;
	}

	// STEP 2: open a [secure] socket to the remote
	iRV = xNetSocket(psConn) ;
	if (iRV < erSUCCESS)
		return iRV;
	#if	(netxBUILD_SPC == 1)
	// STEP 3: configure the specifics (method, mask & certificate files) of the SSL/TLS component
	if (psConn->psSec) {
		iRV = xNetSecurePreConnect(psConn) ;
		if (iRV < erSUCCESS)
			return iRV;
	}
	#endif

	// STEP 4: Initialize Client or Server connection
	iRV = (psConn->pHost) ? xNetConnect(psConn) : xNetBindListen(psConn) ;
	if (iRV < erSUCCESS)
		return iRV;
	// STEP 5: configure the specifics (method, mask & certificate files) of the SSL/TLS component
	if (psConn->psSec) {
		iRV = xNetSecurePostConnect(psConn) ;
		if (iRV < erSUCCESS)
			return iRV;
	}
	if (debugOPEN || psConn->d_open)
		xNetReport(psConn, __FUNCTION__, iRV, 0, 0);
	return iRV ;
}

/**
 * xNetAccept()
 * @param psServCtx
 * @param psClntCtx
 * @param mSecTime
 * @return			on success file descriptor of the socket (positive value)
 * 					on failure erFAILURE (-1) with error set...
 */
int	xNetAccept(netx_t * psServCtx, netx_t * psClntCtx, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psServCtx) && halCONFIG_inSRAM(psClntCtx)) ;
	int iRV = xNetSetRecvTimeOut(psServCtx, mSecTime) ;
	if (iRV < 0)
		return iRV;
	memset(psClntCtx, 0, sizeof(netx_t)) ;		// clear the client context
	socklen_t len = sizeof(struct sockaddr_in) ;

	/* Also need to consider adding a loop to repeat the accept()
	 * in case of EAGAIN or POOL_IS_EMPTY errors */
	iRV = accept(psServCtx->sd, &psClntCtx->sa, &len) ;
	if (iRV < 0)
		return xNetGetError(psServCtx, __FUNCTION__, errno) ;
	psServCtx->error = 0 ;
	/* The server socket had flags set for BIND & LISTEN but the client
	 * socket should just be connected and marked same type & flags */
	psClntCtx->sd		= iRV ;
	psClntCtx->type		= psServCtx->type ;			// Make same type TCP/UDP/RAW
	psClntCtx->d_flags	= psServCtx->d_flags ;		// inherit all flags
	psClntCtx->psSec	= psServCtx->psSec ;		// TBC same security ??
	if (debugACCEPT || psServCtx->d_accept) {
		xNetReport(psServCtx, __FUNCTION__, iRV, 0, 0) ;
		xNetReport(psClntCtx, __FUNCTION__, iRV, 0, 0) ;
	}
	return iRV ;
}

/**
 * xNetSelect() - Used with write() to minimise the wait time...
 * @param psConn
 * @param Flag
 * @return
 */
int	xNetSelect(netx_t * psConn, uint8_t Flag) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn) && Flag < selFLAG_NUM) ;
	// If the timeout is too short dont select() just simulate 1 socket ready...
	if (psConn->tOut <= configXNET_MIN_TIMEOUT) return 1;
	// Need to add code here to accommodate LwIP & OpenSSL for ESP32
	fd_set	fdsSet ;
	FD_ZERO(&fdsSet) ;
	FD_SET(psConn->sd, &fdsSet) ;
	struct timeval	timeVal ;
	timeVal.tv_sec	= psConn->tOut / MILLIS_IN_SECOND ;
	timeVal.tv_usec = (psConn->tOut * MICROS_IN_MILLISEC) % MICROS_IN_SECOND ;

	// then do select based on new timeout
	int iRV = select(psConn->sd+1 , (Flag == selFLAG_READ)	? &fdsSet : 0,
									(Flag == selFLAG_WRITE) ? &fdsSet : 0,
									(Flag == selFLAG_EXCEPT)? &fdsSet : 0, &timeVal) ;
	if (iRV < 0)
		return xNetGetError(psConn, __FUNCTION__, errno) ;
	psConn->error = 0 ;
	if (debugSELECT || psConn->d_select)
		xNetReport(psConn, Flag == selFLAG_READ ? "read/select" :
							Flag == selFLAG_WRITE ? "write/select" :
							Flag == selFLAG_EXCEPT ? "except/select" : "", iRV, 0, 0) ;
	return iRV;
}

/**
 * xNetClose()  - closes the socket connection
 * @param[in]   psConn = pointer to connection context
 * @return	  result of the close (ie < erSUCCESS indicate error code)
 */
int	xNetClose(netx_t * psConn) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	int	iRV = erSUCCESS ;
	if (psConn->sd != -1) {
		if (psConn->d_close)
			xNetReport(psConn, "xNetClose1", psConn->error, 0, 0) ;
		if (psConn->psSec) {
			mbedtls_ssl_close_notify(&psConn->psSec->ssl) ;
			vNetMbedDeInit(psConn) ;
		}
		iRV = close(psConn->sd) ;
		psConn->sd = -1 ;								// mark as closed
		if (debugCLOSE || psConn->d_close)
			xNetReport(psConn, "xNetClose2", iRV, 0, 0) ;
	}
	return iRV ;
}

// #################################################################################################

/**
 * xNetWrite() -
 * @param	psConn
 * @param	pBuf
 * @param	xLen
 * @return	on success, positive number 1 -> iRV -> xLen indicating number of bytes written
 * 			on failure, -1 with error set to the actual code
 */
int	xNetWrite(netx_t * psConn, char * pBuf, int xLen) {
	// Check pBuf range against MEM not SRAM to allow COREDUMP from FLASH
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn) && halCONFIG_inMEM(pBuf) &&  xLen > 0);
	int iRV ;
	if (psConn->psSec) {
		iRV = mbedtls_ssl_write(&psConn->psSec->ssl, (unsigned char *) pBuf, xLen) ;
	} else {
		if (psConn->connect) {
			iRV = send(psConn->sd, pBuf, xLen, psConn->flags) ;
		} else {
			iRV = sendto(psConn->sd, pBuf, xLen, psConn->flags, &psConn->sa, sizeof(psConn->sa_in)) ;
		}
	}
	if (iRV < 0) {
		return xNetGetError(psConn, __FUNCTION__, errno) ;
	}
	psConn->error = 0 ;
	psConn->maxTx = (iRV > psConn->maxTx) ? iRV : psConn->maxTx ;
	if (debugWRITE || psConn->d_write) {
		xNetReport(psConn, __FUNCTION__, iRV, pBuf, iRV);
	}
	return iRV;
}

/**
 * xNetRead()
 * @param	psConn
 * @param	pBuf
 * @param	xLen
 * @param	i16Flags
 * @return	on success, positive number 1 -> iRV -> xLen indicating number of bytes read
 * 			on failure,
 */
int	xNetRead(netx_t * psConn, char * pBuf, int xLen) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn) && halCONFIG_inSRAM(pBuf) && (xLen > 0)) ;
	int	iRV ;
	if (psConn->psSec) {
		iRV = mbedtls_ssl_read( &psConn->psSec->ssl, (unsigned char *) pBuf, xLen) ;
	} else {
		if (psConn->connect) {						// TCP read from socket (connection oriented)
			iRV = recv(psConn->sd, pBuf, xLen, psConn->flags) ;
		} else {									// UDP read from socket (connection-less)
			socklen_t i16AddrSize = sizeof(struct sockaddr_in) ;
			iRV = recvfrom(psConn->sd, pBuf, xLen, psConn->flags, &psConn->sa, &i16AddrSize) ;
		}
	}
	if (iRV < 0) {
		return xNetGetError(psConn, __FUNCTION__, errno) ;
	}
	psConn->error = 0 ;
	psConn->maxRx = (iRV > psConn->maxRx) ? iRV : psConn->maxRx ;
	if (debugREAD || psConn->d_read) {
		xNetReport(psConn, __FUNCTION__, iRV, pBuf, iRV);
	}
	return iRV ;
}

// #################################################################################################

/**
 * xNetWriteBlocks() - write to a TCP/UDP socket connection
 * @param	psConn	pointer to connection context
 * @param	pBuf		pointer to the buffer to write from
 * @param	xLen		number of bytes in buffer to write
 * @param	i16Flags	flags as defined in socket.h
 * @param	mSecTime	number of milli-seconds to block
 * @return	number of bytes written (ie < erSUCCESS indicates error code)
 */
int	xNetWriteBlocks(netx_t * psConn, char * pBuf, int xLen, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn)) ;
	IF_myASSERT(debugPARAM, halCONFIG_inMEM(pBuf)) ;
	IF_myASSERT(debugPARAM, xLen > 0) ;
	int	iRV, xLenDone = 0 ;
	mSecTime = xNetAdjustTimeout(psConn, mSecTime) ;
	do {
		iRV = xNetSelect(psConn, selFLAG_WRITE) ;
		if (iRV < 0) break ;
		if (iRV == 0) continue ;						// try again
		iRV = xNetWrite(psConn, pBuf + xLenDone, xLen - xLenDone) ;
		if (iRV > -1) {
			xLenDone += iRV ;
		} else if (psConn->error == EAGAIN)	{
			continue ;
		} else {
			break ;
		}
	} while((++psConn->trynow < psConn->trymax) && (xLenDone < xLen)) ;
	return (xLenDone > 0) ? xLenDone : iRV ;
}

/**
 * xNetReadBlocks() - read from a TCP/UDP connection
 * @param[in]   psConn = pointer to connection context
 * @param[in]	pBuf = pointer to the buffer to read into
 * @param[in]	xLen = max number of bytes in buffer to read
 * @param[in]	i16Flags = flags as defined in socket.h
 * @param[in]	mSecTime = number of milli-seconds to block
 * @return	  number of bytes read (ie < erSUCCESS indicates error code)
 */
int	xNetReadBlocks(netx_t * psConn, char * pBuf, int xLen, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psConn) && halCONFIG_inSRAM(pBuf) && (xLen > 0)) ;
	mSecTime = xNetAdjustTimeout(psConn, mSecTime) ;
	xNetSetRecvTimeOut(psConn, mSecTime) ;
	int	iRV, xLenDone = 0 ;
	do {
		iRV = xNetRead(psConn, pBuf + xLenDone, xLen - xLenDone) ;
		if (iRV > -1) {
			xLenDone +=	iRV ;
		} else if (psConn->error == EAGAIN)	{
			continue ;
		} else {
			break ;
		}
 	} while ((++psConn->trynow < psConn->trymax) && (xLenDone < xLen)) ;
	return (xLenDone > 0) ? xLenDone : iRV ;
}

// #################################################################################################

int	xNetWriteFromBuf(netx_t * psConn, ubuf_t * psBuf, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psBuf) && halCONFIG_inSRAM(psBuf->pBuf) && (psBuf->Size > 0)) ;
	int	iRV = xNetWriteBlocks(psConn, psBuf->pBuf + psBuf->IdxRD, psBuf->Used, mSecTime) ;
	if (iRV > erSUCCESS) {
		psBuf->IdxRD	+= iRV ;
		psBuf->Used		-= iRV ;
	}
	return iRV ;
}

int	xNetReadToBuf(netx_t * psConn, ubuf_t * psBuf, uint32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psBuf) && halCONFIG_inSRAM(psBuf->pBuf) && (psBuf->Size > 0)) ;
	int iRV = xNetReadBlocks(psConn, psBuf->pBuf + psBuf->IdxWR, psBuf->Used, mSecTime) ;
	if (iRV > erSUCCESS) {
		psBuf->IdxWR	+= iRV ;
		psBuf->Used		+= iRV ;
	}
	return iRV ;
}

// #################################################################################################

void xNetReportStats(void) {
	for (int i = 0; i < CONFIG_LWIP_MAX_SOCKETS; ++i) {
	    struct sockaddr_in addr;
	    socklen_t addr_size = sizeof(addr);
	    int sock = LWIP_SOCKET_OFFSET + i;
	    int res = getpeername(sock, (struct sockaddr *)&addr, &addr_size);
	    if (res == 0)
	    	printfx("sock: %d -- addr: %I, port: %d\n", sock, addr.sin_addr.s_addr, addr.sin_port) ;
	}
	printfx(
#if		(CONFIG_ESP32_WIFI_STATIC_TX_BUFFER == 1)
			"Wifi: Static Tx="	mySTRINGIFY(CONFIG_ESP32_WIFI_STATIC_TX_BUFFER_NUM)
			"  Rx="  			mySTRINGIFY(CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM)
			"  Dynamic Rx="		mySTRINGIFY(CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM) "\n"
#elif	(CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER == 1)
			"Wifi: Dynamic Tx="	mySTRINGIFY(CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM)
			"  Rx="				mySTRINGIFY(CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM)
			"  Static Rx="  	mySTRINGIFY(CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM) "\n"
#endif
			"LWIP: MaxSock="	mySTRINGIFY(CONFIG_LWIP_MAX_SOCKETS)
			"  RcvMboxSize="	mySTRINGIFY(CONFIG_TCPIP_RECVMBOX_SIZE) "\n"
			"TCP: Max Act="		mySTRINGIFY(CONFIG_LWIP_MAX_ACTIVE_TCP)
			"  Listen="			mySTRINGIFY(CONFIG_LWIP_MAX_LISTENING_TCP) "\n"
			"UDP: Max PCBs="	mySTRINGIFY(CONFIG_LWIP_MAX_UDP_PCBS)
			"  RxMboxSize=" 	mySTRINGIFY(CONFIG_UDP_RECVMBOX_SIZE) "\n") ;
	void dbg_lwip_tcp_pcb_show(void) ; dbg_lwip_tcp_pcb_show() ;
	void dbg_lwip_udp_pcb_show(void) ; dbg_lwip_udp_pcb_show() ;
	void dbg_lwip_stats_show(void) ; dbg_lwip_stats_show() ;
}
