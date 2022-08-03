/*
 * socketsX.c
 * Copyright (c) 2014-22 Andre M. Maree / KSS Technologies (Pty) Ltd.
 */

#include	"hal_variables.h"
#include	"socketsX.h"
#include	"printfx.h"									// +x_definitions +stdarg +stdint +stdio
#include	"syslog.h"
#include	"systiming.h"
#include	"x_errors_events.h"

#include	"mbedtls/error.h"

#ifdef	CONFIG_MBEDTLS_DEBUG
	#include	"mbedtls/debug.h"
#endif

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG					0xF000

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
	#define xnetSTEP	10
	#define xnetROUND	(xnetSTEP / 2)
	EventBits_t CurBits;
	xTicks = (xTicks < xnetSTEP) ? xnetSTEP :
			(xTicks == portMAX_DELAY) ? portMAX_DELAY :
			(xTicks + xnetROUND) % xnetSTEP;
	do {
		CurBits = xRtosWaitStatusANY(ReqBits, xnetSTEP);
		if ((CurBits & flagLX_STA) == flagLX_STA)
			return flagLX_STA;
		if ((CurBits & flagLX_SAP) == flagLX_SAP)
			return flagLX_SAP;
		if (xTicks != portMAX_DELAY)
			xTicks -= xnetSTEP;
	} while (xTicks);
	return CurBits;
}

/**
 * @brief
 * @param	psC
 * @param	eCode
 * @return
 */
static int xNetGetError(netx_t * psC, const char * pFname, int eCode) {
	psC->error = eCode;
	bool fAlloc = 0;
	char * pcMess = NULL ;
	 // Lowest	: MBEDTLS_ERR_SSL_HW_ACCEL_FAILED  			-0x7F80
	 // Highest	: MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT	-0x1080
	if (INRANGE(-0x7F80, eCode, -0x1080)) {
		if (eCode == MBEDTLS_ERR_SSL_WANT_READ || eCode == MBEDTLS_ERR_SSL_WANT_WRITE) {
			psC->error = EAGAIN;
		} else {
			pcMess = pvRtosMalloc(xnetBUFFER_SIZE) ;
			mbedtls_strerror(eCode, pcMess, xnetBUFFER_SIZE);
			fAlloc = 1 ;
		}
	} else {
		#ifdef LWIP_PROVIDE_ERRNO
		pcMess = (char *) lwip_strerr(eCode);
		#else
		pcMess = (char *) strerror(eCode);
		#endif
	}
	if (debugTRACK && (psC->d_eagain || eCode != EAGAIN)) {
		// to ensure that Syslog related errors does not get logged again, lift the level
		int Level = psC->d_ndebug ? ioB3GET(ioSLhost) + 1 : SL_SEV_ERROR;
		vSyslog(Level, pFname, "%s:%d err=%d (%s)", psC->pHost, ntohs(psC->sa_in.sin_port), eCode, pcMess);
	}
	if (fAlloc)
		vRtosFree(pcMess);
	/* XXX: strange & need further investigation, does not make sense. Specifically done to
	 * avoid Telnet closing connection when eCode = -1 but errno = 0 return erFAILURE ; */
	return psC->error ? erFAILURE : erSUCCESS ;
}

// Based on example found at https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client1.c
static void vNetMbedDebug(void * ctx, int level, const char * file, int line, const char * str) {
	if (level == 4)
		printfx("%d:%s  ", line, file);
	printfx("L=%d  %s\r\n", level, str );
}

/**
 * Certificate verification callback for mbed TLS
 * Here we only use it to display information on each cert in the chain
 */
static int xNetMbedVerify(void *data, mbedtls_x509_crt *crt, int depth, u32_t *flags) {
	(void) data;
	printfx("xNetMbedVerify: Verifying certificate at depth %d:\r\n", depth);
	pc_t pBuf = pvRtosMalloc(xnetBUFFER_SIZE) ;
	mbedtls_x509_crt_info(pBuf, xnetBUFFER_SIZE, "  ", crt);
	printfx(pBuf);
	if (*flags == 0) {
		printfx("xNetMbedVerify: No verification issue for this certificate\r\n");
	} else {
		mbedtls_x509_crt_verify_info(pBuf, xnetBUFFER_SIZE-1, "  ! ", *flags);
		printfx("xNetMbedVerify: %s\r\n", pBuf);
	}
	vRtosFree(pBuf) ;
	return 0 ;
}

static int xNetMbedInit(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC->psSec)) ;
	IF_myASSERT(debugPARAM, halCONFIG_inFLASH(psC->psSec->pcCert)) ;
	IF_myASSERT(debugPARAM, psC->psSec->szCert == strlen((const char *)psC->psSec->pcCert) + 1) ;

	mbedtls_net_init(&psC->psSec->server_fd) ;
	mbedtls_ssl_init(&psC->psSec->ssl) ;
	mbedtls_entropy_init(&psC->psSec->entropy ) ;
	mbedtls_ctr_drbg_init(&psC->psSec->ctr_drbg) ;
	mbedtls_x509_crt_init(&psC->psSec->cacert) ;
	mbedtls_ssl_config_init(&psC->psSec->conf) ;

	char random_key[xpfMAX_LEN_X64] ;
	int iRV = snprintfx(random_key, sizeof(random_key), "%llu", RunTime) ;
	iRV = mbedtls_ctr_drbg_seed(&psC->psSec->ctr_drbg, mbedtls_entropy_func, &psC->psSec->entropy, (pcuc_t) random_key, iRV) ;
	if (iRV != 0)
		return xNetGetError(psC, "mbedtls_ctr_drbg_seed", iRV) ;
#if 1
	iRV = mbedtls_x509_crt_parse(&psC->psSec->cacert, (pcuc_t) psC->psSec->pcCert, psC->psSec->szCert) ;
#else
	if (psC->psSec->pcCert) {			// use provided certificate
		iRV = mbedtls_x509_crt_parse(&psC->psSec->cacert, psC->psSec->pcCert, psC->psSec->szCert) ;
	} else {							// use default certificate list
		iRV = mbedtls_x509_crt_parse(&psC->psSec->cacert, (pcuc_t) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len) ;
	}
#endif
	if (iRV != 0)
		return xNetGetError(psC, "mbedtls_x509_crt_parse", iRV);
	iRV = mbedtls_ssl_config_defaults(&psC->psSec->conf,
			(psC->pHost == 0)			? MBEDTLS_SSL_IS_SERVER			: MBEDTLS_SSL_IS_CLIENT,
			(psC->type == SOCK_STREAM)	? MBEDTLS_SSL_TRANSPORT_STREAM	: MBEDTLS_SSL_TRANSPORT_DATAGRAM,
			MBEDTLS_SSL_PRESET_DEFAULT);
	if (iRV != 0)
		return xNetGetError(psC, "mbedtls_ssl_config_defaults", iRV);
	iRV = mbedtls_ssl_setup( &psC->psSec->ssl, &psC->psSec->conf);
	if (iRV != 0)
		return xNetGetError(psC, "mbedtls_ssl_setup", iRV);
	mbedtls_ssl_conf_ca_chain(&psC->psSec->conf, &psC->psSec->cacert, NULL);
	mbedtls_ssl_conf_rng( &psC->psSec->conf, mbedtls_ctr_drbg_random, &psC->psSec->ctr_drbg );

	#if	(CONFIG_MBEDTLS_DEBUG > 0)
	if (debugTRACK && psC->d_secure) {
		mbedtls_debug_set_threshold(psC->d_level + 1);
		mbedtls_ssl_conf_dbg(&psC->psSec->conf, vNetMbedDebug, psC);
	}
	#endif
 	return iRV ;
}

static void vNetMbedDeInit(netx_t * psC) {
	mbedtls_net_free(&psC->psSec->server_fd) ;
	mbedtls_x509_crt_free(&psC->psSec->cacert) ;
	mbedtls_ssl_free(&psC->psSec->ssl) ;
	mbedtls_ssl_config_free(&psC->psSec->conf) ;
	mbedtls_ctr_drbg_free(&psC->psSec->ctr_drbg) ;
	mbedtls_entropy_free(&psC->psSec->entropy) ;
}

/*
 * xNetReport()
 */
#if (debugTRACK)
int xNetReport(netx_t * psC, const char * pFname, int Code, void * pBuf, int xLen) {
	printfx_lock();
	printfx_nolock("%C%-s%C\t%s  %s://%-I:%d ",
			colourFG_CYAN, pFname, attrRESET,
			(psC->sa_in.sin_family == AF_INET) ? "ip4" : (psC->sa_in.sin_family == AF_INET6) ? "ip6" : "ip?",
			(psC->type == SOCK_DGRAM) ? "udp" : (psC->type == SOCK_STREAM) ? "tcp" : "raw",
			ntohl(psC->sa_in.sin_addr.s_addr), ntohs(psC->sa_in.sin_port));
	printfx_nolock("(%s)  sd=%d  %s=%d  Try=%d/%d  ",
			psC->pHost, psC->sd, Code < erFAILURE ? esp_err_to_name(Code) : (Code > 0) ? "Count" : "iRV",
			Code, psC->trynow, psC->trymax);
	printfx_nolock("TO=%d%s  D=0x%02X  F=0x%X  E=%d\r\n",
			psC->tOut, psC->tOut == 0 ? "(BLK)" :psC->tOut == 1 ? "(NB)" : "mSec",
			psC->d_flags, psC->flags, psC->error);
	if (psC->d_data && pBuf && xLen)
		printfx_nolock("%!`+B", xLen, pBuf);
	printfx_unlock();
	return erSUCCESS;
}
#endif

#define OPT_RESOLVE					1

static int xNetGetHost(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC));
	xNetWaitLx(flagLX_STA, portMAX_DELAY);
	#if (OPT_RESOLVE == 1)				// [lwip_]getaddrinfo 		WORKS!!!
	struct addrinfo * psAI;
	struct addrinfo sAI;
	memset (&sAI, 0, sizeof(sAI));
	sAI.ai_family = psC->sa_in.sin_family;
	sAI.ai_socktype = psC->type;
	char portnum[16];
	snprintf(portnum, sizeof(portnum), "%d", ntohs(psC->sa_in.sin_port));
	int iRV = getaddrinfo(psC->pHost, portnum, &sAI, &psAI);
	if (iRV != 0 || psAI == NULL) {
		iRV = xNetGetError(psC, __FUNCTION__, iRV);
	} else {
		struct sockaddr_in * sa_in = (struct sockaddr_in *) psAI->ai_addr;
		psC->sa_in.sin_addr.s_addr = sa_in->sin_addr.s_addr;
		if (debugTRACK && psC->d_host)
			xNetReport(psC, __FUNCTION__, 0, 0, 0);
	}
	if (psAI != NULL)
		freeaddrinfo(psAI);
	return iRV;
	#elif (OPT_RESOLVE == 2)			// [lwip_]gethostbyname()	UNRELIABLE

	static SemaphoreHandle_t GetHostMux;
	xRtosSemaphoreTake(&GetHostMux, portMAX_DELAY);
	int iRV = erSUCCESS;
	struct hostent * psHE = gethostbyname(psC->pHost);
//	P("Host=:%s  psHE=%p\r\n", psC->pHost, psHE);
//	IF_P(psHE, "Name=%s\r\n", psHE->h_name);
//	IF_P(psHE, "Type=%d\r\n", psHE->h_addrtype);
//	IF_P(psHE, "Len=%d\r\n", psHE->h_length);
//	IF_P(psHE, "List=%p\r\n", psHE->h_addr_list);
//	IF_P(psHE && psHE->h_addr_list, "List[0]=%p\r\n", psHE->h_addr_list[0]);
//	IF_P(psHE && psHE->h_addr_list && psHE->h_addr_list[0], "Addr[0]=%-#I\r\n", ((struct in_addr *) psHE->h_addr_list[0])->s_addr);
	if ((psHE == NULL) || (psHE->h_addrtype != AF_INET) ||
		(psHE->h_addr_list == NULL) || (psHE->h_addr_list[0] == NULL)) {
		iRV = xNetGetError(psC, __FUNCTION__, h_errno);
	} else {
		struct in_addr * psIA = (struct in_addr *) psHE->h_addr_list[0];
		psC->sa_in.sin_addr.s_addr = psIA->s_addr;
		if (debugTRACK && psC->d_host)
			xNetReport(psC, __FUNCTION__, 0, 0, 0);
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
	while ((iRV = gethostbyname_r (psC->pHost, &sHE, tmphstbuf, hstbuflen, &psHE, &psAI)) == ERANGE) {
		/* Enlarge the buffer.  */
		hstbuflen *= 2;
		tmphstbuf = realloc (tmphstbuf, hstbuflen);
	}
	P("Host=:%s psHE=%p Size=%d iRV=%d res=%d\r\n", psC->pHost, psHE, hstbuflen, iRV, psAI);
	/*  Check for errors.  */
	if (psAI || psHE == NULL) {
		iRV = xNetGetError(psC, __FUNCTION__, psAI) ;
	} else {
		IF_P(psHE, "Name=%s  Type=%d  Len=%d  List=%p",
				psHE->h_name, psHE->h_addrtype, psHE->h_length, psHE->h_addr_list);
		IF_P(psHE && psHE->h_addr_list, "  List[0]=%p", psHE->h_addr_list[0]);
		IF_P(psHE && psHE->h_addr_list && psHE->h_addr_list[0], "  Addr[0]=%-#I", ((struct in_addr *) psHE->h_addr_list[0])->s_addr);
		P("\r\n");
		struct in_addr * psIA = (struct in_addr *) psHE->h_addr_list[0] ;
		psC->sa_in.sin_addr.s_addr = psIA->s_addr;
		if (debugTRACK && psC->d_host)
			xNetReport(psC, __FUNCTION__, 0, 0, 0);
	}
	free(tmphstbuf);
	return iRV;
	#elif (OPT_RESOLVE == 4)			// netconn_gethostbyname_addrtype()
	ip_addr_t addr;
	int iRV = netconn_gethostbyname_addrtype(psC->pHost, &addr, AF_INET);
	TRACK("Host=%s  iRV=%d  type=%d  so1=%d  so2=%d so3=%d\r\n", psC->pHost, iRV, addr.type,
		sizeof(struct sockaddr_storage), sizeof(struct sockaddr), sizeof(struct sockaddr_in));
	if (iRV == ERR_OK) {
		struct sockaddr_in * psSAI = &psC->sa_in;
//		psC->sa_in.sin_addr.s_addr = addr.u_addr.ip4.addr;
		psSAI->sin_addr.s_addr = addr.u_addr.ip4.addr;
		if (debugTRACK && psC->d_host)
			xNetReport(psC, __FUNCTION__, 0, 0, 0);
	} else {
		TRACK();
		iRV = xNetGetError(psC, __FUNCTION__, errno);
	}
	return iRV;
	#endif
}

static int xNetSocket(netx_t * psC)  {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC));
	int iRV = socket(psC->sa_in.sin_family, psC->type, IPPROTO_IP);
	/* Socket() can return any number from 0 upwards as a valid descriptor but since
	 * 0=stdin, 1=stdout & 2=stderr normal descriptor would be greater than 2 ie 3+ */
	if (iRV < 0)
		return xNetGetError(psC, __FUNCTION__, errno);
	psC->sd = (s16_t) iRV;
	if (psC->psSec)
		psC->psSec->server_fd.fd = iRV;
	if (debugTRACK && psC->d_open)
		xNetReport(psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

int xNetSecurePreConnect(netx_t * psC) { return 0; }

/**
 * @brief
 * @return	0 if successful, -1 with error level set if not...
 */
static int xNetConnect(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC));
  	int iRV = connect(psC->sd, &psC->sa, sizeof(struct sockaddr_in));
  	if (iRV != 0)
  		return xNetGetError(psC, __FUNCTION__, errno);
	psC->connect = 1;
	if (debugTRACK && psC->d_host)
		xNetReport(psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

/*
 * @brief	Configure a socket to be non-blocking or with a specific timeout
 * @param	Socket context to use
 * @param	Timeout to be configured
 * @return	Actual period configured
 */
int	xNetSetRecvTO(netx_t * psC, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC));
	psC->tOut = mSecTime;
	int iRV;
	if (mSecTime <= flagXNET_NONBLOCK) {
		iRV = ioctl(psC->sd, FIONBIO, &mSecTime);		// 0 = Disable, 1+ = Enable NonBlocking
	} else {
		struct timeval timeVal;
		timeVal.tv_sec	= mSecTime / MILLIS_IN_SECOND;
		timeVal.tv_usec = (mSecTime * MICROS_IN_MILLISEC ) % MICROS_IN_SECOND;
		iRV = setsockopt(psC->sd, SOL_SOCKET, SO_RCVTIMEO, &timeVal, sizeof(timeVal));
		/*if (debugTRACK && psC->d_timing) {
			socklen_t SockOptLen ;
			SockOptLen = sizeof(timeVal);
			getsockopt(psC->sd, SOL_SOCKET, SO_RCVTIMEO, &timeVal, &SockOptLen);
			u32_t tOut = (timeVal.tv_sec * MILLIS_IN_SECOND) + (timeVal.tv_usec / MICROS_IN_MILLISEC);
			myASSERT(tOut == mSecTime);
		}*/
	}
	if (iRV != 0)
		return xNetGetError(psC, __FUNCTION__, iRV);
	if (debugTRACK && psC->d_timing)
		xNetReport(psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

/*
 * @brief	Used when reading/writing blocks/buffers to adjust the overall timeout specified
 * @param	Socket context to use
 * @param	Timeout (total) to be configured into multiple retries of a smaller periods
 * @return	Actual period configured
 */
u32_t xNetAdjustTimeout(netx_t * psC, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC)) ;
	psC->trynow	= 0;
	// must pass thru mSecTime of 0 (blocking) and 1 (non-blocking)
	if (mSecTime <= flagXNET_NONBLOCK) {
		psC->trymax	= 1 ;
 		psC->tOut = mSecTime;
		return mSecTime ;
	}
	// adjust the lower limit.
	if (mSecTime < configXNET_MIN_TIMEOUT)
		mSecTime = configXNET_MIN_TIMEOUT ;
	if ((mSecTime / configXNET_MIN_TIMEOUT) > configXNET_MAX_RETRIES)
		psC->trymax = configXNET_MAX_RETRIES ;
	else
		psC->trymax = (mSecTime + configXNET_MIN_TIMEOUT - 1) / configXNET_MIN_TIMEOUT ;

	psC->tOut = (psC->trymax > 0) ? (mSecTime / psC->trymax) : mSecTime;
	if (debugTRACK && psC->d_timing)
		xNetReport(psC, __FUNCTION__, mSecTime, 0, 0);
	return 	psC->tOut;
}

int	xNetBindListen(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC)) ;
	int iRV = 0 ;
	if (psC->flags & SO_REUSEADDR) {
		int enable = 1 ;
		iRV = setsockopt(psC->sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	}
	if (iRV == 0) {
		iRV = bind(psC->sd, &psC->sa, sizeof(struct sockaddr_in));
		if (iRV == 0 && psC->type == SOCK_STREAM)
			iRV = listen(psC->sd, 10);	// config for listen, max queue backlog of 10
	}
	if (iRV < 0)
		return xNetGetError(psC, __FUNCTION__, errno);
	if (debugTRACK && psC->d_bANDl)
		xNetReport(psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

int	xNetSecurePostConnect(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC));
	int iRV = mbedtls_ssl_set_hostname(&psC->psSec->ssl, psC->pHost);
	// OPTIONAL is not recommended for security but makes inter-operability easier
	mbedtls_ssl_conf_authmode(&psC->psSec->conf, psC->psSec->Verify
			? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
	if (psC->psSec->Verify) {
		u32_t Result;
		iRV = mbedtls_x509_crt_verify(&psC->psSec->cacert, &psC->psSec->cacert,
			NULL, NULL, &Result, xNetMbedVerify, psC);
	}
	mbedtls_ssl_set_bio(&psC->psSec->ssl, &psC->psSec->server_fd,
			mbedtls_net_send, mbedtls_net_recv, NULL);
	if (iRV != 0)
		return xNetGetError(psC, __FUNCTION__, iRV);
	if (debugTRACK && psC->d_secure)
		xNetReport(psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

/*
 * @brief	open a UDP/TCP socket based on specific parameters
 * @param   psC = pointer to connection context
 * @return	status of last socket operation (ie < erSUCCESS indicates error code)
 */
int	xNetOpen(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC)) ;
	int	iRV;
	xNetWaitLx(flagLX_ANY, portMAX_DELAY);
	// STEP 0: just for mBed TLS Initialize the RNG and the session data
	if (psC->psSec) {
		iRV = xNetMbedInit(psC) ;
		if (iRV != erSUCCESS) {
			vNetMbedDeInit(psC) ;
			return iRV ;
		}
	}

	// STEP 1: if connecting as client, resolve the host name & IP address
	if (psC->pHost) {							// Client type connection ?
		iRV = xNetGetHost(psC) ;
		if (iRV < erSUCCESS)
			return iRV;
	} else {
		psC->sa_in.sin_addr.s_addr = htonl(INADDR_ANY) ;
	}

	// STEP 2: open a [secure] socket to the remote
	iRV = xNetSocket(psC) ;
	if (iRV < erSUCCESS)
		return iRV;
	#if	(netxBUILD_SPC == 1)
	// STEP 3: configure the specifics (method, mask & certificate files) of the SSL/TLS component
	if (psC->psSec) {
		iRV = xNetSecurePreConnect(psC) ;
		if (iRV < erSUCCESS)
			return iRV;
	}
	#endif

	// STEP 4: Initialize Client or Server connection
	iRV = (psC->pHost) ? xNetConnect(psC) : xNetBindListen(psC) ;
	if (iRV < erSUCCESS)
		return iRV;
	// STEP 5: configure the specifics (method, mask & certificate files) of the SSL/TLS component
	if (psC->psSec) {
		iRV = xNetSecurePostConnect(psC) ;
		if (iRV < erSUCCESS)
			return iRV;
	}
	if (debugTRACK && psC->d_open)
		xNetReport(psC, __FUNCTION__, iRV, 0, 0);
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
int	xNetAccept(netx_t * psServCtx, netx_t * psClntCtx, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psServCtx) && halCONFIG_inSRAM(psClntCtx));
	// Set host/server RX timeout
	int iRV = xNetSetRecvTO(psServCtx, mSecTime);
	if (iRV < 0)
		return iRV;
	memset(psClntCtx, 0, sizeof(netx_t)) ;		// clear the client context
	socklen_t len = sizeof(struct sockaddr_in) ;

	/* Also need to consider adding a loop to repeat the accept()
	 * in case of EAGAIN or POOL_IS_EMPTY errors */
	iRV = accept(psServCtx->sd, &psClntCtx->sa, &len);
	if (iRV < 0)
		return xNetGetError(psServCtx, __FUNCTION__, errno);
	/* The server socket had flags set for BIND & LISTEN but the client
	 * socket should just be connected and marked same type & flags */
	psClntCtx->sd		= iRV ;
	psClntCtx->type		= psServCtx->type ;			// Make same type TCP/UDP/RAW
	psClntCtx->d_flags	= psServCtx->d_flags ;		// inherit all flags
	psClntCtx->psSec	= psServCtx->psSec ;		// TBC same security ??
	if (debugTRACK && psServCtx->d_accept) {
		xNetReport(psServCtx, __FUNCTION__, iRV, 0, 0) ;
		xNetReport(psClntCtx, __FUNCTION__, iRV, 0, 0) ;
	}
	return iRV ;
}

/**
 * xNetSelect() - Used with write() to minimise the wait time...
 * @param psC
 * @param Flag
 * @return
 */
int	xNetSelect(netx_t * psC, uint8_t Flag) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC) && Flag < selFLAG_NUM) ;
	// If the timeout is too short dont select() just simulate 1 socket ready...
	if (psC->tOut <= configXNET_MIN_TIMEOUT)
		return 1;
	// Need to add code here to accommodate LwIP & OpenSSL for ESP32
	fd_set	fdsSet ;
	FD_ZERO(&fdsSet) ;
	FD_SET(psC->sd, &fdsSet) ;
	struct timeval	timeVal ;
	timeVal.tv_sec	= psC->tOut / MILLIS_IN_SECOND ;
	timeVal.tv_usec = (psC->tOut * MICROS_IN_MILLISEC) % MICROS_IN_SECOND ;

	// do select based on new timeout
	int iRV = select(psC->sd+1 , (Flag == selFLAG_READ)	? &fdsSet : 0,
									(Flag == selFLAG_WRITE) ? &fdsSet : 0,
									(Flag == selFLAG_EXCEPT)? &fdsSet : 0, &timeVal) ;
	if (iRV < 0)
		return xNetGetError(psC, __FUNCTION__, errno);
	if (debugTRACK && psC->d_select)
		xNetReport(psC, Flag == selFLAG_READ ? "read/select" :
							Flag == selFLAG_WRITE ? "write/select" :
							Flag == selFLAG_EXCEPT ? "except/select" : "", iRV, 0, 0) ;
	return iRV;
}

/**
 * xNetClose()  - closes the socket connection
 * @param[in]   psC = pointer to connection context
 * @return	  result of the close (ie < erSUCCESS indicate error code)
 */
int	xNetClose(netx_t * psC) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC));
	int	iRV = erSUCCESS;
	if (psC->sd != -1) {
		if (debugTRACK && psC->d_close)
			xNetReport(psC, "xNetClose1", psC->error, 0, 0);
		if (psC->psSec) {
			mbedtls_ssl_close_notify(&psC->psSec->ssl);
			vNetMbedDeInit(psC);
		}
		iRV = close(psC->sd);
		psC->sd = -1;								// mark as closed
		if (debugTRACK && psC->d_close)
			xNetReport(psC, "xNetClose2", iRV, 0, 0);
	}
	return iRV;
}

// #################################################################################################

/**
 * @brief	Write data to host based on connection context
 * @param	psC
 * @param	pBuf
 * @param	xLen
 * @return	on success, positive number 1 -> iRV -> xLen indicating number of bytes written
 * 			on failure, -1 with error set to the actual code
 */
int	xNetWrite(netx_t * psC, u8_t * pBuf, int xLen) {
	// Check pBuf range against MEM not SRAM to allow COREDUMP from FLASH
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC) && halCONFIG_inMEM(pBuf) &&  xLen > 0);
	int iRV ;
	if (psC->psSec) {
		iRV = mbedtls_ssl_write(&psC->psSec->ssl, (unsigned char *) pBuf, xLen) ;
	} else {
		if (psC->connect) {
			iRV = send(psC->sd, pBuf, xLen, psC->flags) ;
		} else {
			iRV = sendto(psC->sd, pBuf, xLen, psC->flags, &psC->sa, sizeof(psC->sa_in)) ;
		}
	}
	if (iRV < 0)
		return xNetGetError(psC, __FUNCTION__, (errno != 0) ? errno : iRV);
	psC->maxTx = (iRV > psC->maxTx) ? iRV : psC->maxTx ;
	if (debugTRACK && psC->d_write)
		xNetReport(psC, __FUNCTION__, iRV, pBuf, iRV);
	return iRV;
}

/**
 * xNetRead()
 * @param	psC
 * @param	pBuf
 * @param	xLen
 * @param	i16Flags
 * @return	on success, positive number 1 -> iRV -> xLen indicating number of bytes read
 * 			on failure,
 */
int	xNetRead(netx_t * psC, u8_t * pBuf, int xLen) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC) && halCONFIG_inSRAM(pBuf) && (xLen > 0)) ;
	int	iRV ;
	if (psC->psSec) {
		iRV = mbedtls_ssl_read( &psC->psSec->ssl, (unsigned char *) pBuf, xLen) ;
	} else {
		if (psC->connect) {						// TCP read from socket (connection oriented)
			iRV = recv(psC->sd, pBuf, xLen, psC->flags) ;
		} else {									// UDP read from socket (connection-less)
			socklen_t i16AddrSize = sizeof(struct sockaddr_in) ;
			iRV = recvfrom(psC->sd, pBuf, xLen, psC->flags, &psC->sa, &i16AddrSize) ;
		}
	}
	if (iRV < 0)
		return xNetGetError(psC, __FUNCTION__, (errno != 0) ? errno : iRV);
	psC->maxRx = (iRV > psC->maxRx) ? iRV : psC->maxRx ;
	if (debugTRACK && psC->d_read)
		xNetReport(psC, __FUNCTION__, iRV, pBuf, iRV);
	return iRV ;
}

// #################################################################################################

/**
 * xNetWriteBlocks() - write to a TCP/UDP socket connection
 * @param	psC	pointer to connection context
 * @param	pBuf		pointer to the buffer to write from
 * @param	xLen		number of bytes in buffer to write
 * @param	i16Flags	flags as defined in socket.h
 * @param	mSecTime	number of milli-seconds to block
 * @return	number of bytes written (ie < erSUCCESS indicates error code)
 */
int	xNetWriteBlocks(netx_t * psC, u8_t * pBuf, int xLen, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC)) ;
	IF_myASSERT(debugPARAM, halCONFIG_inMEM(pBuf)) ;
	IF_myASSERT(debugPARAM, xLen > 0) ;
	int	iRV, xLenDone = 0 ;
	mSecTime = xNetAdjustTimeout(psC, mSecTime) ;
	do {
		iRV = xNetSelect(psC, selFLAG_WRITE) ;
		if (iRV < 0)
			break ;
		if (iRV == 0)
			continue ;						// try again
		iRV = xNetWrite(psC, pBuf + xLenDone, xLen - xLenDone) ;
		if (iRV > -1) {
			xLenDone += iRV ;
		} else if (psC->error == EAGAIN) {
			continue ;
		} else {
			break ;
		}
	} while((++psC->trynow < psC->trymax) && (xLenDone < xLen)) ;
	return (xLenDone > 0) ? xLenDone : iRV ;
}

/**
 * xNetReadBlocks() - read from a TCP/UDP connection
 * @param[in]   psC = pointer to connection context
 * @param[in]	pBuf = pointer to the buffer to read into
 * @param[in]	xLen = max number of bytes in buffer to read
 * @param[in]	i16Flags = flags as defined in socket.h
 * @param[in]	mSecTime = number of milli-seconds to block
 * @return	  number of bytes read (ie < erSUCCESS indicates error code)
 */
int	xNetReadBlocks(netx_t * psC, u8_t * pBuf, int xLen, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psC) && halCONFIG_inSRAM(pBuf) && (xLen > 0)) ;
	mSecTime = xNetAdjustTimeout(psC, mSecTime) ;
	xNetSetRecvTO(psC, mSecTime) ;
	int	iRV, xLenDone = 0 ;
	do {
		iRV = xNetRead(psC, pBuf + xLenDone, xLen - xLenDone) ;
		if (iRV > -1) {
			xLenDone +=	iRV ;
		} else if (psC->error == EAGAIN) {
			continue ;
		} else {
			break ;
		}
 	} while ((++psC->trynow < psC->trymax) && (xLenDone < xLen)) ;
	return (xLenDone > 0) ? xLenDone : iRV ;
}

// #################################################################################################

int	xNetWriteFromBuf(netx_t * psC, ubuf_t * psBuf, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psBuf) && halCONFIG_inSRAM(psBuf->pBuf) && (psBuf->Size > 0)) ;
	int	iRV = xNetWriteBlocks(psC, psBuf->pBuf + psBuf->IdxRD, psBuf->Used, mSecTime) ;
	if (iRV > erSUCCESS) {
		psBuf->IdxRD	+= iRV ;
		psBuf->Used		-= iRV ;
	}
	return iRV ;
}

int	xNetReadToBuf(netx_t * psC, ubuf_t * psBuf, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halCONFIG_inSRAM(psBuf) && halCONFIG_inSRAM(psBuf->pBuf) && (psBuf->Size > 0)) ;
	int iRV = xNetReadBlocks(psC, psBuf->pBuf + psBuf->IdxWR, psBuf->Used, mSecTime) ;
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
	    	printfx("sock: %d -- addr: %I, port: %d\r\n", sock, addr.sin_addr.s_addr, addr.sin_port) ;
	}
	printfx(
		#if	(CONFIG_ESP32_WIFI_STATIC_TX_BUFFER == 1)
			"Wifi: Static Tx="	mySTRINGIFY(CONFIG_ESP32_WIFI_STATIC_TX_BUFFER_NUM)
			"  Rx="  			mySTRINGIFY(CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM)
			"  Dynamic Rx="		mySTRINGIFY(CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM) "\r\n"
		#elif (CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER == 1)
			"Wifi: Dynamic Tx="	mySTRINGIFY(CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM)
			"  Rx="				mySTRINGIFY(CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM)
			"  Static Rx="  	mySTRINGIFY(CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM) "\r\n"
		#endif
			"LWIP: MaxSock="	mySTRINGIFY(CONFIG_LWIP_MAX_SOCKETS)
			"  RcvMboxSize="	mySTRINGIFY(CONFIG_TCPIP_RECVMBOX_SIZE) "\r\n"
			"TCP: Max Act="		mySTRINGIFY(CONFIG_LWIP_MAX_ACTIVE_TCP)
			"  Listen="			mySTRINGIFY(CONFIG_LWIP_MAX_LISTENING_TCP) "\r\n"
			"UDP: Max PCBs="	mySTRINGIFY(CONFIG_LWIP_MAX_UDP_PCBS)
			"  RxMboxSize=" 	mySTRINGIFY(CONFIG_UDP_RECVMBOX_SIZE) "\r\n") ;
	void dbg_lwip_tcp_pcb_show(void) ; dbg_lwip_tcp_pcb_show() ;
	void dbg_lwip_udp_pcb_show(void) ; dbg_lwip_udp_pcb_show() ;
	void dbg_lwip_stats_show(void) ; dbg_lwip_stats_show() ;
}
