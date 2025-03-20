// socketsX.c - Copyright (c) 2014-25 Andre M. Maree / KSS Technologies (Pty) Ltd.

#include "hal_platform.h"
#include "hal_memory.h"
#include "hal_network.h"								// Station IP address
#include "hal_options.h"
#include "errors_events.h"
#include "socketsX.h"
#include "printfx.h"
#include "syslog.h"
#include "systiming.h"
#include "utilitiesX.h"

#ifdef CONFIG_LWIP_STATS
	#include "lwip/stats.h"
#endif

#ifdef CONFIG_LWIP_DEBUG
	#include "lwip/debug.h"
	#include "lwip/stats.h"
#endif

#ifdef	CONFIG_MBEDTLS_DEBUG
	#include "mbedtls/debug.h"
#endif
#include "mbedtls/error.h"

// ############################### BUILD: debug configuration options ##############################

#define	debugFLAG					0xF000
#define	debugRECONNECT				(debugFLAG & 0x0001)
#define	debugTIMING					(debugFLAG_GLOBAL & debugFLAG & 0x1000)
#define	debugTRACK					(debugFLAG_GLOBAL & debugFLAG & 0x2000)
#define	debugPARAM					(debugFLAG_GLOBAL & debugFLAG & 0x4000)
#define	debugRESULT					(debugFLAG_GLOBAL & debugFLAG & 0x8000)

// ######################################## Build macros ###########################################

#define netxBUILD_SPC				0					// en/disable Secure PreConnect support
#define	xnetBUFFER_SIZE 			1024
#define xnetMS_CONNECTED			3500				// was 10000
#define xnetMS_RECONNECT			4000				// avg 3.54sec 
#define xnetTICKS_STEP				10

// ######################################## Local constants ########################################

// ###################################### Local only functions #####################################

// https://stackoverflow.com/questions/47179793/how-to-gracefully-handle-accept-giving-emfile-and-close-the-connection
// https://esp32.io/viewtopic.php?t=12288

/**
 * @brief	Extract error code from errno/h_errno (LWIP/MbedTLS)
 * @param[in]	Remap range of error codes to ENOTCONN or EAGAIN
 * @return	posssibly remapped error code obtained
 */
static int xNetErrorXlat(netx_t * psC) {
	// extract error code from network stack
	psC->error = errno ? errno : h_errno ? h_errno : psC->error;
	if (psC->error) {
		if (psC->error == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			psC->error = ENOTCONN;
		} else if (psC->error == MBEDTLS_ERR_SSL_WANT_READ || psC->error == MBEDTLS_ERR_SSL_WANT_WRITE || psC->error == TRY_AGAIN || psC->error == EWOULDBLOCK) {
			psC->error = EAGAIN;
		}
	}
	return psC->error;
}

/**
 * @brief	process socket (incl MBEDTLS) error codes  using syslog functionality
 * @param	psC socket context
 * @return	adjusted error code
 */
static int xNetSyslog(netx_t * psC, const char * pFname) {
	// Step 1: remap error codes where required
	int iRV = xNetErrorXlat(psC);
	if (iRV == 0)
		return erSUCCESS;
	/* The problem with printfx() or any of the variants are
	 * a) if the channel, STDOUT or STDERR, is redirected to a UDP/TCP connection
	 * b) and the network connection is dropped; then
	 * c) the detection of the socket being closed (or other error)
	 * d) will cause the system to want to send more data to the (closed) socket.....
	 * 
	 * In order to avoid recursing back into syslog in cases of network errors
	 * encountered in the syslog connection, we check on the NoSyslog flag.
	 */
	if (psC->c.NoSyslog)
		goto exit;
	if (iRV != EAGAIN || (iRV == EAGAIN && psC->d.ea)) {	/* if not EAGAIN or EAGAIN but d.ea flag is set */
		char * pcMess;										/* report the error */
		bool fAlloc;
		// Step 2: Map error code to message
		if (INRANGE(mbedERROR_SMALLEST, iRV, mbedERROR_BIGGEST)) {
			pcMess = malloc(xnetBUFFER_SIZE);
			fAlloc = 1;
			mbedtls_strerror(iRV, pcMess, xnetBUFFER_SIZE);
		} else {
			pcMess = (char *) pcStrError(iRV);
			fAlloc = 0;
		}
		// Step 3: Process error code and message
		const char * pHost = (psC->pHost && *psC->pHost) ? psC->pHost : "localhost";
		vSyslog(SL_PRI(SL_FAC_LOGALERT, SL_SEV_ERROR), pFname, "%s:%d %s(%d/x%X)", pHost, ntohs(psC->sa_in.sin_port), pcMess, iRV, iRV);
		if (fAlloc)
			free(pcMess);
	}
exit:
	return erFAILURE;
}

/**
 * @brief		Try to automatically reconnect on unexpected disconnect
 * @param[in]	psCtx pointer to suddenly disconnected context
 * @return		result from xNetOpen()
 */
#if (appRECONNECT > 0)
int xNetReConnect(netx_t * psC) {
	int iRV = erFAILURE;
	if (psC->pHost == NULL)								/* MUST be a client context */
		goto exit;
	/* Filter out qualifying error codes */
	int origErr = xNetErrorXlat(psC);					/* recover error code from network stack */
	if (origErr != ECONNABORTED && origErr != EHOSTUNREACH && origErr != ENOTCONN)
		goto exit;
	// now setup the context for a retry
	IF_CP(debugRECONNECT, "%#-I:%d  sd=%d" strNL, psC->sa_in.sin_addr.s_addr, ntohs(psC->sa_in.sin_port), psC->sd);
	bool bNoSyslog = psC->c.NoSyslog;					/* save the flag */
	psC->c.NoSyslog = 1;								/* disable xNetSyslog output */
	IF_EXEC(debugRECONNECT, psC->d.o=1; psC->d.h=1; psC->d.t=1; );
	while(psC->c.RCcnt < psC->c.RCmax) {
		xNetClose(psC);
		++psC->c.RCcnt;
		if (halEventWaitStatus(flagLX_STA,pdMS_TO_TICKS(xnetMS_RECONNECT))) {
			iRV = xNetOpen(psC);						/* try reconnect with failed context */
			if (iRV > erFAILURE)
				break;
		} else {
			iRV = erTIMEOUT;
		}
	}
	psC->c.NoSyslog = bNoSyslog;
	IF_CP(debugRECONNECT, "  iRV=%d  sd=%d", iRV, psC->sd);
	if (iRV > erFAILURE) {								/* if successful */
		++psC->ReConOK;
	} else {
		xNetClose(psC);
		iRV = psC->error = origErr;						/* restore original error code */
		++psC->ReConErr;
	}
	IF_CP(debugRECONNECT, "  FSM=%d  ic=%d", xMqttState, sClient.isconnected);
	IF_CP(debugRECONNECT, "  iRV=%d  RC=%d/%d  Err=%d" strNL, iRV, psC->c.RCcnt, psC->c.RCmax, psC->ReConErr);
exit:
	return iRV;
}
#endif

// Based on example found at https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client1.c
void vNetMbedDebug(void * ctx, int level, const char * file, int line, const char * str) {
	wprintfx(NULL, "%s Lev=%d '%s' %s:%d" strNL, __FUNCTION__, level, str, level == 4 ? file : strNULL, level == 4 ? line : 0);
}

/**
 * Certificate verification callback for mbed TLS
 * Here we only use it to display information on each cert in the chain
 */
static int xNetMbedVerify(void *data, mbedtls_x509_crt *crt, int depth, u32_t *flags) {
	(void) data;
	wprintfx(NULL, "xNetMbedVerify: Verifying certificate at depth %d:" strNL, depth);
	pc_t pBuf = malloc(xnetBUFFER_SIZE);
	mbedtls_x509_crt_info(pBuf, xnetBUFFER_SIZE, "  ", crt);
	wprintfx(NULL, pBuf);
	if (*flags == 0) {
		wprintfx(NULL, "xNetMbedVerify: No verification issue for this certificate" strNL);
	} else {
		mbedtls_x509_crt_verify_info(pBuf, xnetBUFFER_SIZE-1, "  ! ", *flags);
		wprintfx(NULL, "xNetMbedVerify: %s" strNL, pBuf);
	}
	free(pBuf);
	return 0;
}

/**
 * @brief		initialise a secure connection
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetMbedInit(netx_t * psC) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC->psSec));
	psC->error = 0;
	char * pcName = NULL;
	#if	(CONFIG_MBEDTLS_DEBUG > 0)
		const u8_t XlatSL2TLS[8] = {0, 1, 1, 1, 2, 3, 4, 4};
		u8_t Level = XlatSL2TLS[xSyslogGetConsoleLevel()];
		mbedtls_debug_set_threshold(Level);
		mbedtls_ssl_conf_dbg(&psC->psSec->conf, vNetMbedDebug, psC);
	#endif

	mbedtls_ssl_init(&psC->psSec->ssl);
	mbedtls_x509_crt_init(&psC->psSec->cacert);
	mbedtls_ctr_drbg_init(&psC->psSec->ctr_drbg);
	mbedtls_ssl_config_init(&psC->psSec->conf);
	mbedtls_entropy_init(&psC->psSec->entropy);

	int iRV = mbedtls_ctr_drbg_seed(&psC->psSec->ctr_drbg, mbedtls_entropy_func, &psC->psSec->entropy, NULL, 0);
	if (iRV != 0) {
		pcName = "mbedtls_ctr_drbg_seed";
		goto exit;
	}
	if (psC->psSec->pcCert) {
		IF_myASSERT(debugPARAM, halMemoryANY((void *)psC->psSec->pcCert));
		IF_myASSERT(debugPARAM, psC->psSec->szCert == strlen((const char *)psC->psSec->pcCert) + 1);
		iRV = mbedtls_x509_crt_parse(&psC->psSec->cacert, (pcuc_t) psC->psSec->pcCert, psC->psSec->szCert);
		if (iRV != 0) {
			pcName = "mbedtls_x509_crt_parse";
			goto exit;
		}
	} else {
		#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
		iRV = esp_crt_bundle_attach(&psC->psSec->conf);
		if (iRV != erSUCCESS) {
			pcName = "esp_crt_bundle_attach";
			goto exit;
		}
		#endif
	}

	// mbedtls_ssl_set_hostname();
	iRV = mbedtls_ssl_config_defaults(&psC->psSec->conf,
			psC->pHost ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
			psC->c.type == SOCK_STREAM ? MBEDTLS_SSL_TRANSPORT_STREAM : MBEDTLS_SSL_TRANSPORT_DATAGRAM,
			MBEDTLS_SSL_PRESET_DEFAULT);
	if (iRV != 0) {
		pcName = "mbedtls_ssl_config_defaults";
		goto exit;
	}
	
	if (psC->d.ver)
		mbedtls_ssl_conf_authmode(&psC->psSec->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&psC->psSec->conf, &psC->psSec->cacert, NULL);
	mbedtls_ssl_conf_rng( &psC->psSec->conf, mbedtls_ctr_drbg_random, &psC->psSec->ctr_drbg);
	iRV = mbedtls_ssl_setup(&psC->psSec->ssl, &psC->psSec->conf);
	if (iRV != 0)
		pcName = "mbedtls_ssl_setup";
	else
		mbedtls_net_init(&psC->psSec->server_fd);
exit:
	if (iRV != 0 || pcName)
		return xNetSyslog(psC, pcName);
 	return iRV;
}

/**
 * @brief		deinitialise a secure connection
 * @param[in]	psC - pointer to socket context
 */
static void vNetMbedDeInit(netx_t * psC) {
	mbedtls_net_free(&psC->psSec->server_fd);
	mbedtls_x509_crt_free(&psC->psSec->cacert);
	mbedtls_ssl_free(&psC->psSec->ssl);
	mbedtls_ssl_config_free(&psC->psSec->conf);
	mbedtls_ctr_drbg_free(&psC->psSec->ctr_drbg);
	mbedtls_entropy_free(&psC->psSec->entropy);
}

/**
 * @brief		
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetGetHost(netx_t * psC) {
	// https://sourceware.org/glibc/wiki/NameResolver
	// https://github.com/espressif/esp-idf/issues/5521
	struct addrinfo * psAI;
	struct addrinfo sAI = { 0 };
	sAI.ai_family = psC->sa_in.sin_family;
	sAI.ai_socktype = psC->c.type;
	char portnum[16];
	snprintfx(portnum, sizeof(portnum), "%u", ntohs(psC->sa_in.sin_port));
	int iRV = getaddrinfo(psC->pHost, portnum, &sAI, &psAI);
	if (iRV != 0 || psAI == NULL)
		iRV = xNetSyslog(psC, __FUNCTION__);
	else {
		struct sockaddr_in * sa_in = (struct sockaddr_in *) psAI->ai_addr;
		psC->sa_in.sin_addr.s_addr = sa_in->sin_addr.s_addr;
		if (debugTRACK && psC->d.h)
			xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	}
	if (psAI != NULL)
		freeaddrinfo(psAI);
	return iRV;
}

/**
 * @brief		
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetSocket(netx_t * psC)  {
	int iRV = socket(psC->sa_in.sin_family, psC->c.type, IPPROTO_IP);
	/* Socket() can return any number from 0 upwards as a valid descriptor but since
	 * 0=stdin, 1=stdout & 2=stderr normal descriptor would be greater than 2 ie 3+ */
	if (iRV < 0)
		return xNetSyslog(psC, __FUNCTION__);
	psC->sd = (i16_t) iRV;
	if (psC->psSec)
		psC->psSec->server_fd.fd = iRV;
	if (debugTRACK && psC->d.o)
		xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

#if	(netxBUILD_SPC == 1)
/**
 * @brief		
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetSecurePreConnect(netx_t * psC) { return 0; }
#endif

/**
 * @brief		
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetConnect(netx_t * psC) {
  	int iRV = connect(psC->sd, &psC->sa, sizeof(struct sockaddr_in));
  	if (iRV != 0)
		return xNetSyslog(psC, __FUNCTION__);
	if (debugTRACK && psC->d.h)
		xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

/**
 * @brief		
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetBindListen(netx_t * psC) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC));
	int iRV = 0;
	if (psC->flags & SO_REUSEADDR) {
		int enable = 1;
		iRV = setsockopt(psC->sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	}
	if (iRV == 0) {
		iRV = bind(psC->sd, &psC->sa, sizeof(struct sockaddr_in));
		if (iRV == 0 && psC->c.type == SOCK_STREAM)
			iRV = listen(psC->sd, 10);	// config for listen, max queue backlog of 10
	}
	if (iRV != 0)
		return xNetSyslog(psC, __FUNCTION__);
	if (debugTRACK && psC->d.bl)
		xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

/**
 * @brief		
 * @param[in]	psC - pointer to socket context
 * @return		erSUCCESS or erFAILURE with psC->error set to the code
 */
static int xNetSecurePostConnect(netx_t * psC) {
	u32_t Result;
	int iRV = mbedtls_ssl_set_hostname(&psC->psSec->ssl, psC->pHost);
	if (iRV == 0) {
		// OPTIONAL is not recommended for security but makes inter-operability easier
		mbedtls_ssl_conf_authmode(&psC->psSec->conf, psC->d.ver ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
		// Enable certificate verification, if requested
		if (psC->d.ver)
			iRV = mbedtls_x509_crt_verify(&psC->psSec->cacert, &psC->psSec->cacert, NULL, NULL, &Result, xNetMbedVerify, psC);
		if (iRV == 0)
			mbedtls_ssl_set_bio(&psC->psSec->ssl, &psC->psSec->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	}
	if (iRV != 0)
		return xNetSyslog(psC, __FUNCTION__);
	if (debugTRACK && psC->d.sec)
		xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

// ######################################## Public functions #######################################

EventBits_t xNetWaitLx(TickType_t ttWait) {
	if (ttWait != portMAX_DELAY)
		ttWait = (ttWait <= xnetTICKS_STEP) ? xnetTICKS_STEP : u32Round(ttWait, xnetTICKS_STEP);
	do {
		EventBits_t tEB = halEventGetStatus(flagLX_ANY);
		if ((tEB & flagLX_STA) == flagLX_STA)			/* check if LX STA mode is functional */
			return flagLX_STA;							/* if so, return STA flag */
		if ((tEB & flagLX_SAP) == flagLX_SAP)			/* if not, check if LX SAP is functional */
			return flagLX_SAP;							/* if so, return SAP status flag */
		vTaskDelay(xnetTICKS_STEP);						/* if neither SAP or STA functional */
		if (ttWait != portMAX_DELAY)					/* wait for calculated interval */
			ttWait -= xnetTICKS_STEP;					/* adjust remaining wait period */
	} while (ttWait);									/* and repeat until wait period expired */
	return 0;
}

int	xNetOpen(netx_t * psC) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC));
	EventBits_t ebX = xNetWaitLx(pdMS_TO_TICKS(xnetMS_CONNECTED));
	int	iRV = erFAILURE;
	if (ebX == 0) {										// Neither STA nor SAP level functional, get out...
		psC->error = ENOTCONN;
		psC->ConErr++;
		goto exit;
	}
	psC->ConOK++;
	psC->error = 0;
	// STEP 0: just for mBed TLS Initialize the RNG and the session data
	if (psC->psSec) {
		iRV = xNetMbedInit(psC);
		if (iRV != erSUCCESS) {
			vNetMbedDeInit(psC); 
			goto exit;
		}
	}

	// STEP 1: if connecting as client, resolve the host name & IP address
	if (psC->pHost) {									// Client type connection ?
		if (ebX != flagLX_STA)							// MUST be in STAtion (not SAP) mode
			return erFAILURE;
		iRV = xNetGetHost(psC);
		if (iRV < erSUCCESS)
			goto exit;
	} else {											// Either STA or SAP is OK....
		psC->sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	// STEP 2: open a [secure] socket to the remote
	iRV = xNetSocket(psC);
	if (iRV < erSUCCESS)
		goto exit;
	if (psC->soRcvTO) {									// If 0, leave default, 
		iRV = xNetSetRecvTO(psC, psC->soRcvTO);
		if (iRV < erSUCCESS)
			goto exit;
	}

	// STEP 3: configure the specifics (method, mask & certificate files) of the SSL/TLS component
	#if	(netxBUILD_SPC == 1)
		if (psC->psSec) {
			iRV = xNetSecurePreConnect(psC);
			if (iRV < erSUCCESS)
				goto exit;
		}
	#endif

	// STEP 4: Initialize Client or Server connection
	iRV = (psC->pHost) ? xNetConnect(psC) : xNetBindListen(psC);
	if (iRV < erSUCCESS)
		goto exit;
	// STEP 5: configure the specifics (method, mask & certificate files) of the SSL/TLS component
	if (psC->psSec) {
		iRV = xNetSecurePostConnect(psC);
		if (iRV < erSUCCESS)
			goto exit;
	}
exit:
	if (debugTRACK && psC->d.o)
		xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

int	xNetSetRecvTO(netx_t * psC, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC));
	psC->error = 0;
	if (psC->tOut == mSecTime)
		return erSUCCESS;			// nothing to do, already correct
	psC->tOut = mSecTime;
	int iRV;
	if (mSecTime <= flagXNET_NONBLOCK) {
		iRV = ioctl(psC->sd, FIONBIO, &mSecTime);		// 0 = Disable, 1+ = Enable NonBlocking
	} else {
		struct timeval timeVal;
		timeVal.tv_sec	= mSecTime / MILLIS_IN_SECOND;
		timeVal.tv_usec = (mSecTime * MICROS_IN_MILLISEC ) % MICROS_IN_SECOND;
		iRV = setsockopt(psC->sd, SOL_SOCKET, SO_RCVTIMEO, &timeVal, sizeof(timeVal));
		if (debugTRACK && psC->d.t) {
			socklen_t SockOptLen;
			SockOptLen = sizeof(timeVal);
			getsockopt(psC->sd, SOL_SOCKET, SO_RCVTIMEO, &timeVal, &SockOptLen);
			u32_t tTest = (timeVal.tv_sec * MILLIS_IN_SECOND) + (timeVal.tv_usec / MICROS_IN_MILLISEC);
			myASSERT(tTest == mSecTime);
		}
	}
	if (iRV < 0)
		return xNetSyslog(psC, __FUNCTION__);
	if (debugTRACK && psC->d.t)
		xNetReport(NULL, psC, __FUNCTION__, iRV, 0, 0);
	return iRV;
}

int	xNetAccept(netx_t * psServCtx, netx_t * psClntCtx, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psServCtx) && halMemorySRAM(psClntCtx));
	psServCtx->error = 0;
	// Set host/server RX timeout
	int iRV = xNetSetRecvTO(psServCtx, mSecTime);
	if (iRV < 0)
		return iRV;
	memset(psClntCtx, 0, sizeof(netx_t));		// clear the client context
	socklen_t len = sizeof(struct sockaddr_in);

	// Also need to consider adding a loop to repeat the accept()
	// in case of EAGAIN or POOL_IS_EMPTY errors
	iRV = accept(psServCtx->sd, &psClntCtx->sa, &len);
	if (iRV < 0)
		return xNetSyslog(psServCtx, __FUNCTION__);
	// The server socket had flags set for BIND & LISTEN but the client
	// socket should just be connected and marked same type & flags
	psClntCtx->sd = iRV;
	psClntCtx->c.type = psServCtx->c.type;						// Make same type TCP/UDP/RAW
	psClntCtx->d.val = psServCtx->d.val;					// inherit all flags
	psClntCtx->psSec = psServCtx->psSec;					// TBC same security ??
	if (debugTRACK && psServCtx->d.a) {
		xNetReport(NULL, psServCtx, __FUNCTION__, iRV, 0, 0);
		xNetReport(NULL, psClntCtx, __FUNCTION__, iRV, 0, 0);
	}
	return iRV;
}

int	xNetSelect(netx_t * psC, uint8_t Flag) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC) && Flag < selFLAG_NUM);
	psC->error = 0;
	// If the timeout is too short dont select() just simulate 1 socket ready...
	if (psC->tOut <= configXNET_MIN_TIMEOUT)
		return 1;
	// Need to add code here to accommodate LwIP & OpenSSL for ESP32
	fd_set fdsSet;
	FD_ZERO(&fdsSet);
	FD_SET(psC->sd, &fdsSet);
	struct timeval timeVal;
	timeVal.tv_sec = psC->tOut / MILLIS_IN_SECOND;
	timeVal.tv_usec = (psC->tOut * MICROS_IN_MILLISEC) % MICROS_IN_SECOND;
	// do select based on new timeout
	int iRV = select(psC->sd+1, (Flag == selFLAG_READ)	? &fdsSet : 0,
								(Flag == selFLAG_WRITE) ? &fdsSet : 0,
								(Flag == selFLAG_EXCEPT)? &fdsSet : 0, &timeVal);
	if (iRV < 0)
		return xNetSyslog(psC, __FUNCTION__);
#if 0
	if (FD_ISSET(psC->sd, &fdsSet)) {        /* select() exception set using getsockopt() */
        socklen_t optlen = sizeof(int);
        getsockopt(psC->sd, SOL_SOCKET, SO_ERROR, &psC->error, &optlen);
		return xNetSyslog(psC, __FUNCTION__);
    }
#endif
	if (debugTRACK && psC->d.s) {
		const char * xNetSelectType[4] = { "RD/select", "WR/select", "EX/select", "UNKNOWN/select" };
		xNetReport(NULL, psC, xNetSelectType[Flag & 3], iRV, 0, 0);
	}
	return iRV;
}

int	xNetClose(netx_t * psC) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC));
	if (psC->sd >= 0) {
		if (debugTRACK && psC->d.cl)
			xNetReport(NULL, psC, "xNetClose1", psC->error, 0, 0);
		if (psC->psSec) {
			mbedtls_ssl_close_notify(&psC->psSec->ssl);
			vNetMbedDeInit(psC);
		}
		int iRV = close(psC->sd);
		psC->sd = -1;								// mark as closed
		if (debugTRACK && psC->d.cl)
			xNetReport(NULL, psC, "xNetClose2", iRV, 0, 0);
		return iRV;
	}
	return erSUCCESS;
}

// ##################################### Basic Send/Receive ########################################

int	xNetSend(netx_t * psC, u8_t * pBuf, int xLen) {
	// Check pBuf range against MEM not SRAM to allow COREDUMP from FLASH
	IF_myASSERT(debugPARAM, halMemorySRAM(psC) && halMemoryANY(pBuf) &&  xLen > 0);
	if (xNetWaitLx(pdMS_TO_TICKS(xnetMS_CONNECTED)) == 0) {
		psC->error = ENOTCONN;
		psC->ConErr++;
		return erFAILURE;
	}
	psC->ConOK++;
	psC->error = 0;
	int iRV;
	unsigned char * pTmp = pBuf;
	int xTmp = xLen;
	do {
		if (psC->psSec)			iRV = mbedtls_ssl_write(&psC->psSec->ssl, pTmp, xTmp);
		else if (psC->pHost)	iRV = send(psC->sd, pTmp, xTmp, psC->flags);
		else					iRV = sendto(psC->sd, pTmp, xTmp, psC->flags, &psC->sa, sizeof(psC->sa_in));
		if (iRV == xTmp || iRV <= 0)					/* if all done sending or error */
			break;										/* break out of loop */
		pTmp += iRV;									/* step temp write pointer forward */
		xTmp -= iRV;									/* adjust temp length downwards */
	} while (xTmp > 0);									/* loop until done... */
	if (iRV <= 0)
		return xNetSyslog(psC, __FUNCTION__);
	psC->maxTx = (iRV > psC->maxTx) ? iRV : psC->maxTx;
	if (debugTRACK && psC->d.w)
		xNetReport(NULL, psC, __FUNCTION__, iRV, pBuf, iRV);
	return xLen;										/* was iRV which would be a 0 */
}

int	xNetRecv(netx_t * psC, u8_t * pBuf, int xLen) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC) && halMemorySRAM(pBuf) && (xLen > 0));
	if (xNetWaitLx(pdMS_TO_TICKS(xnetMS_CONNECTED)) == 0) {
		psC->error = ENOTCONN;
		psC->ConErr++;
		return erFAILURE;
	}
	psC->ConOK++;;
	int	iRV;
#if (appRECONNECT > 0)
	do {
		psC->error = 0;
		if (psC->psSec) 		iRV = mbedtls_ssl_read( &psC->psSec->ssl, (unsigned char *) pBuf, xLen);
		else if (psC->pHost)	iRV = recv(psC->sd, pBuf, xLen, psC->flags);
		else {											/* UDP (connection-less) */
			socklen_t i16AddrSize = sizeof(struct sockaddr_in);
			iRV = recvfrom(psC->sd, pBuf, xLen, psC->flags, &psC->sa, &i16AddrSize);
		}
		if (iRV > 0) {									/* successful ? */
			psC->c.RCcnt = 0;
			break;										/* exit loop */
		}
		/* reconnection logic */
		if (psC->c.RCcnt == psC->c.RCmax)				/* reconnect attempts gone ? */
			break;
		iRV = xNetReConnect(psC);						/* try (again) to reconnect */
	} while (iRV >= erSUCCESS);
#else
	psC->error = 0;
	if (psC->psSec)			iRV = mbedtls_ssl_read( &psC->psSec->ssl, (unsigned char *) pBuf, xLen);
	else if (psC->pHost)	iRV = recv(psC->sd, pBuf, xLen, psC->flags);
	else {												/* UDP (connection-less) */
		socklen_t i16AddrSize = sizeof(struct sockaddr_in);
		iRV = recvfrom(psC->sd, pBuf, xLen, psC->flags, &psC->sa, &i16AddrSize);
	}
#endif
	// AMM check for possible loophole with 0 being returned, socket closed !!!
	if (iRV < 0)
		return xNetSyslog(psC, __FUNCTION__);
	psC->maxRx = (iRV > psC->maxRx) ? iRV : psC->maxRx;
	if (debugTRACK && psC->d.r)
		xNetReport(NULL, psC, __FUNCTION__, iRV, pBuf, iRV);
	return iRV;
}

// ##################################### Block Send/Receive ########################################

#if 0
u32_t xNetAdjustTO(netx_t * psC, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC));
	if (mSecTime == (psC->c.trymax * psC->tOut))			// same as previous
		return psC->tOut;
	psC->c.trynow	= 0;
	// must pass thru mSecTime of 0 (blocking) and 1 (non-blocking)
	if (mSecTime <= flagXNET_NONBLOCK) {
		psC->c.trymax	= 1;
 		psC->tOut = mSecTime;
		return mSecTime;
	}
	// adjust the lower limit.
	if (mSecTime < configXNET_MIN_TIMEOUT)
		mSecTime = configXNET_MIN_TIMEOUT;
	if ((mSecTime / configXNET_MIN_TIMEOUT) > configXNET_MAX_RETRIES) {
		psC->c.trymax = configXNET_MAX_RETRIES;
	} else {
		psC->c.trymax = (mSecTime + configXNET_MIN_TIMEOUT - 1) / configXNET_MIN_TIMEOUT;
	}
	psC->tOut = (psC->c.trymax > 0) ? (mSecTime / psC->c.trymax) : mSecTime;
	if (debugTRACK && psC->d.t)
		xNetReport(NULL, psC, __FUNCTION__, mSecTime, 0, 0);
	return psC->tOut;
}

int	xNetSendBlocks(netx_t * psC, u8_t * pBuf, int xLen, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC) && halMemoryANY(pBuf) && xLen > 0);
	int	iRV, xLenDone = 0;
	mSecTime = xNetAdjustTO(psC, mSecTime);
	do {
		iRV = xNetSelect(psC, selFLAG_WRITE);
		if (iRV < 0)
			break;
		if (iRV == 0)
			continue;									// try again
		iRV = xNetSend(psC, pBuf + xLenDone, xLen - xLenDone);
		if (iRV > -1) {
			xLenDone += iRV;
		} else if (psC->error != EAGAIN) {
			break;
		}
	} while((++psC->c.trynow < psC->c.trymax) && (xLenDone < xLen));
	return (xLenDone > 0) ? xLenDone : iRV;
}

int	xNetRecvBlocks(netx_t * psC, u8_t * pBuf, int xLen, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psC) && halMemorySRAM(pBuf) && (xLen > 0));
	mSecTime = xNetAdjustTO(psC, mSecTime);
	xNetSetRecvTO(psC, mSecTime);
	int	iRV, xLenDone = 0;
	do {
		iRV = xNetRecv(psC, pBuf + xLenDone, xLen - xLenDone);
		if (iRV > -1) {
			xLenDone +=	iRV;
		} else if (psC->error != EAGAIN) {
			break;
		}
 	} while ((++psC->c.trynow < psC->c.trymax) && (xLenDone < xLen));
	return (xLenDone > 0) ? xLenDone : iRV;
}
#endif

// ###################################### uBuf Send/Receive ########################################

#if 0
int	xNetSendUBuf(netx_t * psC, ubuf_t * psBuf, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psBuf) && halMemorySRAM(psBuf->pBuf) && (psBuf->Size > 0));
	int	iRV = xNetSendBlocks(psC, psBuf->pBuf + psBuf->IdxRD, psBuf->Used, mSecTime);
	if (iRV > erSUCCESS) {
		psBuf->IdxRD += iRV;
		psBuf->Used -= iRV;
	}
	return iRV;
}

int	xNetRecvUBuf(netx_t * psC, ubuf_t * psBuf, u32_t mSecTime) {
	IF_myASSERT(debugPARAM, halMemorySRAM(psBuf) && halMemorySRAM(psBuf->pBuf) && (psBuf->Size > 0));
	int iRV = xNetRecvBlocks(psC, psBuf->pBuf + psBuf->IdxWR, psBuf->Used, mSecTime);
	if (iRV > erSUCCESS) {
		psBuf->IdxWR += iRV;
		psBuf->Used += iRV;
	}
	return iRV;
}
#endif

// ###################################### Socket Reporting #########################################

int xNetCloseDuplicates(u16_t port) {
	int iRV, Count = 0;
	for (int sock = LWIP_SOCKET_OFFSET; sock < (LWIP_SOCKET_OFFSET+CONFIG_LWIP_MAX_SOCKETS); ++sock) {
	    struct sockaddr_in addr;
	    socklen_t addr_size = sizeof(struct sockaddr_in);
	    iRV = getpeername(sock, (struct sockaddr *)&addr, &addr_size);
		if (iRV == -1)
			continue;
	    if ((iRV == 0) && (addr.sin_port == port)) {
			close(sock);
			++Count;
			SL_WARN("Closing sd=%d -> %-#I:%d", sock, addr.sin_addr.s_addr, htons(addr.sin_port));
		} else {
			SL_NOT("Ignoring sd=%d -> %-#I:%d (iRV=%d)", sock, addr.sin_addr.s_addr, htons(addr.sin_port), iRV);
		}	// (res == 0)
	}		// (for i = 0)
	return Count;
}

int xNetReport(report_t * psR, netx_t * psC, const char * pFname, int Code, void * pBuf, int xLen) {
	u32_t IPaddr = psC->sa_in.sin_addr.s_addr ? psC->sa_in.sin_addr.s_addr : nvsWifi.ipSTA;
	const char * pHost = (psC->pHost && *psC->pHost) ? psC->pHost : (IPaddr == nvsWifi.ipSTA) ? "localhost" : "unknown";
	int iRV = 0;
	if (psR == NULL)
		iRV += wprintfx(psR, "%!.3R ", halTIMER_ReadRunTime());
	iRV += wprintfx(psR, "%C%-s%C\t%s %s://%-I:%d (%s) sd=%d %s=%d ",
			xpfCOL(colourFG_CYAN,0), pFname, xpfCOL(attrRESET,0),
			(psC->sa_in.sin_family == AF_INET) ? "ip4" : (psC->sa_in.sin_family == AF_INET6) ? "ip6" : "ip?",
			(psC->c.type == SOCK_DGRAM) ? "udp" : (psC->c.type == SOCK_STREAM) ? "tcp" : "raw",
			ntohl(IPaddr), ntohs(psC->sa_in.sin_port), pHost, psC->sd,
			(Code < 0) ? pcStrError(Code) : "iRV", Code);
#if (appRECONNECT > 0)
	iRV += wprintfx(psR, "Try=%hhu/%hhu TO=%hu%s D=0x%02X F=0x%X E=%d  [Cerr=%d vs %d]  [RCerr=%d vs %d]" strNL,
			psC->c.trynow, psC->c.trymax, psC->tOut, (psC->tOut == 0) ? "/BLK" : (psC->tOut == 1) ? "/NB" : "mS",
			psC->d.val, psC->flags, psC->error, psC->ConErr, psC->ConOK, psC->ReConErr, psC->ReConOK);
#else
	iRV += wprintfx(psR, "Try=%hhu/%hhu TO=%hu%s D=0x%02X F=0x%X E=%d  [Cerr=%d vs %d]" strNL,
			psC->c.trynow, psC->c.trymax, psC->tOut, (psC->tOut == 0) ? "/BLK" : (psC->tOut == 1) ? "/NB" : "mS",
			psC->d.val, psC->flags, psC->error, psC->ConErr, psC->ConOK);
#endif
	if (psC->d.d && pBuf && xLen)
		iRV += wprintfx(psR, "%!'+hhY" strNL, xLen, pBuf);
	if (fmTST(aNL))
		iRV += wprintfx(psR, strNL);
	return iRV;
}

/**
 * @brief 
 * @param p 
 * @param name
*/
void __wrap_stats_display_proto(struct stats_proto *p, const char *name) {
	#define hdrPROTO "%s\txmit\trecv\tfw\tdrop\tchkerr\tlenerr\tmemerr\trterr\tproterr\topterr\terr\tcachehit" strNL
	wprintfx(NULL, hdrPROTO, name);
	wprintfx(NULL, "\t%d\t%d\t%d\t%d\t%d\t%d", p->xmit, p->recv, p->fw, p->drop, p->chkerr, p->lenerr);
	wprintfx(NULL, "\t%d\t%d\t%d\t%d\t%d\t%d" strNL, p->memerr, p->rterr, p->proterr, p->opterr, p->err, p->cachehit);
}

void __wrap_stats_display_igmp(struct stats_igmp *p, const char *name) {
	#define hdrIGMP "%s\txmit\trecv\tdrop\tchkerr\tlenerr\tmemerr\tproterr\tRXv1\tRXgrp\tRXgen\tRXrprt\tTXjoin\tTXleave\tTXrprt" strNL
	wprintfx(NULL, hdrIGMP, name);
	wprintfx(NULL, "\t%d\t%d\t%d\t%d\t%d\t%d\t%d", p->xmit, p->recv, p->drop, p->chkerr, p->lenerr, p->memerr, p->proterr);
	wprintfx(NULL, "\t%d\t%d\t%d\t%d\t%d\t%d\t%d" strNL, p->rx_v1, p->rx_group, p->rx_general, p->rx_report, p->tx_join, p->tx_leave, p->tx_report);
}

void __wrap_stats_display_sys(struct stats_sys *p) {
	wprintfx(NULL, "SYS\tSEMused\tSEMmax\tSEMerr\tMUXused\tMUXmax\tMUXerr\tMBXused\tMBXmax\tMBXerr" strNL "\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d" strNL,
		p->sem.used, p->sem.max, p->sem.err, p->mutex.used, p->mutex.max, p->mutex.err, p->mbox.used, p->mbox.max, p->mbox.err);
}

void xNetReportStats(report_t * psR) {
//	for (int sock = LWIP_SOCKET_OFFSET; sock < (LWIP_SOCKET_OFFSET + CONFIG_LWIP_MAX_SOCKETS); ++sock) {
	for (int sock = 0; sock < (LWIP_SOCKET_OFFSET + CONFIG_LWIP_MAX_SOCKETS); ++sock) {
		struct sockaddr_in addr;
	    socklen_t addr_size = sizeof(struct sockaddr_in);
	    int res = getpeername(sock, (struct sockaddr *)&addr, &addr_size);
	    if (res == 0)
			wprintfx(psR, "sock: %d -- addr: %-#I:%d" strNL, sock, addr.sin_addr.s_addr, htons(addr.sin_port));
	}
	void dbg_lwip_stats_show(void); dbg_lwip_stats_show();
	#if 0
	void dbg_lwip_tcp_pcb_show(void); dbg_lwip_tcp_pcb_show();
	void dbg_lwip_udp_pcb_show(void); dbg_lwip_udp_pcb_show();
	wprintfx(psR,
		#if	(CONFIG_ESP32_WIFI_STATIC_TX_BUFFER == 1)
			"Wifi: Static Tx="	toSTR(CONFIG_ESP32_WIFI_STATIC_TX_BUFFER_NUM)
			"  Rx="  			toSTR(CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM)
			"  Dynamic Rx="		toSTR(CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM) strNL
		#endif
		#if (CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER == 1)
			"Wifi: Dynamic Tx="	toSTR(CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM)
			"  Rx="				toSTR(CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM)
			"  Static Rx="  	toSTR(CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM) strNL
		#endif
			"LWIP: MaxSock="	toSTR(CONFIG_LWIP_MAX_SOCKETS)
			"  RcvMboxSize="	toSTR(CONFIG_TCPIP_RECVMBOX_SIZE) strNL
			"TCP: Max Act="		toSTR(CONFIG_LWIP_MAX_ACTIVE_TCP)
			"  Listen="			toSTR(CONFIG_LWIP_MAX_LISTENING_TCP) strNL
			"UDP: Max PCBs="	toSTR(CONFIG_LWIP_MAX_UDP_PCBS)
			"  RxMboxSize=" 	toSTR(CONFIG_UDP_RECVMBOX_SIZE) strNL);
	#endif
}
