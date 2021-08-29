/*
    This program is RSPAMD agent for use with
    exim (http://www.exim.org) MTA by its local_scan feature.

    To enable exim local scan please copy this file to exim source tree
    Local/local_scan.c, edit Local/Makefile to add

    LOCAL_SCAN_SOURCE=Local/local_scan.c
    LOCAL_SCAN_HAS_OPTIONS=yes

    and compile exim.

    Comment out RSPAM_UNIXSOCKET definition below if you have remote RSPAMD
    daemon

    AND

    use Exim parameters daemonIP and daemonPort to configure remote
    RSPAMD daemon.

    For exim compilation with local scan feature details please visit
    http://www.exim.org/exim-html-4.50/doc/html/spec_toc.html#TOC333

    For RSPAMD details please visit
    http://rspamd.sourceforge.net
*/

/* Comment out the row below to use socket type AF_INET
   to connect RSPAMD daemon */
//#define RSPAM_UNIXSOCKET

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "local_scan.h"

extern uschar *sender_helo_name;
extern int     message_size;

#define READ_FAIL(x)    ((x) < 0)
#define RSPAMD_FAILURE_HDR 	"X-Spam-Flag"
#define RSPAMD_SCORE_HDR 	"X-Spam-Status"
#define REJECT_ON_ERROR 0

static int _OK = 0;
static int ERR_WRITE = 53;
static int ERR_READ  = 54;
static int MAX_FAILS_C = 256;
static int MAX_PATH  = 256;
static int MAX_SIZE_FILE = 64*1024;

static uschar *daemonIP = US"127.0.0.1";
static int daemonPort = 11333;
static uschar *temp_dir = US"/var/tmp";
static uschar *socket_name = US"/var/run/rspamd.sock";
static int strange = 0;

optionlist local_scan_options[] =
{
    {"rspam_ip", opt_stringptr, &daemonIP},
    {"rspam_port", opt_int, &daemonPort},
    {"rspam_tmp", opt_stringptr, &temp_dir},
    {"rspam_sock", opt_stringptr, &socket_name},

};

int local_scan_options_count = sizeof (local_scan_options) / sizeof (optionlist);

typedef int socket_t;
static socket_t sock = -1;

int iFdInp;
struct sockaddr_un	ssun;
struct sockaddr_in	ssin;

static int mOpenTmp (char *pszDir, char *pszPrefix, char *pszPath)
{
    int iLen;
    int iFd = -1;
    char *pszSep = "";

    iLen = (int)strlen(pszDir);
    if (iLen > MAX_PATH)
        return -1;

    if (pszDir[iLen - 1] != '/')
        pszSep = "/";

    sprintf (pszPath, "%s%s%sXXXXXX", pszDir, pszSep, pszPrefix);
    iFd = mkstemp (pszPath);

    if (iFd < 0)
        log_write (0, LOG_MAIN, "rspam-exim: Temp file create error %d", errno);

    return iFd;
}

static int ReadFd (int iFdMsg, int fd)
{
    char psMsg [MAX_SIZE_FILE]; /* max size SO can swallow */
    int iLen, result = _OK;

    if ((iLen = read (fd, psMsg, sizeof (psMsg))) > 0)
    {
        if (write (iFdMsg, psMsg, (unsigned int) iLen) != iLen)
            result = ERR_WRITE;
    }
    else
        result = ERR_READ;

    close (iFdMsg);

    return result;
}


void CleanupInp (char *sName)
{
    if (sName) unlink (sName);

    close (iFdInp);
    return;
}


int FakeSMTPCommand (socket_t sock,
                     char *command,
                     char *value,
                     char *sName,
                     int Cleanup,
            	     int wa)
{
    char sCommand[1024];
    char answ [3];
    int  Len;

    sprintf (sCommand, "%s %s\r\n", command, value);

    if (send (sock, sCommand, strlen (sCommand), 0) != (int) strlen (sCommand))
    {
        log_write (0, LOG_MAIN, "rspam-exim: socket sending '%s' error %d", sCommand, errno);
        if (Cleanup)
            CleanupInp (sName);
        return ERR_WRITE;
    }

    if(wa) {
	memset (answ, '\0', sizeof (answ));
        Len = read (sock, answ, sizeof (answ));
	if (READ_FAIL (Len))
	{
    	    log_write (0, LOG_MAIN, "rspam-exim: read() error %d, len=%d", errno, Len);
    	    if (Cleanup)
        	CleanupInp (sName);
    	    return ERR_WRITE;
	}

	if (strncmp (answ, "OK", 2) != 0)
	{
    	    log_write (0, LOG_MAIN, "rspam-exim: server did not confirm, answ=%s", answ);
    	    if (Cleanup)
        	CleanupInp (sName);
    	    return ERR_WRITE;	/* Cannot read message error code */
	}
    }

    return OK;
}


static int written (socket_t fd, const char *vptr, int n)
{
    size_t nleft;
    int nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nwritten = send (fd, ptr, nleft, 0)) <= 0)
        {
            if (errno == EINTR)
                nwritten = 0;
            else
                return (-1);
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return (n);
}


static int SendEnvelope (char *sFile)
{
    int i;
    char str [256], *rh;
    void *psBuf;
    int fd, bytesRead;

    if(message_size > MAX_SIZE_FILE) {
	log_write (0, LOG_MAIN, "rspam-exim: file %s is great %d bytes", sFile, MAX_SIZE_FILE);
        return ERR_WRITE;
    }

    /* send greeting */
//    if(FakeSMTPCommand(sock, "PROCESS", "RSPAMC/1.0", sFile, 1, 0) != _OK)
//        return ERR_WRITE;
    if(FakeSMTPCommand(sock, "SYMBOLS", "RSPAMC/1.1", sFile, 1, 0) != _OK)
//    if(FakeSMTPCommand(sock, "CHECK", "RSPAMC/1.0", sFile, 1, 0) != _OK)
        return ERR_WRITE;



    /* sender IP */
    if (FakeSMTPCommand (sock, "IP:", sender_host_address, sFile, 1, 0) != _OK)
        return ERR_WRITE;

    /* mail from */
    if (FakeSMTPCommand (sock, "From:",
                         strlen (sender_address) == 0 ?  "MAILER-DAEMON" : (char*) sender_address, sFile, 1, 0) != _OK)
        return ERR_WRITE;

    /* send helo */
    if (FakeSMTPCommand (sock, "Helo:", sender_helo_name, sFile, 1, 0) != _OK)
        return ERR_WRITE;

    /* send helo */
    sprintf(str, "%d", message_size);
    if (FakeSMTPCommand (sock, "Content-Length:", str, sFile, 1, 0) != _OK)
        return ERR_WRITE;

    /* number of recipient */
    sprintf(str, "%d", recipients_count);
    if (FakeSMTPCommand (sock, "Recipient-Number:", str, sFile, 1, 0) != _OK)
        return ERR_WRITE;

    /* envelope rcpto */
    for (i = 0; i < recipients_count; i ++)
    {
        if (FakeSMTPCommand (sock, "Rcpt:", recipients_list[i].address, sFile, 1, 0) != _OK)
            return ERR_WRITE;
    }

    psBuf = store_get (MAX_SIZE_FILE);

    fd = open (sFile, O_RDONLY);
    if (fd > 0)
    {
        bytesRead = read (fd, psBuf, MAX_SIZE_FILE);
        close (fd);

        if (FakeSMTPCommand (sock, "\r\n", "", sFile, 1, 0) != _OK)
            return ERR_WRITE;

        if (written (sock, psBuf, bytesRead) != bytesRead)
            return ERR_WRITE;
    }
    else
    {
        log_write (0, LOG_MAIN, "rspam-exim: file %s open error %d", sFile, errno);
        return ERR_WRITE;
    }

    return _OK;
}


int GetFiles (char *pInpFile, int local_scan_fd)
{
    /*
        Returns OK if no errors, else error code.
        On successful return, pEnvFile points to Envelope file name and
        pInpFile points to Message filename
    */
    int iStatus;
    struct header_line *h_line;

    iFdInp = mOpenTmp ((char *)temp_dir, "sp-inp", pInpFile);
    if (iFdInp == -1)
    {
        return ERR_WRITE;
    }

    /* Emit headers */
    h_line = header_list;
    while (h_line != NULL)
    {
        if (h_line->type == '*') /* internal header */
        {
            h_line = h_line->next;
            continue;
        }

        if (write (iFdInp, h_line->text, strlen (h_line->text)) != strlen (h_line->text))
        {
            CleanupInp ("");
            return ERR_WRITE;
        }
        h_line = h_line->next;
    }
    if (write (iFdInp, "\n", 1) != 1)
    {
        CleanupInp ("");
        return ERR_WRITE;
    }

    /* Read msg */
    if ((iStatus = ReadFd (iFdInp, local_scan_fd)))
    {
        return iStatus;
    }

    /* Return success */
    return _OK;
}


int GetAndTransferMessage (int fd, char *sFile)
{
    char answ [4];
    int	 iStatus;
    int	 Len, ccnt;
    int	 test;

    iStatus = GetFiles ((char *)sFile, fd);

    if (iStatus != _OK)
    {
        log_write (0, LOG_MAIN, "rspam-exim: Error %d getting message", iStatus);
        close (sock);
        return iStatus;
    }

    for (ccnt = 0; ccnt <= MAX_FAILS_C; ccnt ++)
    {
#ifdef RSPAM_UNIXSOCKET
        test = connect (sock, (struct sockaddr *) &ssun, sizeof (struct sockaddr_un)) < 0;
#else
        test = connect (sock, (struct sockaddr *) &ssin, sizeof (struct sockaddr_in)) < 0;
#endif
        if (test)
        {
            if (ccnt < MAX_FAILS_C)
                usleep (1000);
            else
            {
                close (sock);
#ifdef RSPAM_UNIXSOCKET
                log_write (0, LOG_MAIN, "rspam-exim: socket connect to %s failed", (char *)socket_name);
#else
                log_write (0, LOG_MAIN, "rspam-exim: socket connect to %s:%u failed", daemonIP, daemonPort);
#endif
		return REJECT_ON_ERROR ? LOCAL_SCAN_TEMPREJECT:LOCAL_SCAN_ACCEPT;
            }
        }
        else
            break;
    }

    iStatus = SendEnvelope (sFile);
    if (iStatus != _OK)
    {
        log_write (0, LOG_MAIN, "rspam-exim: error %d sending envelope data", iStatus);
        close (sock);
        return iStatus;
    }

    /* fprintf (stderr, "Transmit OK\n"); */
    return _OK;
}

void header_del (uschar *hdr)
{
    struct header_line *h_line;

    h_line = header_list;
    while (h_line != NULL)
    {
        if (h_line->type == '*') /* internal header */
        {
            h_line = h_line->next;
            continue;
        }

        if (strncasecmp (h_line->text, hdr, strlen(hdr)) == 0)
        {
            h_line->type = '*';
            while (h_line->next &&
                   (*h_line->next->text == ' ' || *h_line->next->text == '\t'))
            {
                h_line = h_line->next;
                h_line->type = '*';
            }
        }
        h_line = h_line->next;
    }
}

void AlterSubject (char *label)
{
    struct header_line *h_line;
    char *subject, *strP;

    h_line = header_list;

    while (h_line != NULL)
    {
        if (h_line->type == '*') /* internal header */
        {
            h_line = h_line->next;
            continue;
        }

        if (strncasecmp (h_line->text, "Subject", strlen("Subject")) == 0)
        {
            strP = strchr (h_line->text, ':');
            subject = string_copy (++strP);
            while (h_line->next &&
                   (*h_line->next->text == ' ' || *h_line->next->text == '\t'))
            {
                h_line = h_line->next;
		subject = string_sprintf ("%s\n%s", subject, h_line->text);
            }
            header_del (US "Subject");
            break;
        }

        h_line = h_line->next;
    }
    header_add (' ', "Subject: %s%s", label, subject ? subject : "");
}

int
io_read(int fd, char *buf, size_t size)
{
    int nfd, next = 0, rcount = 15;
    size_t len = 0;
    fd_set fds;
    struct timeval tv;

    if((sock < 0) || (buf == NULL))
	return -1;

    FD_ZERO(&fds);

repeat_read:

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_SET(fd, &fds);

//    log_write(0, LOG_MAIN, "rspam-exim: before select");

    if((nfd=select(fd+1, &fds, NULL, NULL, &tv)) == -1) {
//	log_write(0, LOG_MAIN, "rspam-exim: select error: %s", strerror(errno));
	return -1;
    }

//    log_write(0, LOG_MAIN, "rspam-exim: select return %d fds, rcount %d, next %d", nfd, rcount, next);

    if((nfd>0) && (FD_ISSET(fd, &fds))) {
	next += len = read(fd, buf + next, size - next);
//        log_write(0, LOG_MAIN, "rspam-exim: read %d bytes", len);
//	if(next<size)
//	    goto repeat_read;
    }
    rcount--;
    if(rcount>0)
	goto repeat_read;

    return next;
}

int WaitForScanResult (uschar **resStr)
{
    int Len, i;
    int rej = 0, result = LOCAL_SCAN_ACCEPT, answer_size, spm = 0, code = 0, ns = 0, smb = 0, urf = 0;
    char *strP, *tok, *tmp;
    char *hdr = NULL, *hdrv = NULL, *spmStr = NULL, *symbols=NULL, *urls=NULL;
    char answ [4096], state[6], metric[128], back;
    float sm=0, smd=0, smr=0;

    memset (answ, '\0', sizeof (answ));
//    log_write(0, LOG_MAIN, "rspam-exim: before read from %d", sock);
//    Len = read (sock, answ, sizeof (answ) - 1);
    Len = io_read(sock, answ, sizeof (answ) - 1);
    log_write(0, LOG_MAIN, "rspam-exim: read %d bytes", Len);

    if (strncmp (answ, "RSPAMD/1.1 ", 11) == 0)
    {
        strP = (char *)answ;
        for (tok = strtok (strP, "\n"); tok; tok = strtok (NULL, "\n"))
        {
//            log_write(0, LOG_MAIN, "rspam-exim: process line '%s'", tok);

            if (strncmp (tok, "RSPAMD/1.1 ", 11) == 0)
            {
                if (sscanf (tok, "%*s %d %s", &code, state) == 2)
                {
//                    log_write(0, LOG_MAIN, "rspam-exim: daemon reports code %d %s", code, state);
            	    if ((code == 0) && (strcmp(state,"OK")==0)) {
                	    header_del ((uschar *) RSPAMD_FAILURE_HDR);
                	    header_add (' ', "%s: SKIP\n", RSPAMD_FAILURE_HDR);
                	    strange = 1;
            		    continue;
            	    } else {
                	    header_del ((uschar *) RSPAMD_FAILURE_HDR);
                	    header_add (' ', "%s: SKIP\n", RSPAMD_FAILURE_HDR);
                            log_write(0, LOG_MAIN, "rspam-exim: daemon reports code %d %s", code, state);
                    	    return LOCAL_SCAN_ACCEPT;
            	    }
                }
                continue;
            }

	    /* Metric: default; False; 6.00 / 10.00 */
            /* Process metric */
            if (strncmp (tok, "Metric:", 7) == 0)
            {
        	tmp = tok;
        	while(	(*tmp++) &&
        		((*tmp!='\r') || (*tmp!='\n'))
        		);
        	back = *tmp;
        	*tmp = '\0';
                if (sscanf (tok, "Metric: %[^';']; %[^';']; %f / %f / %f", metric, state, &sm, &smd, &smr) == 5) {
            		log_write(0, LOG_MAIN, "rspam-exim: metric: %s; %s; %f / %f / %f", metric, state, sm, smd, smr );
            		if(strcasecmp(state,"true")==0) {
                		header_del ((uschar *) RSPAMD_FAILURE_HDR);
                		header_add (' ', "%s: %s\n", RSPAMD_FAILURE_HDR, "Yes");
            		} else if(strcasecmp(state,"skip")==0) {
                		header_del ((uschar *) RSPAMD_FAILURE_HDR);
                		header_add (' ', "%s: %s\n", RSPAMD_FAILURE_HDR, "Skip");
            		} else {
                		header_del ((uschar *) RSPAMD_FAILURE_HDR);
                		header_add (' ', "%s: %s\n", RSPAMD_FAILURE_HDR, "No");
            		}
                	header_del ((uschar *) RSPAMD_SCORE_HDR);
                	header_add (' ', "%s: %.2f / %.2f / %.2f\n", RSPAMD_SCORE_HDR, sm, smd, smr);
                	strange = 0;
        	}
		*tmp = back;
                continue;
            }

            if (strncmp (tok, "Symbol:", 7) == 0)
            {
        	tmp = tok;
        	while(	(*tmp++) &&
        		((*tmp!='\r') || (*tmp!='\n'))
        		);
        	back = *tmp;
        	*tmp = '\0';
		if(smb>0) {
		    tok += 7;
		    while(*tok && isspace(*tok)) tok++;
		    if(strlen(tok)>0) {
			symbols = string_sprintf ("%s\n %s", symbols, tok);
		    }
		} else {
		    tok += 7;
		    while(*tok && isspace(*tok)) tok++;
		    symbols = string_copy (tok);
		}
        	smb = 1;
		*tmp = back;
        	continue;
	    }

            if (strncmp (tok, "Urls:", 5) == 0)
            {
        	tmp = tok;
        	while(	(*tmp++) &&
        		((*tmp!='\r') || (*tmp!='\n'))
        		);
        	back = *tmp;
        	*tmp = '\0';
		if(urf>0) {
		    tok[0] = tok[1]= tok[2]= tok[3]= tok[4] = ' ';
		    urls = string_sprintf ("%s\n%s", urls, tok+3);
		} else {
		    tok += 5;
		    while(*tok && isspace(*tok)) tok++;
		    urls = string_copy (tok);
		}
        	urf = 1;
		*tmp = back;
        	continue;
	    }
        }


        /* do not forget the symbols */
        if (symbols != NULL && strlen(symbols))
        {
    	    i = 0;
    	    tmp = tok = string_copy(symbols);
            header_del ((uschar *) "X-Spam-Sybmols");
            header_add (' ', "%s: %s\n", "X-Spam-Sybmols", symbols);
            while(*tmp!='\0') {
        	if(*tmp == '\r')
			*tmp = ' ';
        	if(*tmp == '\n')
        		*tmp = ',';
        	tmp++;
            }
	    *tmp = '\0';
            log_write(0, LOG_MAIN, "rspam-exim: symbols: %s", tok);
        }

        /* do not forget the urls */
        if (urls != NULL && strlen(urls))
        {
            log_write(0, LOG_MAIN, "rspam-exim: urls: %s", urls);
            header_del ((uschar *) "X-Spam-Urls");
            header_add (' ', "%s: %s\n", "X-Spam-Urls", urls);
        }

        log_write (0, LOG_MAIN, "rspam-exim: For message from %s will return %s, mailfrom: <%s>, rcpto: <%s>", sender_host_address, rej == 2 ? "DISCARD" : rej == 1 ? "REJECT" : "ACCEPT", sender_address, recipients_list[0].address);

    }
    else
    {
        result = LOCAL_SCAN_ACCEPT;
        log_write(0, LOG_MAIN, "rspam-exim: wrong signature in answer: %s", answ);
    }

    if((sm>0) && (smr>0) && (sm>=smr)) {
	result = LOCAL_SCAN_REJECT;
    }
    return result;
}


int
local_scan(int fd, uschar **return_text)
{
    int 	retval = _OK;
    char sFileInp [MAX_PATH + 81];

    /* Socket stuff */

    strange = 0;
#ifdef RSPAM_UNIXSOCKET
    if ((sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        log_write(0, LOG_MAIN, "rspam-exim: socket() failed");
        exit (EXIT_FAILURE);
    }
    memset (&ssun, '\0', sizeof (struct sockaddr_un));
    ssun.sun_family = AF_UNIX;
    if (sizeof (socket_name) > sizeof (ssun.sun_path))
    {
        close (sock);
        log_write(0, LOG_MAIN, "rspam-exim: UNIX socket name %s too long", socket_name);
        exit (EXIT_FAILURE);
    }
    strcpy (ssun.sun_path, socket_name);
#else
    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
        log_write(0, LOG_MAIN, "rspam-exim: socket() failed");
        exit (EXIT_FAILURE);
    }
    memset (&ssin, '\0', sizeof (struct sockaddr_in));
    ssin.sin_family = AF_INET;
    ssin.sin_addr.s_addr = inet_addr (daemonIP);
    ssin.sin_port = htons (daemonPort);
#endif

    if (GetAndTransferMessage (fd, (char *)sFileInp) != _OK)
    {
        close (sock);
        unlink (sFileInp);
        SPOOL_DATA_START_OFFSET;
	return REJECT_ON_ERROR ? LOCAL_SCAN_TEMPREJECT:LOCAL_SCAN_ACCEPT;
    }

    retval = WaitForScanResult (return_text);

    if(!strange)
	unlink (sFileInp);
    close (sock);
    SPOOL_DATA_START_OFFSET;

    return retval;
}

/* End of local_scan.c */
