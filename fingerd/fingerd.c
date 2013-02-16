/*
 * Copyright (c) 1983 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

char copyright[] =
  "@(#) Copyright (c) 1983 The Regents of the University of California.\n"
  "All rights reserved.\n";

/* 
 * from: @(#)fingerd.c	5.6 (Berkeley) 6/1/90"
 */
char rcsid[] = 
  "$Id: fingerd.c,v 1.23 1999/12/12 18:46:28 dholland Exp $";

#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "pathnames.h"
#include "../version.h"

#define	ENTRIES	50
#define WS " \t\r\n"

/* These are used in this order if the finger path compiled in doesn't work. */
#define _ALT_PATH_FINGER_1 "/usr/local/bin/finger"
#define _ALT_PATH_FINGER_2 "/usr/ucb/finger"
#define _ALT_PATH_FINGER_3 "/usr/bin/finger"

static
void
fatal(const char *msg, int use_errno, int tolog, int toclient)
{
	const char *err = "";
	const char *sep = "";
	if (use_errno) {
		err = strerror(errno);
		sep = ": ";
	}
	if (tolog) syslog(LOG_ERR, "%s%s%s\n", msg, sep, err);
	if (toclient) fprintf(stderr, "fingerd: %s%s%s\r\n", msg, sep, err);
	else fprintf(stderr, "fingerd: Internal error\r\n");
	exit(1);
}

static
void
timeout(int sig)
{
	(void)sig;
	errno = ETIMEDOUT;
	fatal("Input timeout", 0, 1, 1);
}


int
main(int argc, char *argv[])
{
#if 0
	FILE *fp;
	int p[2], ch;
	pid_t pid;
#endif
	int ca;
	const char *av[ENTRIES + 1];
	const char **avy;
	char *const *avx;
	char line[1024];
	int welcome = 0, heavylogging = 0, nouserlist = 0;
	int patience = 60, forwarding = 0;
	int k, nusers;
	char *s, *t;
	const char *fingerpath = NULL;
	struct sockaddr_in sn;
	socklen_t sval = sizeof(sn);


	if (getpeername(0, (struct sockaddr *) &sn, &sval) < 0) {
		fatal("getpeername", 1, 0, 1);
	}

	openlog("fingerd", LOG_PID, LOG_DAEMON);

	if (!getuid() || !geteuid()) {
		struct passwd *pwd = getpwnam("nobody");
		if (pwd) {
			initgroups(pwd->pw_name, pwd->pw_gid);
			setgid(pwd->pw_gid);
			setuid(pwd->pw_uid);
		}
		seteuid(0);   /* this should fail */
		if (!getuid() || !geteuid()) {
			fatal("setuid: couldn't drop root", 0, 1, 0);
		}
	}
	/*endpwent();  -- is it safe to put this here? */

	opterr = 0;
	while ((ca = getopt(argc, argv, "wlL:p:uft:h?")) != EOF) {
		switch(ca) {
		  case 'w':
			welcome = 1;
			break;
		  case 'l':
		        heavylogging = 1;
			break;
		  case 'L': 
		  case 'p':
		        fingerpath = optarg;
			break;
		  case 'u':
		        nouserlist = 1;
			break;
		  case 'f':
		        forwarding = 1;
			break;
		  case 't':
		        patience = atoi(optarg);
			break;
		  case '?':
		  case 'h':
		  default:
			syslog(LOG_ERR, "usage: fingerd [-wulf]"
					"[-pL /path/finger] [-t timeout]");
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * Hang up after a while so people can't DoS by leaving lots of
	 * open sockets about.
	 */
	if (patience != 0) {
		signal(SIGALRM, timeout);
		alarm(patience);
	}
	if (!fgets(line, sizeof(line), stdin)) {
		fatal("Client hung up - probable port-scan", 0, 1, 0);
	}

	if (welcome) {
		char buf[256];
		struct hostent *hp;
		struct utsname utsname;

		uname(&utsname);
		gethostname(buf, sizeof(buf));
		if ((hp = gethostbyname(buf))) {
			/* paranoia: dns spoofing? */
			strncpy(buf, hp->h_name, sizeof(buf));
			buf[sizeof(buf)-1] = 0;
		}
		printf("\r\nWelcome to %s version %s at %s !\r\n\n",
				utsname.sysname, utsname.release, buf);
		fflush(stdout);
		switch (fork()) {
		 case -1: /* fork failed, oh well */
		     break;
		 case 0: /* child */
		     execl(_PATH_UPTIME, _PATH_UPTIME, NULL);
		     _exit(1);
		 default: /* parent */
		     wait(NULL);
		     break;
		}
		fflush(stdout);
		printf("\r\n");
		fflush(stdout);
	}

	k = nusers = 0;
	av[k++] = "finger";
	for (s = strtok(line, WS); s && k<ENTRIES; s = strtok(NULL, WS)) {
		/* RFC742: "/[Ww]" == "-l" */
		if (!strncasecmp(s, "/w", 2)) memcpy(s, "-l", 2);
		if (!forwarding) {
		    t = strchr(s, '@');
		    if (t) {
			    fprintf(stderr,
				    "fingerd: forwarding not allowed\r\n");
			    syslog(LOG_WARNING, "rejected %s\n", s);
			    exit(1);
		    }
		}
		if (heavylogging) {
		    if (*s=='-') syslog(LOG_INFO, "option %s\n", s);
		    else syslog(LOG_INFO, "fingered %s\n", s);
		}
		av[k++] = s;
		if (*s!='-') nusers++;
	}
	av[k] = NULL;
	if (nusers==0) {
		/* finger @host */
		if (nouserlist) {
			syslog(LOG_WARNING, "rejected finger @host\n");
			printf("Please supply a username\r\n");
			return 0;
		}
		if (heavylogging) syslog(LOG_INFO, "fingered @host\n");
	}

/* Yay! we don't need to do this any more - finger does it for us */
#if 0
	if (pipe(p) < 0) {
		fatal("pipe", 1, 1, 0);
	}

	pid = fork();
	if (pid<0) {
		fatal("fork", 1, 1, 0);
	}
	if (pid==0) {
		/* child */
		close(p[0]);
		dup2(p[1], 1);
		if (p[1]!=1) close(p[1]);
#endif
		/*
		 * execv() takes (char *const *), because (char const *const *)
		 * doesn't work right in C (only in C++). C9x might fix this
		 * if we're lucky. In the meantime we need to defeat the type
		 * system to avoid warnings.
		 */
		avy = av;
		/*avx = avy;*/
		memcpy(&avx, &avy, sizeof(avx));

		if (fingerpath) execv(fingerpath, avx);
		execv(_PATH_FINGER, avx);
		execv(_ALT_PATH_FINGER_1, avx);
		execv(_ALT_PATH_FINGER_2, avx);
		execv(_ALT_PATH_FINGER_3, avx);
		syslog(LOG_ERR, "Finger program not found\n");
		exit(1);
#if 0
	}
	/* parent */
	close(p[1]);

	/* convert \n to \r\n. This should be an option to finger... */
	fp = fdopen(p[0], "r");
	if (!fp) {
		fatal("fdopen", 1, 1, 0);
	}

	while ((ch = getc(fp)) != EOF) {
		if (ch == '\n')	putchar('\r');
		putchar(ch);
	}
	return 0;
#endif
}
