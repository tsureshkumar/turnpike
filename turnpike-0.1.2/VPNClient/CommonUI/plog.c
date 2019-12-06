/* $Id: plog.c,v 1.1 2005/12/14 14:34:21 rvinay Exp $ */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <ctype.h>
#include <err.h>

#include "plog.h"

#ifndef VA_COPY
# define VA_COPY(dst,src) memcpy(&(dst), &(src), sizeof(va_list))
#endif

#define ARRAYLEN(a)     (sizeof(a)/sizeof(a[0]))

char *pname = NULL;
int loglevel = LLV_BASE;
int f_foreground = 0;

int print_location = 0;

static struct log *logp = NULL;
static char *logfile = NULL;

static char *plog_common __P((int, const char *, const char *));

static struct plogtags {
	char *name;
	int priority;
} ptab[] = {
	{ "(not defined)",	0, },
	{ "INFO",		LOG_INFO, },
	{ "NOTIFY",		LOG_INFO, },
	{ "WARNING",		LOG_INFO, },
	{ "ERROR",		LOG_INFO, },
	{ "DEBUG",		LOG_DEBUG, },
	{ "DEBUG2",		LOG_DEBUG, },
};


struct log {
        int head;
        int siz;
        char **buf;
        time_t *tbuf;
        char *fname;
};


struct log *
log_open(siz, fname)
        size_t siz;
        char *fname;
{
        struct log *p;

        p = (struct log *)malloc(sizeof(*p));
        if (p == NULL)
                return NULL;
        memset(p, 0, sizeof(*p));

        p->buf = (char **)malloc(sizeof(char *) * siz);
        if (p->buf == NULL) {
                free(p);
                return NULL;
        }
        memset(p->buf, 0, sizeof(char *) * siz);

        p->tbuf = (time_t *)malloc(sizeof(time_t *) * siz);
        if (p->tbuf == NULL) {
                free(p->buf);
                free(p);
                return NULL;
        }
        memset(p->tbuf, 0, sizeof(time_t *) * siz);

        p->siz = siz;
        if (fname)
                p->fname = strdup(fname);

        return p;
}




int
log_vaprint(struct log *p, const char *fmt, va_list ap)
{
        FILE *fp;

        if (p->fname == NULL)
                return -1;      /*XXX syslog?*/
        fp = fopen(p->fname, "a");
        if (fp == NULL)
                return -1;
        vfprintf(fp, fmt, ap);
        fclose(fp);

        return 0;
}



static char *
plog_common(pri, fmt, func)
	int pri;
	const char *fmt, *func;
{
	static char buf[800];	/* XXX shoule be allocated every time ? */
	char *p;
	int reslen, len;

	p = buf;
	reslen = sizeof(buf);

	if (logfile ) {
		time_t t;
		struct tm *tm;

		t = time(0);
		tm = localtime(&t);
		len = strftime(p, reslen, "%Y-%m-%d %T: ", tm);
		p += len;
		reslen -= len;
	}

	if (pri < ARRAYLEN(ptab)) {
		len = snprintf(p, reslen, "%s: ", ptab[pri].name);
		if (len >= 0 && len < reslen) {
			p += len;
			reslen -= len;
		} else
			*p = '\0';
	}

	if (print_location)
		snprintf(p, reslen, "%s: %s", func, fmt);
	else
		snprintf(p, reslen, "%s", fmt);

	return buf;
}

void
plog(int pri, const char *func, struct sockaddr *sa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	plogv(pri, func, sa, fmt, ap);
	va_end(ap);
}

void
plogv(int pri, const char *func, struct sockaddr *sa,
	const char *fmt, va_list ap)
{
	char *newfmt;
	va_list ap_bak;

	if (pri > loglevel)
		return;

	newfmt = plog_common(pri, fmt, func);

	VA_COPY(ap_bak, ap);
	

	if (logfile)
		log_vaprint(logp, newfmt, ap_bak);
}


void
ploginit()
{
	if (logfile) {
		logp = log_open(250, logfile);
		if (logp == NULL)
			errx(1, "ERROR: failed to open log file %s.", logfile);
		return;
	}

//        openlog(pname, LOG_NDELAY, LOG_DAEMON);
}

void
plogset(file)
	char *file;
{
	if (logfile != NULL)
		free(logfile);
	logfile = strdup(file);
}

