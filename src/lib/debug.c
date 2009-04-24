/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
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

#include "common.h"
#include "debug.h"


#if defined(SOCKER_DEBUG)
#include <syslog.h>

static void
debug_init(void)
{
  static bool initialized;

  if (!initialized) {
    initialized = true;
    openlog("socker", LOG_PID | LOG_NDELAY, LOG_USER);
  }
}
#endif /* SOCKER_DEBUG */

/*
 * For security reasons no messages should be output on stdout or stderr.
 * Define SOCKER_DEBUG for debugging purposes only.
 */
void
debug_msg(const char *fmt, ...)
{
  va_list ap;

#if defined(SOCKER_DEBUG)
  {
    int saved_errno = errno;
    const char *user;
    char msg[4096];

    user = get_username();
    debug_init();
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    syslog(LOG_DEBUG | LOG_USER, "(%s) %s", user ? user : "<unknown>", msg);
    va_end(ap);
    errno = saved_errno;
  }
#else /* !SOCKER_DEBUG */
  (void) fmt;
  (void) ap;
#endif /* SOCKER_DEBUG */
}

void
debug_error(const char *fmt, ...)
{
  va_list ap;
  
#if defined(SOCKER_DEBUG)
  {
    int saved_errno = errno;
    const char *user;
    char msg[4096];

    user = get_username();
    debug_init();
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    errno = saved_errno;
    syslog(LOG_DEBUG | LOG_USER, "(%s) %s: %m", user ? user : "<unknown>", msg);
    va_end(ap);
    errno = saved_errno;
  }
#else /* !SOCKER_DEBUG */
  (void) fmt;
  (void) ap;
#endif /* SOCKER_DEBUG */
}

void
debug_assert(const struct assert_point *ap)
{
#if defined(SOCKER_DEBUG)
  const char *sv[] = {
    "\nAssertion failure at ",
    NULL, /* ap->file */
    ":",
    NULL, /* ap->line */
    " (",
    NULL, /* ap->func */
    "): ",
    NULL, /* ap->expr */
    "\n"
  };
  struct iovec iov[ARRAY_LEN(sv)];
  unsigned i;

  for (i = 0; i < ARRAY_LEN(iov); i++)
  switch (i) {
  case 1: sv[i] = ap->file; break;
  case 3: sv[i] = ap->line; break;
  case 5: sv[i] = ap->func; break;
  case 7: sv[i] = ap->expr; break;
  }

  for (i = 0; i < ARRAY_LEN(iov); i++) {
    iov[i].iov_base = deconstify_char_ptr(sv[i]);
    iov[i].iov_len = strlen(sv[i]);
  }

  (void) writev(STDERR_FILENO, iov, ARRAY_LEN(iov));
  abort();
#else /* !SOCKER_DEBUG */
  (void) ap;
#endif /* SOCKER_DEBUG */
}


/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
