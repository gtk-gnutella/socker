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
#include <pwd.h>

const char *
get_username(void)
{
  static const char *user;
  static char *dbuf;
  static uid_t uid;

  if (user && getuid() != uid) {
    user = NULL;
    if (dbuf) {
      free(dbuf);
      dbuf = NULL;
    }
  }

  if (!user) {
    const struct passwd *pw;
    static char user_buf[1024];

    uid = getuid();
    pw = getpwuid(uid);
    if (!pw) {
      return NULL;
    }
    if (strlen(pw->pw_name) < sizeof user_buf) {
      strncpy(user_buf, pw->pw_name, sizeof user_buf);
      user = user_buf;
    } else {
      user = dbuf = strdup(pw->pw_name);
      if (!user) {
	      return NULL;
      }
    }
  }
  return user;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
