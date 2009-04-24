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

#include "config.h"
#ifdef HAVE_FEATURES_H
/* This is required to get RTLD_NEXT defined with GNU libc. */
#define _GNU_SOURCE
#endif /* HAVE_FEATURES_H */

#include "common.h"
#include "socker.h"

#include <sys/wait.h>
#include <dlfcn.h>

int socket(int, int, int)
  __attribute__((alias ("socker_socket")));

#ifdef HAVE_BIND_WITH_STRUCT_SOCKADDR
int bind(int s, const struct sockaddr *, socklen_t)
  __attribute__((alias ("socker_bind")));
#else /* HAS_BIND_WITH_STRUCT_SOCKADDR */
int bind(int s, const void *, socklen_t)
  __attribute__((alias ("socker_bind")));
#endif /* HAS_BIND_WITH_STRUCT_SOCKADDR */

typedef void (*func_ptr)(void);

static int socker_socket(int, int, int);
static int socker_bind(int, const struct sockaddr *, socklen_t);

static func_ptr
socker_get_libc_symbol(const char *symbol)
{
  static void *handle;
  static const func_ptr zero_func;
  func_ptr func = zero_func;

#if defined(RTLD_NEXT)
  handle = RTLD_NEXT;
#else /* !RTLD_NEXT */
  if (!handle) {
    handle = dlopen("libc.so", RTLD_NOW);
  }
#endif /* RTLD_NEXT */

  if (handle) {
    union {
      func_ptr f;
      const void *p;
    } u;
    u.p = dlsym(handle, symbol);
    func = u.f;
    if (!func) {
      errno = ENOSYS;
    }
  } else {
    errno = ENOENT;
  }

  return func;
}

static int
socker_real_socket(int domain, int type, int protocol)
{
  typedef int (*socket_func_ptr)(int, int, int);
  static socket_func_ptr func;

  if (!func) {
#ifdef __NetBSD__
    func = (socket_func_ptr) socker_get_libc_symbol("__socket30");
#endif
    if (!func) {
      func = (socket_func_ptr) socker_get_libc_symbol("socket");
    }
    if (!func)
      return -1;
  }
  return func(domain, type, protocol);
}

static int
socker_real_bind(int s, const struct sockaddr *addr, socklen_t addr_len)
{
  typedef int (*bind_func_ptr)(int, const struct sockaddr *, socklen_t);
  static bind_func_ptr func;
  
  if (!func) {
    func = (bind_func_ptr) socker_get_libc_symbol("bind");
    if (!func)
      return -1;
  }
  return func(s, addr, addr_len);
}

static void (*
set_signal(int signo, void (*handler)(int)))(int)
{
  struct sigaction sa, osa;

  memset(&sa, 0, sizeof sa);
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = signo != SIGALRM ? SA_RESTART
#ifdef HAVE_SA_INTERRUPT
    : SA_INTERRUPT;
#else
    : 0;
#endif
  return sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
}

static void
sigchld_handler(int signo)
{
  (void) signo;
  waitpid(-1, NULL, WNOHANG);
}

static int
socker_request_bind(int s, const char *addr, unsigned port)
{
  pid_t pid;
  
  pid = fork();
  if ((pid_t) -1 == pid) {
    debug_error("fork() failed");
  } else if (0 == pid) {  /* child */
    static char *argv[] = {
      "socker",
      "-b",
      "-f", NULL,
      "-a", NULL,
      "-P", NULL,
      NULL,
    };
    char s_port[32];
    char s_fd[32];
    unsigned i;

    snprintf(s_port, sizeof s_port, "%u", port);
    snprintf(s_fd, sizeof s_fd, "%d", s);

    i = 1;

    argv[i++] = "-b";
    
    argv[i++] = "-f";
    argv[i++] = s_fd;
  
    if (addr) {
      argv[i++] = "-a";
      argv[i++] = deconstify_char_ptr(addr);
   
      if ((unsigned) -1 != port) {
        argv[i++] = "-P";
        argv[i++] = s_port;
      }
    }
    argv[i] = NULL;
    RUNTIME_ASSERT(i < ARRAY_LEN(argv));

    execvp(argv[0], argv);
    _exit(EXIT_FAILURE);

  } else {  /* parent */
    pid_t ret;
    int status;

    errno = 0;
    ret = waitpid(pid, &status, 0);
    if ((pid_t) -1 == ret) {
      if (ECHILD != errno) {
        debug_error("waitpid() failed");
      }
    } else if (0 != ret && pid != ret) {
      debug_msg("waitpid() returned %lu\n", (unsigned long) ret);
    } else if (pid == ret && (!WIFEXITED(status) || 0 != WEXITSTATUS(status))) {
      debug_msg("child exited with status %u\n",
        (unsigned) WEXITSTATUS(status));
    }

    {
      union {
        struct sockaddr any;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
      } saddr;
      socklen_t len;
      bool success = false;
   
      len = sizeof saddr;
      if (0 != getsockname(s, &saddr.any, &len)) {
        debug_error("getsockname() failed");
      } else {
        switch (saddr.any.sa_family) {
        case AF_INET:
          success = htons(port) == saddr.in.sin_port;
          break;
#if defined(HAVE_IPV6_SUPPORT)
        case AF_INET6:
          success = htons(port) == saddr.in6.sin6_port;
          break;
#endif /* HAVE_IPV6_SUPPORT */
        }
      }

      if (success) {
        return 0;
      } else {
        errno = EACCES;
        return -1;
      }
    }
  }

  return -1;
}

static int
socker_socket(int domain, int type, int protocol)
{
  int s;

  s = socker_real_socket(domain, type, protocol);
  if (s < 0 && (EACCES == errno || EPERM == errno)) {
    s = socker_get(domain, type, protocol, NULL, (unsigned) -1);
  }
  return s;
}

static int
socker_bind(int s, const struct sockaddr *addr, socklen_t addr_len)
{
  char addr_buf[256];
  const char *addr_str = NULL;
  unsigned port = -1;
  int ret;
 
  ret = socker_real_bind(s, addr, addr_len);
  if (0 != ret && (EACCES == errno || EPERM == errno)) {

    if (NULL == addr) {
      errno = EFAULT;
      return -1;
    }
        
    switch (addr->sa_family) {
    case AF_INET:
      if (sizeof(struct sockaddr_in) == addr_len) {
        const struct sockaddr_in *addr_in;

        addr_in = (const void *) addr; 
        port = ntohs(addr_in->sin_port);
        addr_str = inet_ntop(AF_INET, &addr_in->sin_addr.s_addr,
            addr_buf, sizeof addr_buf);
      }
      break;
      
#if defined(HAVE_IPV6_SUPPORT)
    case AF_INET6:
      if (sizeof(struct sockaddr_in6) == addr_len) {
        const struct sockaddr_in6 *addr_in6;

        addr_in6 = (const void *) addr; 
        port = ntohs(addr_in6->sin6_port);
        addr_str = inet_ntop(AF_INET6, &addr_in6->sin6_addr,
            addr_buf, sizeof addr_buf);
      }
      break;
#endif /* HAVE_IPV6_SUPPORT */
    default:
      debug_msg("socker_bind(): sa_family=%u\n", (unsigned) addr->sa_family);
    }

    if (addr_str) {
      void (*handler)(int);
      int flags, saved_errno;

      /* Clear the close-on-exec flag temporarly if set */
      flags = fcntl(s, F_GETFD, 0);
      if (-1 == flags) {
        debug_error("fcntl(s, F_GETFD, 0) failed");
        /* Ignore error */
      }
      if (
         0 != (FD_CLOEXEC & flags) &&
         -1 == fcntl(s, F_SETFD, flags & ~FD_CLOEXEC)
      ) {
        debug_error("fcntl(s, F_GETFD, flags & ~FD_CLOEXEC) failed");
        /* Ignore error */
      }

      handler = set_signal(SIGCHLD, sigchld_handler);
      ret = socker_request_bind(s, addr_str, port);
      saved_errno = errno;
      set_signal(SIGCHLD, handler);
      
      /* Restore the close-on-exec flag if it was set before */
      if (0 != (FD_CLOEXEC & flags) && -1 == fcntl(s, F_SETFD, flags)) {
        debug_error("Failed to restore FD_CLOEXEC");
        /* Ignore error */
      }

      errno = saved_errno;
    } else {
      errno = EINVAL;
      ret = -1;
    }
  }
  return ret;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
