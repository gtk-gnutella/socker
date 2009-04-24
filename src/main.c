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

#include "lib/common.h"
#include <pwd.h>

#include "static-config.h"

static const char wildcard[] = "*";
static unsigned line_number; /* current line number in the config file */

static void
fail(void)
{
  exit(EXIT_FAILURE);
}

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

static int
send_descriptor(const int master_fd, const int fd)
{
  static const struct msghdr zero_msg;
  static struct iovec iov[1];
  static const char buf[1];
  struct msghdr msg;
  ssize_t ret;
  void *to_free;

  RUNTIME_ASSERT(-1 != master_fd);
  RUNTIME_ASSERT(-1 != fd);

  iov[0].iov_base = (void *) buf;
  iov[0].iov_len = sizeof buf;
  
  msg = zero_msg;
  msg.msg_iov = iov;
  msg.msg_iovlen = ARRAY_LEN(iov);

#ifdef HAVE_MSGHDR_ACCRIGHTS
  {
    to_free = NULL;
    msg.msg_accrights = &fd;
    msg.msg_accrightslen = sizeof fd;
  }
#endif /* HAVE_MSGHDR_ACCRIGHTS */
#if !defined(HAVE_MSGHDR_ACCRIGHTS) && defined(HAVE_MSGHDR_CONTROL)
  {
    static const struct cmsghdr zero_cmsg;
    struct cmsghdr *cmsg;

    cmsg = calloc(1, CMSG_SPACE(sizeof fd));
    if (!cmsg) {
      debug_error("calloc()");
      return -1;
    }
    to_free = cmsg;

    *cmsg = zero_cmsg;
    cmsg->cmsg_len = CMSG_LEN(sizeof fd);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;

    memcpy((char *) cmsg + CMSG_LEN(0), &fd, sizeof fd);

    msg.msg_control = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;
  }
#endif /* HAVE_MSGHDR_CONTROL */

  ret = sendmsg(master_fd, &msg, 0);
  if ((ssize_t) -1 == ret) {
    debug_error("sendmsg()");
  }
  if (to_free) {
    free(to_free);
  }
  return ret;
}

static int
parse_socket_domain(const char *s, int *val_ptr)
{
  static const struct {
    const char * const name;
    const int val;
  } tab[] = {
#define D(x) { #x, (x) }
#if defined(HAVE_IPV6_SUPPORT)
    D(PF_INET6),
#endif /* PF_INET6 */
    D(PF_INET), 
#undef D
  };
  unsigned i;

  RUNTIME_ASSERT(s);

  for (i = 0; i < ARRAY_LEN(tab); i++) {
    if (0 == strcasecmp(s, tab[i].name)) {
      if (val_ptr)
        *val_ptr = tab[i].val;
      return 0;
    }
  }

  /* Retry without the PF_ prefix */
  for (i = 0; i < ARRAY_LEN(tab); i++) {
    const char *q;

    q = strchr(tab[i].name, '_');
    if (q && 0 == strcasecmp(s, &q[1])) {
      if (val_ptr)
        *val_ptr = tab[i].val;
      return 0;
    }
  }

  if (val_ptr)
    *val_ptr = -1;
  return -1;
}

static int
parse_socket_type(const char *s, int *val_ptr)
{
#define D(x) { #x, (x) }
  static const struct {
    const char * const name;
    const int val;
  } tab[] = {
    D(SOCK_STREAM),
    D(SOCK_DGRAM),
    D(SOCK_RAW),
    D(SOCK_SEQPACKET),
    D(SOCK_RDM),
#undef D
  };
  unsigned i;

  RUNTIME_ASSERT(s);

  for (i = 0; i < ARRAY_LEN(tab); i++) {
    if (0 == strcmp(s, tab[i].name)) {
      if (val_ptr)
        *val_ptr = tab[i].val;
      return 0;
    }
  }
  /* Retry without the SOCK_ prefix */
  for (i = 0; i < ARRAY_LEN(tab); i++) {
    const char *q;

    q = strchr(tab[i].name, '_');
    if (q && 0 == strcasecmp(s, &q[1])) {
      if (val_ptr)
        *val_ptr = tab[i].val;
      return 0;
    }
  }

  if (val_ptr)
    *val_ptr = -1;
  return -1;
}

static int
parse_socket_protocol(const char *s, int *val_ptr)
{
  char *endptr;
  unsigned long u;

  errno = 0;
  u = strtoul(s, &endptr, 10);
  if (0 == errno && u < INT_MAX && endptr != s && '\0' == *endptr) {
    *val_ptr = u;
    return 0;
  } else {
    struct protoent *p;

    p = getprotobyname(s);
    if (p) {
      *val_ptr = p->p_proto;
      return 0;
    }
  }
  return -1;
}

int
parse_number(const char *token, char **endptr, const unsigned max_num)
{
  char *ep;
  unsigned long u;
  int port = -1;
  int saved_errno = errno;

  if (isdigit((unsigned char) token[0])) {
    errno = 0;
    u = strtoul(token, &ep, 10);
    if (0 == errno && u <= max_num && ep != token) {
      port = u;
    }
  }

  if (endptr) {
    *endptr = ep;
  }
  errno = saved_errno;
  return port;
}

int
parse_port(const char *token, char **endptr)
{
  return parse_number(token, endptr, 65535);
}

int
parse_fd(const char *s)
{
  unsigned long u;
  char *endptr;

  errno = 0;
  u = strtoul(s, &endptr, 10);
  if (u > INT_MAX || 0 != errno || endptr == s || '\0' != *endptr) {
    debug_msg("Cannot parse file descriptor number (\"%s\")", s);
    return -1;
  }
  if (u < 3) {
    debug_msg("Unacceptable file descriptor number (\"%s\")", s);
    return -1;
  }
  return u;
}

/**
 * Unescapes the given token in-place. A single slash '\' escapes the next
 * character, this is useful to escape a '"' or ':'. Escaping NUL characters
 * is not allowed. A double-quote '"' escapes all characters up to the next
 * double-quote except slashes. This is especially useful for IPv6 addresses.
 * Escaping NUL characters or non-closed * double-quotes cause a failure. Empty
 * quoted strings ("") are tolerated.
 *
 * @return -1 on failure and 0 on success. 
 */
int
unescape_token(char *token)
{
  const char *p;
  char *q;
  bool quoted = false;

  q = token;
  for (p = token; '\0' != *p; p++) {
    if ('\\' == *p) {
      p++;
      if ('\0' == *p)
        return -1;
    } else if ('"' == *p) {
      quoted = !quoted;
      if ('\0' == *p) {
        break;
      }
      continue;
    }
    *q++ = *p;
  }
  *q = '\0';

  return quoted ? -1 : 0;
}

/**
 * Finds the next non-escaped/quoted ':' (token separator) and replaces
 * it with a NUL character.
 *
 * @return  NULL if no token separator was found or a pointer to start of
 *          the next token.
 */
char *
separate_token(char * const token)
{
  bool esc = false, quoted = false;
  char *p;
 
  for (p = token; p != NULL; p++) {
    if ('\0' == *p) {
      if (esc || quoted) {
        p = NULL; /* Quoting or escaping NUL is invalid */
      }
      break;
    } else if (esc) {
      esc = false;
      continue;
    } else if (':' == *p) {
      if (!quoted)
        break;
    } else if ('"' == *p) {
      quoted = !quoted;
    } else if ('\\' == *p) {
      esc = true;
    }
  }

  if (p && '\0' != *p) {
    *p++ = '\0';
  }

  return p;
}

/**
 * Extracts the next token from the given string 'line'. The token is
 * unescaped and terminated with a NUL character.
 *
 * @return NULL on failure or a pointer to the start of the extracted token.
 */
char *
get_token(char * const line, char **endptr, const char * const item)
{
  char *ep;
  
  ep = separate_token(line);
  if (endptr) {
    *endptr = ep;
  }
  if (!ep) {
    debug_msg("Non-terminated %s (%u)", item, line_number);
    return NULL;
  }
  if (0 != unescape_token(line)) {
    debug_msg("Badly escaped %s (%u)", item, line_number);
    return NULL;
  }
  return line;
}

int
extract_mask_len(char *token, unsigned max_bits)
{
  char *p;
  int n;

  p = strchr(token, '/');
  if (p) {
    *p++ = '\0';
    n = parse_number(p, &p, max_bits);
  } else {
    n = max_bits;
  }

  return n;
}

static bool
address_matches(char *token,
    const int domain, const struct sockaddr * const addr)
{
  if (0 == strcmp(token, wildcard)) {
    return true;
  }
  if (!addr) {
    /* If there was no address given only the empty token matches.
     * This is used for socket-only requests. */
    return '\0' == token[0];
  }

  switch (domain) {
  case PF_INET:
    {
      const struct sockaddr_in *addr_in = cast_to_const_void_ptr(addr);
      in_addr_t ip;
      int mask_len;

      mask_len = extract_mask_len(token, 32);
      if (
        mask_len > 0 && mask_len <= 32 &&
        1 == inet_pton(AF_INET, token, &ip)
      ) {
        int shift = 32 - mask_len;

        ip = ntohl(ip) >> shift;
        if (ip == ntohl(addr_in->sin_addr.s_addr) >> shift)
          return true;
      }
    }
    break;

#if defined(HAVE_IPV6_SUPPORT)
  case PF_INET6:
    {
      const struct sockaddr_in6 *addr_in6 = cast_to_const_void_ptr(addr);
      struct in6_addr ip6;
      int mask_len;

      STATIC_ASSERT(16 == sizeof ip6);

      mask_len = extract_mask_len(token, 128);
      
      if (
        mask_len > 0 && mask_len <= 128 &&
        1 == inet_pton(AF_INET6, token, &ip6) &&
        0 == memcmp(&ip6, &addr_in6->sin6_addr, mask_len / 8)
      ) {
        const unsigned char *a, *b;
        int i, shift;

        a = cast_to_const_void_ptr(&ip6);
        b = cast_to_const_void_ptr(&addr_in6->sin6_addr);
        i = mask_len / 8;
        shift = mask_len % 8;
        if (16 == i || 0 == shift || 0 == ((a[i] ^ b[i]) >> shift))
          return true;
      }
    }
    break;
#endif /* PF_INET6*/
  }

  return false;
}

static bool 
user_matches(const char * const user, const char * const token)
{
  if (0 != strcmp(token, wildcard) && 0 != strcmp(token, user)) {
    debug_msg("User does not match (%u)", line_number);
    return false;
  }
  return true;
}

static bool 
domain_matches(const int domain, const char * const token)
{
  int i_token;

  if (0 == strcmp(token, wildcard)) {
    return true;
  }
  if (0 != parse_socket_domain(token, &i_token)) {
    debug_msg("Unknown socket domain in configuration file \"%s\" (%u)",
        token, line_number);
    return false;
  }
  if (i_token != domain) {
    debug_msg("Domain does not match (%u)", line_number);
    return false;
  }
  return true;
}

static bool 
type_matches(const int type, const char * const token)
{
  int i_token;

  if (0 == strcmp(token, wildcard)) {
    return true;
  }
  if (0 != parse_socket_type(token, &i_token)) {
    debug_msg("Unknown socket type in configuration file \"%s\" (%u)",
        token, line_number);
    return false;
  }
  if (i_token != type) {
    debug_msg("Type does not match (%u)", line_number);
    return false;
  }
  return true;
}

static bool 
protocol_matches(const int protocol, const char * const token)
{
  int i_token;

  if (0 == strcmp(token, wildcard)) {
    return true;
  }
  if (-1 == protocol) {
    if ('\0' == token[0]) {
      return true;
    } else {
      debug_msg("Protocol does not match (%u)", line_number);
      return false;
    }
  }
  if (0 != parse_socket_protocol(token, &i_token)) {
    debug_msg("Unknown socket protocol in configuration file \"%s\" (%u)",
        token, line_number);
    return false;
  }
  if (i_token != protocol) {
    debug_msg("Protocol does not match (%u)", line_number);
    return false;
  }
  return true;
}

static bool 
port_matches(const int port, const char *token)
{
  int first_port, last_port;
  char *ep;

  if (0 == strcmp(token, wildcard)) {
    return true;
  }
  if (-1 == port) {
    if ('\0' == token[0]) {
      /* If there was no port given only the empty token matches.
       * This is used for socket-only requests. */
      return true;
    } else {
      debug_msg("Port does not match (%u)", line_number);
      return false;
    }
  }

  first_port = parse_port(token, &ep);
  if (first_port < 0) {
    debug_msg("Not a port number \"%s\" (%u)", token, line_number);
    return false;
  }
  if ('-' != *ep) {
    last_port = first_port;  
  } else {
    token = &ep[1];
    last_port = parse_port(token, &ep);
    if (last_port < 0) {
      debug_msg("Not a port number \"%s\" (%u)", token, line_number);
      return false;
    }
  }
  if (first_port > last_port) {
    debug_msg("Bad port-range \"%s\" (%u)", token, line_number);
    return false;
  }
  if (port < first_port || port > last_port) {
    debug_msg("Port number does not match (%u)", line_number);
    return false;
  }
  return true;
}


/**
 * @return 'true' if the entry matches and 'false' if not.
 */
static bool 
entry_matches(const char *entry, const char * const user,
   const int domain, const int type, const int protocol,
   const struct sockaddr * const addr, const int port)
{
  char *ep, *token;
  bool has_port;
  char line[1024];

  if (strlen(entry) >= sizeof line) {
    debug_msg("Entry is too long (%u)", line_number);
    return false;
  }
  strncpy(line, entry, sizeof line);

  /* Ignore comments and empty lines */
  if ('#' == line[0] || '\0' == line[0]) {
    debug_msg("Skipping comment (%u)", line_number);
    return false;
  }
  
  token = get_token(line, &ep, "username");
  if (!token || !user_matches(user, token)) {
    return false;
  }

  token = get_token(ep, &ep, "domain");
  if (!token || !domain_matches(domain, token)) {
    return false;
  }

  token = get_token(ep, &ep, "type");
  if (!token || !type_matches(type, token)) {
    return false;
  }

  token = get_token(ep, &ep, "socket protocol");
  if (!protocol_matches(protocol, token)) {
    return false;
  }

  token = get_token(ep, &ep, "address");
  if (!token || !address_matches(token, domain, addr)) {
    debug_msg("Address does not match (%u)", line_number);
    return false;
  }

  switch (domain) {
  case PF_INET:
#if defined(HAVE_IPV6_SUPPORT)
  case PF_INET6:
#endif /* PF_INET6 */
    has_port = true;
    break;
  default:
    has_port = false;
  }

  if (has_port) {
    token = get_token(ep, &ep, "port range");
    if (!token || !port_matches(port, token)) {
      return false;
    }
  }

  /* Ignore rest of line */

  return true; /* If we got this far all parameters matched */
}

#ifndef SOCKER_USE_STATIC_CONFIG
static FILE *
config_open(void)
{
  static const int oflags = O_RDONLY |
#ifdef O_NOFOLLOW
    O_NOFOLLOW |
#endif /* O_NOFOLLOW */
#ifdef O_NOCTTY
    O_NOCTTY |
#endif /* O_NOCTTY */
    O_NONBLOCK;
  FILE *f = NULL;
  int fd, flags;
 
  fd = open(SOCKER_PATH_TO_CONFIG, oflags, 0);
  if (-1 == fd) {
    debug_error("open()");
    goto failure;
  }

  flags = fcntl(fd, F_GETFL, 0);
  if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)) {
    debug_error("fcntl(fd, F_SETFL, ...)");
    goto failure;
  }
  
  {
    struct stat sb;

    if (0 != fstat(fd, &sb)) {
      debug_error("fstat()");
      goto failure;
    }
    if (S_IFREG != (S_IFMT & sb.st_mode)) {
      debug_msg("Configuration file is not a regular file");
      goto failure;
    }
    if (0 != sb.st_uid) {
      debug_msg("Configuration file is not owned by root");
      goto failure;
    }
  }

  f = fdopen(fd, "r");
  if (!f) {
    debug_error("fdopen()");
    goto failure;
  }

  return f;

failure:
  
  if (-1 != fd) {
    close(fd);
  }
  if (f) {
    fclose(f);
  }
  return NULL;
}
#endif /* !SOCKER_USE_STATIC_CONFIG */

static int 
socket_granted(const char * const user,
  const int domain, const int type, const int protocol,
  const struct sockaddr * const addr, const int port)
#ifdef SOCKER_USE_STATIC_CONFIG
{
  for (line_number = 0; line_number < ARRAY_LEN(socker_config); line_number++) {
    if (entry_matches(socker_config[line_number].entry,
          user, domain, type, protocol, addr, port)
    ) {
      debug_msg("Entry matches (%u)", line_number);
      return true;
    }
  }

  return false;
}
#else /* !SOCKER_USE_STATIC_CONFIG */
{
  FILE *f;
  char line[1024];

  f = config_open();
  if (!f)
    goto failure;

  for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
    char *ep;

    ep = strchr(line, '\n');
    if (!ep) {
      debug_msg("Non-terminated or overlong line in configuration file (%u)",
        line_number);
      goto failure;
    }
    *ep = '\0';

    debug_msg("%4u: %s", line_number, line);
    if (entry_matches(line, user, domain, type, protocol, addr, port)) {
      debug_msg("Entry matches (%u)", line_number);
      fclose(f);
      f = NULL;
      return true;
    }
  }

failure:

  if (f) {
    fclose(f);
    f = NULL;
  }
  return false;
}
#endif /* SOCKER_USE_STATIC_CONFIG */

static void
usage(void)
{
  debug_msg("Usage: "
      "socker -d DOMAIN -t TYPE -p PROTOCOL -a ADDRESS [-P PORT] -f FD");
  debug_msg("   or: "
      "socker -b -a ADDRESS [-P PORT] -f SOCKET");
  fail();
}

int
main(int argc, char *argv[])
{
  static const char *s_domain, *s_type, *s_proto, *s_addr, *s_port, *s_fd;
  static int i_domain, i_type, i_proto, i_port = -1, transfer_fd = -1;
  static const struct sockaddr *sockaddr;
  static socklen_t sockaddr_len;
  static bool bind_only;
  int ch;

  if (argc < 1) {
    fail();
  }

  if (!get_username()) {
    debug_msg("Cannot determine username");
    fail();
  }

  if (NULL == freopen("/dev/null", "r+", stdin)) {
    debug_error("freopen(\"/dev/null\", \"r\", stdin)");
    fail();
  }
#if !defined(SOCKER_DEBUG)
  if (NULL == freopen("/dev/null", "w", stdout)) {
    debug_error("freopen(\"/dev/null\", \"w\", stdout)");
    fail();
  }
  if (NULL == freopen("/dev/null", "w", stderr)) {
    debug_error("freopen(\"/dev/null\", \"w\", stderr)");
    fail();
  }
#endif /* !SOCKER_DEBUG */

  while (-1 != (ch = getopt(argc, argv, "a:bd:t:p:P:f:"))) {
    switch (ch) {
    case 'b':
      bind_only = true;
      break;
    case 'd':
      if (s_domain) {
        debug_msg("Multiple use of -%c", ch);
        usage();
      }
      s_domain = optarg;
      break;
    case 't':
      if (s_type) {
        debug_msg("Multiple use of -%c", ch);
        usage();
      }
      s_type = optarg;
      break;
    case 'p':
      if (s_proto) {
        debug_msg("Multiple use of -%c", ch);
        usage();
      }
      s_proto = optarg;
      break;
    case 'a':
      if (s_addr) {
        debug_msg("Multiple use of -%c", ch);
        usage();
      }
      s_addr = optarg;
      break;
    case 'f':
      if (s_fd) {
        debug_msg("Multiple use of -%c", ch);
        usage();
      }
      s_fd = optarg;
      break;
    case 'P':
      if (s_port) {
        debug_msg("Multiple use of -%c", ch);
        usage();
      }
      s_port = optarg;
      break;
    default:
      usage();
      break;
    }
  }

  if (!s_fd || (transfer_fd = parse_fd(s_fd)) < 3) {
    usage();
  }

  {
    struct stat sb;
    
    if (0 != fstat(transfer_fd, &sb)) {
      debug_error("fstat()");
      fail();
    }
    if (S_IFSOCK != (S_IFMT & sb.st_mode)) {
      debug_msg("Not a socket");
      fail();
    }
  }

#define QUOTE(x) ((x) ? "\"" : ""), ((x) ? (x) : "none"), ((x) ? "\"" : "")
  debug_msg(
    "fd=%d domain=%s%s%s type=%s%s%s proto=%s%s%s addr=%s%s%s port=%s%s%s",
    transfer_fd, QUOTE(s_domain), QUOTE(s_type), QUOTE(s_proto),
    QUOTE(s_addr), QUOTE(s_port));
#undef QUOTE

  if (bind_only) {
    socklen_t len;
    struct sockaddr addr;
   
    len = sizeof addr;
    if (0 != getsockname(transfer_fd, &addr, &len)) {
      debug_error("getsockname(%d, ...) failed", transfer_fd);
      fail();
    }
    i_domain = addr.sa_family;

    len = sizeof i_type;
    if (0 != getsockopt(transfer_fd, SOL_SOCKET, SO_TYPE, &i_type, &len)) {
      debug_error("getsockopt(%d, ...) failed", transfer_fd);
      fail();
    }

    /* The protocol cannot be determined. */
    i_proto = -1;
  } else {

    if (!s_domain || !s_type || !s_proto) {
      usage();
    }

    if (0 != parse_socket_domain(s_domain, &i_domain)) {
      debug_msg("Unknown socket domain (\"%s\")", s_domain);
      fail();
    }

    if (0 != parse_socket_type(s_type, &i_type)) {
      debug_msg("Unknown socket type (\"%s\")", s_type);
      fail();
    }

    if (0 != parse_socket_protocol(s_proto, &i_proto)) {
      debug_msg("Unknown socket protocol (\"%s\")", s_proto);
      fail();
    }
  }

  if (s_port) {
    switch (i_domain) {
    case PF_INET:
#if defined(HAVE_IPV6_SUPPORT)
    case PF_INET6:
#endif /* HAVE_IPV6_SUPPORT */
      {
        char *endptr;

        i_port = parse_port(s_port, &endptr);
        if (i_port < 0 || '\0' != *endptr) {
          debug_msg("Cannot parse port number (\"%s\")", s_port);
          fail();
        }
      }
      break;

    default:
      debug_msg("The given domain does not support port numbers");
      fail();
    }
  } else {
    switch (i_domain) {
    case PF_INET:
#if defined(HAVE_IPV6_SUPPORT)
    case PF_INET6:
#endif /* HAVE_IPV6_SUPPORT */
      if (s_addr) {
        debug_msg("Missing port number");
        fail();
      }
      break;
    }
  }

  switch (i_domain) {
  case PF_INET:
    if (s_addr) {
      static const struct sockaddr_in zero_addr;
      static struct sockaddr_in addr;
      int ret;
      
      addr = zero_addr;
      ret = inet_pton(AF_INET, s_addr, &addr.sin_addr.s_addr);
      if (1 != ret) {
        if (0 == ret) {
          debug_msg("Unparsable address for AF_INET domain (\"%s\")", s_addr);
        } else {
          debug_error("No valid AF_INET address");
        }
        fail();
      }
      addr.sin_family = AF_INET;
      addr.sin_port = htons(i_port);
      sockaddr = (const void *) &addr;
      sockaddr_len = sizeof addr;
    }
    break;

#if defined(HAVE_IPV6_SUPPORT)
  case PF_INET6:
    if (s_addr) {
      static const struct sockaddr_in6 zero_addr;
      static struct sockaddr_in6 addr;
      int ret;
      
      addr = zero_addr;
      ret = inet_pton(AF_INET6, s_addr, &addr.sin6_addr);
      if (1 != ret) {
        if (0 == ret) {
          debug_msg("Unparsable address for AF_INET6 domain (\"%s\")", s_addr);
        } else {
          debug_error("No valid AF_INET address");
        }
        fail();
      }
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons(i_port);
      sockaddr = (const void *) &addr;
      sockaddr_len = sizeof addr;
    }
    break;
#endif /* HAVE_IPV6_SUPPORT */

  default:
    debug_msg("Unsupported socket domain (\"%s\")", s_domain);
    fail();
  }

  debug_msg( "i_domain=%d type=%d proto=%d", i_domain, i_type, i_proto);
 
  if (
    socket_granted(get_username(), i_domain, i_type, i_proto, sockaddr, i_port)
  ) {
    int fd;

    if (bind_only) {
      fd = transfer_fd;
    } else {
      fd = socket(i_domain, i_type, i_proto);
      if (-1 == fd) {
        debug_error("socket()");
        fail();
      }
    }

    /* Always enable SO_REUSEADDR for SOCK_STREAM IPv4/IPv6 sockets.
     * We must do this before bind() because it may have no effect
     * later. This prevents that we cannot recreate the socket for
     * a couple of minutes later. While it's not TCP-friendly almost
     * every single application uses this option anyway. */
    if (SOCK_STREAM == i_type) {
      switch (i_domain) {
      case AF_INET:
#if defined(HAVE_IPV6_SUPPORT)
      case AF_INET6:
#endif /* HAVE_IPV6_SUPPORT */
        {
          static const int on = 1;

          if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on)) {
            debug_error("setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, ...)");
            fail();
          }
        }
        break;
      }
    }

    /* Always enable IPv6-only for IPv6 sockets so that the socket()
     * does not accept IPv4 connections. Some implementations
     * do not support this anyway. */
#if defined(IPV6_V6ONLY) && defined(HAVE_IPV6_SUPPORT)
    if (AF_INET6 == i_domain) {
      static const int on = 1;
      
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on)) {
        debug_error("setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, ...)");
        fail();
      }
    }
#endif /* IPV6_V6ONLY */

    if (NULL != sockaddr && 0 != bind(fd, sockaddr, sockaddr_len)) {
      debug_error("bind()");
      fail();
    }

    setgid(getgid());
    if (getgid() != getegid()) {
      debug_error("setgid()");
      fail();
    }
    
    setuid(getuid());
    if (getuid() != geteuid()) {
      debug_error("setuid()");
      fail();
    }

    if (!bind_only) {
      if (0 != send_descriptor(transfer_fd, fd)) {
        fail();
      }
      close(fd);
    }
  } else {
    debug_msg("Permission denied");
    fail();
  }
 
  return 0;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
