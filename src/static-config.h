#ifndef STATIC_CONFIG_HEADER_FILE
#define STATIC_CONFIG_HEADER_FILE

#ifndef SOCKER_PATH_TO_CONFIG
#define SOCKER_PATH_TO_CONFIG "/etc/socker.conf"
#endif /* !SOCKER_PATH_TO_SOCKER_CONFIG */

/* Format of the configuration file
 *
 * entry := <user>:<domain>:<type>:<protocol>:<address>:[<port-range>]
 * port-range := <port>[-<port>]
 * port := <digit>{1,5}; 0-65535
 * digit := 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
 *
 * The port range is only used by PF_INET and PF_INET6.
 * An asterisk '*' can be used as wildcard to allow any value.
 * Empty lines and those starting with a hash mark '#' are skipped.
 * Lines may not exceed 1022 characters including the terminating '\n'.
 * All lines must be terminated by a '\n' character. Whitespace is not
 * ignored.
 */

/* Note:  We continue on most format errors to prevent that adding
 *        a malformed entry causes a denial of service.
 */

#ifdef SOCKER_USE_STATIC_CONFIG
#undef SOCKER_PATH_TO_CONFIG

/*
 * If a static configuration is used, no external configuration file is used.
 * The format is the same, except that line termination is not required.
 */
static const struct {
  const char * const entry;
} socker_config[] = {
  /* Example configuration */
  { "*:inet:DGRAM:0:*:1024-65535" },
  { "*:inet:STREAM:0:*:1024-65535" },
  { "*:inet6:DGRAM:0:*:1024-65535" },
  { "*:inet6:STREAM:0:*:1024-65535" },
  { "dns:inet:DGRAM:0:0.0.0.0:53" },
  { "dns:inet6:STREAM:\"::\":0:53" },
  { "www:inet:DGRAM:0:*:80" },
  { "www:inet6:STREAM:\"::\":0:80" },
};
#endif /* SOCKER_USE_STATIC_CONFIG */

/* vi: set sts=2 sw=2 cindent: */
#endif /* STATIC_CONFIG_HEADER_FILE */
