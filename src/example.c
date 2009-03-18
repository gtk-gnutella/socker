/*
 * Compiling:
 *
 * cc $(socker-config --cflags --libs) -o example example.c
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <socker.h>

int
main(void)
{
  int fd;

#if 1
  fd = socker_get(PF_INET6, SOCK_STREAM, 0, "::1", 80);
  if (-1 == fd) {
    fprintf(stderr, "socker() failed\n");
    exit(EXIT_FAILURE);
  }

  if (listen(fd, 10)) {
    perror("listen()");
    exit(EXIT_FAILURE);
  }

  if (-1 != accept(fd, NULL, NULL)) {
    fprintf(stderr, "Got incoming connection\n");
    exit(EXIT_SUCCESS);
  }
#endif

#if 0 
  fd = socker_get(PF_INET6, SOCK_RAW, 58, "::1", -1);
  if (-1 == fd) {
    fprintf(stderr, "socker() failed\n");
    exit(EXIT_FAILURE);
  } else {
    char buf[4096];
    ssize_t ret;
    
    ret = recvfrom(fd, buf, sizeof buf, 0, NULL, NULL);
    if ((ssize_t) -1 == ret) {
      perror("recvfrom()");
    } else {
      ssize_t i;
      for (i = 0; i < ret; i++) {
        int c = (unsigned char) buf[i];
        if (c < 32 || c > 126 || '%' == c)
          printf("%%%d%d", c / 16, c % 16);
        else
          putchar(c);
      }
    }
  }
#endif

#if 0
  fd = socker_get(PF_UNIX, SOCK_STREAM, 0, "/root/socket", -1);
  if (-1 == fd) {
    fprintf(stderr, "socker() failed\n");
    exit(EXIT_FAILURE);
  }
  if (-1 != accept(fd, NULL, NULL)) {
    fprintf(stderr, "Got incoming connection\n");
    exit(EXIT_SUCCESS);
  }
#endif

  return EXIT_FAILURE;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
