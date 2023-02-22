#define _GNU_SOURCE

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>
#include "logging.h"
#include <fcntl.h>

#define PREENY_MAX_FD 8192
#define PREENY_SOCKET_OFFSET 500
#define READ_BUF_SIZE 65536

#define PREENY_SIN_PORT 1231

#define PREENY_SOCKET(x) (x+PREENY_SOCKET_OFFSET)

int preeny_desock_shutdown_flag = 0;
int preeny_desock_accepted_sock = -1;
int preeny_socket_hooked[PREENY_MAX_FD] = { 0 }; 
int preeny_socket_hooked_is_server[PREENY_MAX_FD] = { 0 };
pthread_t* preeny_socket_threads[PREENY_MAX_FD] = { 0 };
/* The needed accept number*/
int accept_num = 0;
/* The already accepted number*/
int accept_done_num = 0;
/* The needed connect number*/
int connect_num = 0;
/* The already connected number*/
int connect_done_num = 0;
// Next to allocated socket fd, starts from 0
int next_alloc_index = 0;  
/* The number of sockets that opened in calling accept. It is not accurate since some request is dropped, 
use accept_sock_num instead */
//int open_content_socks_num=0;
int accept_sock_num = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t *preeny_socket_threads_to_front[PREENY_MAX_FD] = { 0 };
pthread_t *preeny_socket_threads_to_back[PREENY_MAX_FD] = { 0 };


// Set the non-blocking flag on a socket file descriptor
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }
    return 0;
}

// Set the SO_REUSEADDR option on a socket file descriptor
int set_reuseaddr(int sockfd) {
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        return -1;
    }
    return 0;
}

// Set the SO_KEEPALIVE option on a socket file descriptor
int set_keepalive(int sockfd) {
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1) {
        return -1;
    }
    return 0;
}

// Set up a socket by setting the specified flags
int setup(int sockfd, int flag) {
    if (flag & O_NONBLOCK) {
        if (set_nonblocking(sockfd) == -1) {
            return -1;
        }
    }
    if (flag & SO_REUSEADDR) {
        if (set_reuseaddr(sockfd) == -1) {
            return -1;
        }
    }
    if (flag & SO_KEEPALIVE) {
        if (set_keepalive(sockfd) == -1) {
            return -1;
        }
    }
    return 0;
}



int preeny_socket_sync(int from, int to, int timeout)
{
	struct pollfd poll_in = { from, POLLIN, 0 };
	char read_buf[READ_BUF_SIZE];
	int total_n;
	char error_buf[1024];
	int n;
	int r;

	r = poll(&poll_in, 1, timeout);
	if (r < 0)
	{
		strerror_r(errno, error_buf, 1024);
		return 0;
	}
	else if (poll_in.revents == 0)
	{
		return 0;
	}

	total_n = read(from, read_buf, READ_BUF_SIZE);
	if (total_n < 0)
	{
		strerror_r(errno, error_buf, 1024);
		return -1;
	}
	else if (total_n == 0 && from == 0)
	{
		return -1;
	}

	n = 0;
	while (n != total_n)
	{
		r = write(to, read_buf, total_n - n);
		if (r < 0)
		{
			strerror_r(errno, error_buf, 1024);
			return -1;
		}
		n += r;
	}

	return total_n;
}

__attribute__((destructor)) void preeny_desock_shutdown()
{
	int i;
	int to_sync[PREENY_MAX_FD] = { };

	preeny_desock_shutdown_flag = 1;


	for (i = 0; i < PREENY_MAX_FD; i++)
	{
		if (preeny_socket_threads_to_front[i])
		{
			pthread_join(*preeny_socket_threads_to_front[i], NULL);
			pthread_join(*preeny_socket_threads_to_back[i], NULL);
			to_sync[i] = 1;
		}
	}

	for (i = 0; i < PREENY_MAX_FD; i++)
	{
		if (to_sync[i])
		{
			while (preeny_socket_sync(PREENY_SOCKET(i), 1, 0) > 0);
		}
	}

}

void preeny_socket_sync_loop(int from, int to)
{
	int r;


	while (!preeny_desock_shutdown_flag)
	{
		r = preeny_socket_sync(from, to, 12);
		if (r < 0) return;
	}
}

#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

void *preeny_socket_sync_to_back(void *fd)
{
	int front_fd = (int)fd;
	int back_fd = PREENY_SOCKET(front_fd);
	preeny_socket_sync_loop(back_fd, 1);
	return NULL;
}

void *preeny_socket_sync_to_front(void *fd)
{
	int front_fd = (int)fd;
	int back_fd = PREENY_SOCKET(front_fd);
	preeny_socket_sync_loop(0, back_fd);
	shutdown(back_fd, SHUT_WR);
	return NULL;
}

//
// originals
//
int (*original_socket)(int, int, int);
int (*original_bind)(int, const struct sockaddr *, socklen_t);
int (*original_listen)(int, int);
int (*original_accept)(int, struct sockaddr *, socklen_t *);
int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*original_close)(int fd);
int (*original_shutdown)(int sockfd, int how);
int (*original_getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
__attribute__((constructor)) void preeny_desock_orig()
{
	original_socket = dlsym(RTLD_NEXT, "socket");
	original_listen = dlsym(RTLD_NEXT, "listen");
	original_accept = dlsym(RTLD_NEXT, "accept");
	original_bind = dlsym(RTLD_NEXT, "bind");
	original_connect = dlsym(RTLD_NEXT, "connect");
	original_close = dlsym(RTLD_NEXT, "close");
	original_shutdown = dlsym(RTLD_NEXT, "shutdown");
	original_getsockname = dlsym(RTLD_NEXT, "getsockname");
}

int socket(int domain, int type, int protocol)
{
	int fds[2];
	int front_socket;
	int back_socket;

	if (domain != AF_INET && domain != AF_INET6)
	{
		return original_socket(domain, type, protocol);
	}
	
	int r = socketpair(AF_UNIX, type, 0, fds);

	if (r != 0)
	{
		perror("preeny+ socket emulation failed:");
		return -1;
	}


	front_socket = fds[0];
	back_socket = dup2(fds[1], PREENY_SOCKET(front_socket));
	close(fds[1]);


	preeny_socket_threads_to_front[fds[0]] = malloc(sizeof(pthread_t));
	preeny_socket_threads_to_back[fds[0]] = malloc(sizeof(pthread_t));

	r = pthread_create(preeny_socket_threads_to_front[fds[0]], NULL, (void*(*)(void*))preeny_socket_sync_to_front, (void *)front_socket);
	if (r)
	{
		return -1;
	}

	r = pthread_create(preeny_socket_threads_to_back[fds[0]], NULL, (void*(*)(void*))preeny_socket_sync_to_back, (void *)front_socket);
	if (r)
	{
		return -1;
	}

	return fds[0];
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{   
	if (preeny_desock_accepted_sock >= 0)
	{	
                errno = ECONNRESET;
		return -1;
	}

	 struct sockaddr_in peer_addr;
	 memset(&peer_addr, '0', sizeof(struct sockaddr_in));

		 peer_addr.sin_family = AF_INET;
	 peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
         peer_addr.sin_port = htons(PREENY_SIN_PORT);

	if (addr) memcpy(addr, &peer_addr, sizeof(struct sockaddr_in));

	if (preeny_socket_threads_to_front[sockfd])
	{
		printf("preenyplus_socket_threads_to_front created \n");
		preeny_desock_accepted_sock = dup(sockfd);
		return preeny_desock_accepted_sock;
	}
	else return original_accept(sockfd, addr, addrlen);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    if (!preeny_socket_threads_to_front[sockfd])
	{
        int newfd = original_accept(sockfd, addr, addrlen);
	if (preeny_socket_hooked[sockfd])
	{
		preeny_socket_hooked_is_server[sockfd] = 1;
		if (newfd > 0) {
			preeny_socket_hooked[newfd] = 1;
			pthread_mutex_lock(&mutex);
			accept_sock_num++;
			pthread_mutex_unlock(&mutex);
		}
	}
		printf("preenyplus_socket_threads_to_front \n");
		preeny_desock_accepted_sock = dup(sockfd);
		return preeny_desock_accepted_sock;
	}
	else return original_accept(sockfd, addr, addrlen);
       return accept(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (preeny_socket_threads_to_front[sockfd])
	{
		printf("Emulating bind on port %d\n", ntohs(((struct sockaddr_in*)addr)->sin_port));
		return 0;
	}
	else
	{
		return original_bind(sockfd, addr, addrlen);
	}
}

int listen(int sockfd, int backlog)
{
	if (preeny_socket_threads_to_front[sockfd]) return 0;
	else return original_listen(sockfd, backlog);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (preeny_socket_threads_to_front[sockfd]) return 0;
	else return original_connect(sockfd, addr, addrlen);
}

int close(int fd) {
	if (preeny_desock_accepted_sock != -1 && preeny_desock_accepted_sock == fd)
		exit(0);

	return original_close(fd);
}

int shutdown(int sockfd, int how) {
	if (preeny_desock_accepted_sock != -1 && preeny_desock_accepted_sock == sockfd)
		exit(0);

	return original_shutdown(sockfd, how);
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	struct sockaddr_in target;
	socklen_t copylen = sizeof(target);

	if (!preeny_socket_threads_to_front[sockfd])
		return original_getsockname(sockfd, addr, addrlen);

	if (!addr || !addrlen)
		return -1;

	if (*addrlen < sizeof(target))
		copylen = *addrlen;

	target.sin_family = AF_INET;
	target.sin_addr.s_addr = htonl(INADDR_ANY);
	target.sin_port = htons(PREENY_SIN_PORT);

	memcpy(addr, &target, copylen);
	*addrlen = copylen;

	return 0;
}
