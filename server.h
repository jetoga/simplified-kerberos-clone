#ifndef SERVER_H
#define SERVER_H

#include <sys/un.h>
#include <unistd.h>
	
#include <sys/socket.h>	
#include <sys/time.h>	
#include <time.h>		
	
#include <arpa/inet.h>	
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include "ticket.h"
	
const char ECHO_HEADER[] = "ECHO Server 1.0\n";
const int ECHO_HEADER_SIZE = 16;
	
const char TIME_HEADER[] = "TIME Server 1.0\n";
const int TIME_HEADER_SIZE = 16;


int make_master_socket(int* master_fd, sockaddr_in* server_addr, socklen_t size, int port)
{
	// master echo fd socket creation
	const int on = 1;
	
	*master_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(*master_fd < 0)
	{
		perror("socket failed\n");
		return -1;
	}
	
	bzero(server_addr, size);
	server_addr->sin_family = AF_INET;
	server_addr->sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr->sin_port = htons(port);
	
	if(setsockopt(*master_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
		perror("setsockopt failed\n");
		return -1;
	}
	if(bind(*master_fd, (sockaddr *) server_addr, size) < 0)
	{
		perror("bind failed\n");
		return -1;
	}
	if(listen(*master_fd, LISTEN_NUMBER) < 0)
	{
	
		perror("listen failed\n");
		return -1;
	}
	return 0;
}

int make_udp_socket(int* udp_fd, sockaddr_in* server_addr, socklen_t size, int port)
{
	// echo udp socket creation
	*udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(*udp_fd < 0)
	{
		perror("socket failed\n");
		return -1;
	}
	
	bzero(server_addr, size);
	server_addr->sin_family = AF_INET;
	server_addr->sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr->sin_port = htons(port);
	
	if(bind(*udp_fd, (sockaddr *) server_addr, size) < 0)
	{
		perror("bind failed\n");
		return -1;
	}
	return 0;
}


void invalid_ticket_action_tcp(int fd, int res, ticket* t, char *response, in_addr sender)
{
	char str[INET_ADDRSTRLEN];
	int msg_size = 0;
	
	if(res == -2)
		t->flag = FLAG_TICKET_TIMEOUT;
	else
		t->flag = FLAG_TICKET_ERROR;
	
	memcpy(response + msg_size, t, sizeof(ticket));
	msg_size += sizeof(ticket);
	
	write_tcp(fd, response, msg_size);
	
	inet_ntop(AF_INET, &sender, str, INET_ADDRSTRLEN);
	printf("Recived invalid ticket from %s\n", str);
}

void invalid_ticket_action_udp(int fd, int res, ticket* t, char *response, sockaddr_in client_addr)
{
	char str[INET_ADDRSTRLEN];
	int msg_size = 0;
	
	if(res == -2)
		t->flag = FLAG_TICKET_TIMEOUT;
	else
		t->flag = FLAG_TICKET_ERROR;
	
	memcpy(response + msg_size, t, sizeof(ticket));
	msg_size += sizeof(ticket);
	
	sendto(fd, response, msg_size, 0, (sockaddr *) &client_addr, sizeof(client_addr));

	inet_ntop(AF_INET, &client_addr.sin_addr, str, INET_ADDRSTRLEN);
	printf("Recived invalid ticket from %s\n", str);
}


void tcp_echo(int fd, in_addr sender, in_addr server, int port)
{
	char msg[MSG_SIZE_SERVER];
	int res, msg_size;
	
	msg_size = 0;
	ticket t;
	
	// Read ticket
	res = read_ticket(fd, &t);
	if(res != sizeof(ticket)) return;
	
	// Check the ticket
	res = validate_ticket(t, sender, server, port);
	if(res < 0)
	{
		invalid_ticket_action_tcp(fd, res, &t, msg, sender);
		return;
	}
	
	// Prepare the response
	t.flag = FLAG_SERVER;
	
	memcpy(msg + msg_size, &t, sizeof(ticket));
	msg_size += sizeof(ticket);
	
	memcpy(msg + msg_size, ECHO_HEADER, ECHO_HEADER_SIZE);
	msg_size += ECHO_HEADER_SIZE;
	
	res = read(fd, msg + msg_size, MSG_SIZE_SERVER - msg_size);
	if(res < 0) return;
	msg_size += res;
	
	
	// First response
	if(write_tcp(fd, msg, msg_size) != msg_size)
	{
		perror("write_tcp");
		return;
	}
	
	msg[msg_size] = 0;
	
	printf("Recived and sent: \"%s\"\n", msg + msg_size - res);
	
	// Rest
	do
	{
		while ((res = read(fd, msg, MSG_SIZE_SERVER)) > 0)
		{
			msg[res] = 0;
			printf("Recived and sent: \"%s\"\n", msg);
			if(write_tcp(fd, msg, res) != res) break;
		}
	} 
	while(res < 0 && errno == EINTR);
}


void udp_echo(int fd, sockaddr_in client_addr, socklen_t len, in_addr server, int port)
{
	char msg[MSG_SIZE_SERVER];
	char response[MSG_SIZE_SERVER + ECHO_HEADER_SIZE + sizeof(ticket)];
	int res, response_size, msg_size;
	
	msg_size = recvfrom(fd, msg, MSG_SIZE_SERVER, 0, (sockaddr *) &client_addr, &len);
	if(msg_size < sizeof(ticket)) return;
	
	response_size = 0;
	ticket t;
	memcpy(&t, msg, sizeof(ticket));
	
	// Check the ticket
	res = validate_ticket(t, client_addr.sin_addr, server, port);
	if(res < 0)
	{
		invalid_ticket_action_udp(fd, res, &t, response, client_addr);
		return;
	}
	
	// Create a response
	t.flag = FLAG_SERVER;
	
	memcpy(response + response_size, &t, sizeof(ticket));
	response_size += sizeof(ticket);
	
	memcpy(response + response_size, ECHO_HEADER, ECHO_HEADER_SIZE);
	response_size += ECHO_HEADER_SIZE;
	
	memcpy(response + response_size, msg + sizeof(ticket), msg_size - sizeof(ticket));
	
	response_size += msg_size - sizeof(ticket);
	response[response_size] = 0;
	
	printf("Recived and sent: \"%s\"\n", response + response_size - msg_size + sizeof(ticket));
	
	// Send the response
	sendto(fd, response, response_size, 0, (sockaddr *) &client_addr, sizeof(client_addr));
	return;
}

// TIME

void add_date_time(char* buff, int *len)
{
	struct tm tm = *localtime(&(time_t){time(NULL)});
	asctime_r(&tm, buff);
	*len +=  26;
}

void tcp_time(int fd, in_addr sender, in_addr server, int port)
{
	char msg[MSG_SIZE_SERVER];
	int res, msg_size;
	
	msg_size = 0;
	ticket t;
	
	// Read the ticket
	res = read_ticket(fd, &t);
	if(res != sizeof(ticket))
		return;
	
	// Check the ticket
	res = validate_ticket(t, sender, server, port);
	if(res < 0)
	{
		invalid_ticket_action_tcp(fd, res, &t, msg, sender);
		return;
	}
	
	// Create the response
	t.flag = FLAG_SERVER;
	
	memcpy(msg + msg_size, &t, sizeof(ticket));
	msg_size += sizeof(ticket);
	
	memcpy(msg + msg_size, TIME_HEADER, TIME_HEADER_SIZE);
	msg_size += TIME_HEADER_SIZE;
	
	add_date_time(msg + msg_size, &msg_size);
	
	// Send the response
	if(write_tcp(fd, msg, msg_size) != msg_size)
	{
		perror("write_tcp");
		return;
	}
	
	printf("Sent current date and time: %s", msg + sizeof(ticket) + TIME_HEADER_SIZE);
}

void udp_time(int fd, sockaddr_in client_addr, socklen_t len, in_addr server, int port)
{
	char response[MSG_SIZE_SERVER + ECHO_HEADER_SIZE + sizeof(ticket)];
	int res, response_size, msg_size;
	
	ticket t;
	
	msg_size = recvfrom(fd, &t, sizeof(ticket), 0, (sockaddr *) &client_addr, &len);
	if(msg_size < sizeof(ticket)) return;

	// Check the ticket
	res = validate_ticket(t, client_addr.sin_addr, server, port);
	if(res < 0)
	{
		invalid_ticket_action_udp(fd, res, &t, response, client_addr);
		return;
	}
	
	// Create the response
	t.flag = FLAG_SERVER;
	response_size = 0;
	
	memcpy(response + response_size, &t, sizeof(ticket));
	response_size += sizeof(ticket);
	
	memcpy(response + response_size, TIME_HEADER, TIME_HEADER_SIZE);
	response_size += TIME_HEADER_SIZE;
	
	add_date_time(response + response_size, &response_size);
	
	printf("Sent current date and time: %s", response + sizeof(ticket) + TIME_HEADER_SIZE);
	
	// Send the response
	sendto(fd, response, response_size, 0, (sockaddr *) &client_addr, sizeof(client_addr));
	return;
}

#endif
