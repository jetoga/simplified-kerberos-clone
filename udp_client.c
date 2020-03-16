#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "proto.h"

#define MAXLINE 1000

int main(int argc, char *argv[])
{
	int fd;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	in_addr server;
	socklen_t addr_len;

	char msg[MAXLINE];
	ssize_t msg_size = 0;

	struct timeval tv;
	int broadcast = 1;
	int err;

	ticket t;
	in_addr tsaddr;

	if (argc < 2 || argc > 10)
	{
		printf("Usage:\nEcho service: %s Client_IP Client_port Tickets_port Service_IP Service_port Username Password Valid_time [MSG]\nTime service: %s Client_IP Client_port Tickets_port Service_IP Service_port Username Password Valid_time\n", argv[0], argv[0]);
		return -1;
	}

	// Socket creation
	inet_pton(AF_INET, argv[4], &server);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket");
		return -1;
	}

	// Timeout
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		perror("setsockopt");
		close(fd);
		return -1;
	}

	// Broadcast
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
	{
		perror("setsockopt (broadcast)");
		close(fd);
		return -1;
	}

	// Set client address
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(atoi(argv[2]));
	client_addr.sin_addr.s_addr = inet_addr(argv[1]);

	// Binding
	if (bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) != 0)
	{
		perror("binding");
		close(fd);
		return -1;
	}

	// Get ticket server address and ticket
	do
	{
		while (getTSAddress(fd, atoi(argv[3]), &tsaddr) != 0);
		err = getTicket(fd, atoi(argv[3]), client_addr.sin_addr, tsaddr, server, atoi(argv[5]), atoi(argv[8]), argv[6], argv[7], &t);
		switch (err)
		{
		case ERROR_USERNAME:
			printf("Username too long.\n");
			close(fd);
			return -1;
		case ERROR_PASSWORD:
			printf("Password too long.\n");
			close(fd);
			return -1;
		case ERROR_ENCRYPT:
			printf("Cannot encrypt ticket.\n");
			close(fd);
			return -1;
		case ERROR_RCV_SIZE:
			printf("Data not recived or wrong size.\n");
			break;
		case ERROR_RESPONSE:
			printf("Not recognized response.\n");
			break;
		case ERROR_VERIFY:
			printf("Recived ticket verification failed.\n");
			break;
		case ERROR_AUTH:
			printf("Authentication failed.\n");
			close(fd);
			return -1;
		}
	} while (err != 0);

	t.flag = FLAG_USER;

	// Ustawianie danych o serwerze
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[5]));
	server_addr.sin_addr = server;

	addr_len = sizeof(server_addr);

	// Message sending
	memset(&(server_addr.sin_zero), 0, 8);
	memcpy(msg, &t, sizeof(ticket));
	msg_size += sizeof(ticket);

	if (argc == 10)
	{
		memcpy(msg + sizeof(ticket), argv[9], strlen(argv[9]));
		msg[strlen(argv[9]) + sizeof(ticket)] = 0;
		msg_size += strlen(argv[9]);
	}

	if ((msg_size = sendto(fd, msg, msg_size, 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))) == -1)
	{
		perror("sendto");
		close(fd);
		return -1;
	}

	// Receive message
	msg_size = recvfrom(fd, msg, MAXLINE - 1, 0, (struct sockaddr *)&server_addr, &addr_len);
	if (argc == 9)
		msg_size -= 2;

	if (msg[0] == 2)
	{
		msg[msg_size] = 0;
		printf("%s\n", msg + sizeof(ticket));
	}
	if (msg[0] == 4)
		printf("Recived invalid ticket\n");
	if (msg[0] == 8)
		printf("Recived ticket timeout\n");

	// Close the socket
	close(fd);

	return 0;
}
