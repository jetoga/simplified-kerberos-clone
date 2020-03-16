#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "proto.h"
#include "ticket.h"

#define MAXLINE 1000

int main(int argc, char *argv[])
{
	int fd;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	in_addr server;
	socklen_t addr_len;

	char msg[MAXLINE];
	int msg_size = 0;
	int res;

	struct timeval tv;
	int broadcast = 1;
	int err;
	int proto_fd;

	ticket t;
	in_addr tsaddr;

	if (argc < 2 || argc > 10)
	{
		printf("Usage:\nEcho service: %s Client_IP Client_port Tickets_port Service_IP Service_port Username Password Valid_time [MSG]\nTime service: %s Client_IP Client_port Tickets_port Service_IP Service_port Username Password Valid_time\n", argv[0], argv[0]);
		return -1;
	}

	// Socket creation
	inet_pton(AF_INET, argv[4], &server);

	// Socket for ticket service
	if ((proto_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket (udp)");
		return -1;
	}

	//Timeout
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (setsockopt(proto_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		perror("setsockopt (udp timeout)");
		close(proto_fd);
		return -1;
	}

	//UDP Broadcast
	if (setsockopt(proto_fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
	{
		perror("setsockopt (udp broadcast)");
		close(proto_fd);
		return -1;
	}

	//Set client address
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(atoi(argv[2]));
	client_addr.sin_addr.s_addr = inet_addr(argv[1]);

	//Binding
	if (bind(proto_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) != 0)
	{
		perror("binding (udp)");
		close(proto_fd);
		return -1;
	}

	//Get ticket server address and get ticket
	do
	{
		while (getTSAddress(proto_fd, atoi(argv[3]), &tsaddr) != 0);
		err = getTicket(proto_fd, atoi(argv[3]), client_addr.sin_addr, tsaddr, server, atoi(argv[5]), atoi(argv[8]), argv[6], argv[7], &t);
		switch (err)
		{
		case ERROR_USERNAME:
			printf("Username too long.\n");
			close(proto_fd);
			return -1;
		case ERROR_PASSWORD:
			printf("Password too long.\n");
			close(proto_fd);
			return -1;
		case ERROR_ENCRYPT:
			printf("Cannot encrypt ticket.\n");
			close(proto_fd);
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
			close(proto_fd);
			return -1;
		}
	} while (err != 0);

	close(proto_fd);
	t.flag = FLAG_USER;

	//Tcp Socket
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("socket");
		return -1;
	}

	// Server info
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[5]));
	server_addr.sin_addr = server;

	addr_len = sizeof(server_addr);

	if (connect(fd, (sockaddr *)&server_addr, sizeof(sockaddr)) == -1)
	{
		perror("connect");
		close(fd);
		return -1;
	}

	if (write_tcp(fd, &t, sizeof(ticket)) != sizeof(ticket))
	{
		perror("send");
		close(fd);
		return -1;
	}

	if (argc == 10)
	{
		res = write_tcp(fd, argv[9], strlen(argv[9]));
		if (res != strlen(argv[9]))
		{
			perror("send");
			close(fd);
			return -1;
		}
	}

	shutdown(fd, SHUT_WR);

	printf("Received: \n");

	ticket recv;
	msg_size = 0;

	if (read_ticket(fd, &recv) != sizeof(ticket))
	{
		perror("ticket");
		close(fd);
		return -1;
	}

	if (recv.flag == 2)
	{
		while ((msg_size = read(fd, msg, MAXLINE - 1)) > 0)
		{
			msg[msg_size] = '\0';
			printf("%s", msg);
		}
		if (argc == 10)
			printf("\n");
	}
	if (recv.flag == 4)
		printf("Invalid ticket\n");
	if (recv.flag == 8)
		printf("Ticket timeout\n");

	close(fd);
	return 0;
}
