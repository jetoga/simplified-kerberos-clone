#ifndef TICKET_H
#define TICKET_H

#include <errno.h>
#include <unistd.h>
#include "defines.h"
#include "rsa.h"

int validate_ticket(ticket source, in_addr sender, in_addr server, int port)
{
	time_t curr_time;
	decrypted_ticket t;
	int data[6];
	int result, field, counter;

	//printf("sender: %x\nservice: %x\n", sender, server);
	if(source.flag != FLAG_USER) return -1;
	//printf("Good flag\n");
	result = verify(source.data, 128, data);
	if(result < 0) return -1;
	//Repair data if necessary
	field = 0;
	counter = 0;
	while(field < 4)
	{
		if(counter > 5)
		{
			printf("Cannot repair decrypted data.\n");
			return -1;
		}
		if(data[counter] != 0)
			((int *)&t)[field++] = data[counter];
		++counter;
	}
	/*printf("Sender: %s\n", inet_ntoa(t.sender_address));
	printf("Server %s\n", inet_ntoa(t.server_address));
	printf("Port: %d\n", t.server_port);
	printf("Expire: %d\n", t.expire);*/
	//printf("verify ok\n");
	if(((int*)&t)[3] != port) return -1;
	//printf("Valid port\n");
	//printf("%d vs %d\n", t.sender_address.s_addr, sender.s_addr);
	if(t.sender_address.s_addr != sender.s_addr) return -1;
	//printf("%d vs %d\n", t.server_address.s_addr, server.s_addr);
	if(((int*)&t)[2] != *((int*)&server)) return -1;
	//printf("Valid sender\n");
	time(&curr_time);
	if(t.expire < curr_time) return -2;
	//printf("Valid time\n");
	return 0;
}

int write_tcp(int fd, void* buffer, int n)
{
	int b_written = 0;
	int res;
	
	while(b_written < n)
	{
		res = write(fd, buffer, n - b_written);
		if (res < 1)
		{
			if(errno != EINTR)
				return -1;
			else
				res = 0;
		}
		b_written += res;
	}
	
	return b_written;
}


int read_ticket(int fd, ticket *buffer)
{
	int b_read = 0;
	int res;
	
	while (b_read < sizeof(ticket))
	{
		res = read(fd, buffer + b_read, sizeof(ticket) - b_read);
		if (res < 1)
		{
			if(errno != EINTR)
				return -1;
			else
				res = 0;
		}
		b_read += res;
	}
	return sizeof(ticket);	
}

#endif
