#include "server.h"
#include <string.h>

int main(int argc, char **argv)
{	
	int master_echo_fd, echo_fd, echo_udp_fd;
	int master_time_fd, time_fd, time_udp_fd;
	int time_port;
	int echo_port;
	int select_res, maxfdp;
	fd_set socket_set;
	socklen_t len;
	
	sockaddr_in client_addr, server_addr, server_addr_time;
	in_addr server;
	
	
	if(argc != 2)
	{
		printf("Usage: %s ip\n", argv[0]);
		return 0;
	}
	
	printf("Please enter echo port\n");
	scanf("%d", &echo_port);
	printf("Please enter time port\n");
	scanf("%d", &time_port);
	
	
	inet_pton(AF_INET, argv[1], &server);	
	
	if(make_master_socket(&master_echo_fd, &server_addr, sizeof(server_addr), echo_port) != 0) return -1;
	if(make_udp_socket(&echo_udp_fd, &server_addr, sizeof(server_addr), echo_port) != 0) return -1;
	
	if(make_master_socket(&master_time_fd, &server_addr_time, sizeof(server_addr_time), time_port) != 0) return -1;
	if(make_udp_socket(&time_udp_fd, &server_addr_time, sizeof(server_addr_time), time_port) != 0) return -1;

	printf("Server started\n");
	
	maxfdp = master_echo_fd > master_time_fd ? master_echo_fd : master_time_fd;
	maxfdp = maxfdp > echo_udp_fd ? maxfdp : echo_udp_fd;
	maxfdp = maxfdp > time_udp_fd ? maxfdp : time_udp_fd;
	maxfdp += 1;
	
	
	while(1)
	{
	
		FD_ZERO(&socket_set);
		
		FD_SET(master_echo_fd, &socket_set);
		FD_SET(echo_udp_fd, &socket_set);
		FD_SET(master_time_fd, &socket_set);
		FD_SET(time_udp_fd, &socket_set);
	
		if ( (select_res = select(maxfdp, &socket_set, NULL, NULL, NULL)) < 0)
		{
			if (errno == EINTR)
				continue;		
			else
			{
				perror("Select error");
				return -1;
			}
		}
		

		if (FD_ISSET(master_echo_fd, &socket_set))
		{
			len = sizeof(client_addr);
			echo_fd = accept(master_echo_fd, (sockaddr *) &client_addr, &len);
			
			if(echo_fd < 0)
			{
				perror("Child socket not created\n");
				continue;
			}
			
			if (fork() == 0)
			{
				close(master_time_fd);
				close(master_echo_fd);
				close(echo_udp_fd);
				close(time_udp_fd);
				
				tcp_echo(echo_fd, client_addr.sin_addr, server, echo_port);
				exit(0);
			}
			
			close(echo_fd);
		}

		if (FD_ISSET(master_time_fd, &socket_set))
		{
			len = sizeof(client_addr);
			time_fd = accept(master_time_fd, (sockaddr *) &client_addr, &len);
			
			if(time_fd < 0)
			{
				perror("Child socket not created\n");
				continue;
			}
			

			if (fork() == 0)
			{
				close(master_time_fd);
				close(master_echo_fd);
				close(echo_udp_fd);
				close(time_udp_fd);

				tcp_time(time_fd, client_addr.sin_addr, server, time_port);
				exit(0);
			}
			
			close(time_fd);
		}
		
		if (FD_ISSET(echo_udp_fd, &socket_set))
		{
			//printf("UDP\n");
			len = sizeof(client_addr);
			udp_echo(echo_udp_fd, client_addr, len, server, echo_port);
		}
		
		if (FD_ISSET(time_udp_fd, &socket_set))
		{
			len = sizeof(client_addr);
			udp_time(time_udp_fd, client_addr, len, server, time_port);
		}
	}
	return 0;
}
