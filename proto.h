#ifndef _PROTO_H_
#define _PROTO_H_

#include <string.h>
#include "defines.h"
#include "rsa.h"

//Gets tickets server address.
int getTSAddress(int sockfd, int port, in_addr *res);

//Gets ticket for specified service.
int getTicket(int sockfd, int port, in_addr sender_addr, in_addr ts_addr, in_addr service_addr, int service_port, time_t valid, char *username, char *password, ticket *res);

#endif