# Simple Authentication and Services Servers

The project contains:
* a ticketing server,
* tcp and udp servers of echo and time services,
* a client.

The client can only access services using a correct ticket. 

## Ticket requesting procedure

### Communication protocool 
The protocol is based on UDP, however with the source address being obligatory.
Basic packets contain only a flag, which informs about the purpuse of communication:
* FLAG_GET_ADDR: request to send the ticket server IP address,
* FLAG_TS_ADDR: sending the ticket server IP address,
* FLAG_GET_TICKET: ticket request,
* FLAG_TS_TICKET: sending the ticket,
* FLAG_ERROR: error during issuing of the ticket.

Ticket request requires additional information about the services that will be accessed and the authorization data used by the client. This data is encrypted.  

### Ticket 
The ticket contains simple information about the client and the service. 
Additionaly the ticket is only valid for a limited amount of time.
The structure is as simple as possible:
```
struct{ 
  in_addr sender_address; 
  time_t expire;
  in_addr server_address; 
  int server_port; 
};

```

### Client side procedure
1. Broadcast a message (UDP) requesting ticketing server address.
2. Wait for a response, if time-out occurs return to step 1.
3. Send a ticket request (UDP).
4. Wait for a response, if time-out occurs return to step 1.

### Server side
The server is responsible for the verification and creation of tickets. 

## Usage of the service by the client
Comunication protocol header contains two fields: the flag and the ticket. 
The flag informs about the reason for the communication (request for a service, result of the service, invalid ticket, ticket no longer valid). 
