//Utility structures definition
#ifndef _DEFINES_H_
#define _DEFINES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

typedef struct in_addr in_addr;
typedef struct ticket ticket;
typedef struct decrypted_ticket decrypted_ticket;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct decrypted_ticket_request decrypted_ticket_request;
typedef struct ticket ticket_request;

//Flags defines (tickets server)
#define FLAG_GET_ADDR       0x80    //Get tickets server address
#define FLAG_TS_ADDR        0x40    //Recived tickets server address
#define FLAG_GET_TICKET     0x20    //Get ticket
#define FLAG_TS_TICKET      0x10    //Recived ticket
#define FLAG_ERROR          0xFF    //Cannot get ticket (authentication failed)
//Flags defines (clients and services)
#define FLAG_USER           0x01    //Client
#define FLAG_SERVER         0x02    //Service server
#define FLAG_TICKET_ERROR   0x04    //Recived ticket not valid
#define FLAG_TICKET_TIMEOUT 0x08    //Recived ticket timeout

#define	LISTEN_NUMBER 64
#define	MSG_SIZE_SERVER 512

#define	ECHO_PORT		9877
#define TIME_PORT		9123

//Protocol functions errors
#define ERROR_RCV_SIZE  -1  //Recived wrong size of data or not recived at all
#define ERROR_WRONG_IP  -2  //IP address in wrong version (IPv6 not IPv4)
#define ERROR_RESPONSE  -3  //Not expected response
#define ERROR_USERNAME  -4  //Username too long
#define ERROR_PASSWORD  -5  //Password too long
#define ERROR_ENCRYPT   -6  //Cannot encrypt data
#define ERROR_VERIFY    -7  //Verification (decryption) failed
#define ERROR_AUTH      -8  //Authentication failed

//Decrypted ticket request struct
struct decrypted_ticket_request
{
    in_addr sender_address;     //Sender address
    in_addr server_address;     //Requested service server address
    int server_port;            //Requested service server port
    time_t valid;               //Valid time
    char username[40];          //Client username
    char password[40];          //Client password
};

//Decrypted ticket struct
struct decrypted_ticket 
{
    in_addr sender_address;     //Sender address
    time_t expire;              //Ticket expiration time
    in_addr server_address;     //Allowed service server address
    int server_port;            //Allowed service server port
};

//Encrypted ticket struct
struct ticket
{
	char flag;
    char data[128];
};

//Authentication data struct
struct auth
{
    in_addr user_address;       //User address (from which user is allowed to connect)
    in_addr server_address;     //Service server address
    int server_port;            //Service server port
    char username[40];          //Username
    char password[40];          //User password
};

#endif