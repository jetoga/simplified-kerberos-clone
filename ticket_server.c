//Tickets server implementation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "defines.h"
#include "rsa.h"

//Helper macro
#define checkF(val, flag, mask) (((val ^ flag) & mask) == 0) ? 1 : 0

//Global controls for threads
char debugMode = 0;
pthread_mutex_t mutex;
//Auth db
struct auth authdb[64];
int users_count = 0;

void *server_main_loop(void *args)
{
    //Socket descriptor
    int sock = *((int *)args);
    //Recived data buffer
    ticket_request request;
    //Decrypted request
    decrypted_ticket_request dtr; 
    //Ticket to send
    decrypted_ticket tick;
    //Encrypted ticket
    ticket et;
    //Sender address
    struct sockaddr_storage senderAddr;
    //Sender address length
    socklen_t addrLen;
    //Recived bytes
    int recvBytes;
    //Counter
    int i;

    addrLen = sizeof(senderAddr);

    //While true (main thread stopps this one)
    while (1)
    {
        if (debugMode)
            printf("Waiting for connection...\n");
        recvBytes = recvfrom(sock, &request, sizeof(request), 0, (struct sockaddr *)&senderAddr, &addrLen);
        if (debugMode)
        {
            printf("Recived connection...\n");
            if(senderAddr.ss_family == AF_INET)
                printf("Connection from %s\n", inet_ntoa(((struct sockaddr_in *)&senderAddr)->sin_addr));
        }
        if (recvBytes == sizeof(char))
        {
            if (debugMode)
                printf("One byte flag.\n");
            if (checkF(request.flag, FLAG_GET_ADDR, 0xFF)) //Get address request
            {
                if (debugMode)
                    printf("Get address request recognized.\nSending response...\n");
                request.flag = FLAG_TS_ADDR;
                addrLen = sizeof(struct sockaddr_in);
                sendto(sock, &request, sizeof(char), 0, (struct sockaddr *)&senderAddr, addrLen);
            }
            else if (debugMode)
                printf("Not recognized request.\n");
        }
        else if(recvBytes == sizeof(request))
        {
            if(debugMode)
                printf("Flag with data.\n");
            if(checkF(request.flag, FLAG_GET_TICKET, 0xFF)) //Get ticket request
            {
                if(debugMode)
                    printf("Get ticket request recognized.\n");
                if(senderAddr.ss_family != AF_INET)
                {
                    if(debugMode)
                        printf("Recived not IPv4 address.\n");
                    continue;
                }
                if(private_decrypt(request.data, 128, &dtr) < 0)
                {
                    if(debugMode)
                        printf("Cannot decrypt recived data.\n");
                    continue;
                }
                if(*((int*)&(((struct sockaddr_in *)&senderAddr)->sin_addr)) != ((int*)&dtr)[0])
                {
                    if(debugMode)
                        printf("Sender address different than in ticket request.\n");
                    continue;
                }
                pthread_mutex_lock(&mutex);
                for(i = 0; i < users_count; ++i)
                {
                    if(strcmp(authdb[i].username, &((char *)&dtr)[16]) == 0 && strcmp(authdb[i].password, &((char*)&dtr)[56]) == 0)
                    {
                        if(*((int*)&authdb[i].server_address) == ((int*)&dtr)[1] && authdb[i].server_port == ((int*)&dtr)[2])
                        {
                            if(*((int*)&authdb[i].user_address) == ((int*)&dtr)[0])
                            {
                                if(debugMode)
                                    printf("Authentication successful.\n");
                                memcpy(&tick.sender_address, &((int*)&dtr)[0], sizeof(in_addr));
                                memcpy(&tick.server_address, &((int*)&dtr)[1], sizeof(in_addr));
                                tick.server_port = ((int*)&dtr)[2];
                                tick.expire = time(0) + ((int*)&dtr)[3];
                                et.flag = FLAG_TS_TICKET;
                                if(sign(&tick, sizeof(decrypted_ticket), et.data) != 128)
                                {
                                    if(debugMode)
                                        printf("Cannot sign ticket.\n");
                                    continue;
                                }
                                addrLen = sizeof(struct sockaddr_in);
                                sendto(sock, &et, sizeof(et), 0, (struct sockaddr *)&senderAddr, addrLen);
                                break;
                            }
                        }
                    }
                }
                pthread_mutex_unlock(&mutex);
                if(i == users_count)
                {
                    if(debugMode)
                        printf("Authentication failed.\n");
                    et.flag = FLAG_ERROR;
                    addrLen = sizeof(struct sockaddr_in);
                    sendto(sock, &et, sizeof(char), 0, (struct sockaddr *)&senderAddr, addrLen);
                }
            }
            else if(debugMode)
                printf("Not recognized request.\n");
        }
        else if(debugMode)
            printf("Not proper data size.\n");
    }
}

int main(int argc, char *argv[])
{
    //Ticket server address only IPv4
    struct sockaddr_in serverAddr;
    //Server socket descriptor
    int socketfd;
    //Server main loop thread
    pthread_t mainLoop;
    //Command buffer
    char commandBuff[255];
    //Counter
    int i, j, k, l;

    //Default server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(8000);

    //Process arguments
    if (argc == 2)
    {
        serverAddr.sin_port = htons((short)atoi(argv[1]));
    }
    else if (argc == 3)
    {
        serverAddr.sin_port = htons((short)atoi(argv[1]));
        serverAddr.sin_addr.s_addr = inet_addr(argv[2]);
    }
    else if (argc != 1)
    {
        printf("Unknown arguments.\nUsage:\n%s <port> <address>\nIf address not specified INADDR_ANY is used.\nIf port not specified port 8000 is used.\n", argv[0]);
        return 0;
    }

    //Create socket
    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        printf("Server error - cannot create socket.\n");
        return 0;
    }

    //Bind socket
    if (bind(socketfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0)
    {
        printf("Server error - cannot bind socket.\n");
        close(socketfd);
        return 0;
    }

    //Create mutex
    if (pthread_mutex_init(&mutex, NULL) != 0)
    {
        printf("Server error - cannot create mutex.\n");
        close(socketfd);
        return 0;
    }

    //Create main loop thread
    if (pthread_create(&mainLoop, NULL, &server_main_loop, (void *)&socketfd) != 0)
    {
        printf("Server error - cannot start main server loop thread.\n");
        close(socketfd);
        return 0;
    }

    //Process input commands while main loop working in bg
    printf("Server started!\nYou can type commands now\nMax command length is 254 chars.\nFor help type 'help'.\n");
    do
    {
        memset(commandBuff, 0, sizeof(char) * 255);
        printf(">");
        scanf("%s", commandBuff);

        if (strcmp(commandBuff, "help") == 0)
        {
            printf("Tickets server v1.0.0\n");
            printf("Available commands:\n");
            printf("addusr\t-\tadds user to internal auth db\n");
            printf("debug\t-\tturns debug mode on or off\n");
            printf("help\t-\tshows this help message\n");
            printf("rmusr\t-\tremoves user from internal auth db\n");
            printf("stop\t-\tshutdowns the server\n");
            printf("listusr\t-\tshows users from internal auth db\n");
        }
        else if (strcmp(commandBuff, "debug") == 0)
        {
            pthread_mutex_lock(&mutex);
            debugMode = !debugMode;
            pthread_mutex_unlock(&mutex);
            printf(debugMode ? "Debug mode enabled.\n" : "Debug mode disabled.\n");
        }
        else if (strcmp(commandBuff, "addusr") == 0)
        {
            pthread_mutex_lock(&mutex);
            if (users_count > 64)
            {
                printf("Auth db is full!\n");
                continue;
            }
            else
                printf("Auth db state (users count / max users): %d / 64\n", users_count);
            printf("Enter username (max 39 chars):\n");
            scanf("%s", authdb[users_count].username);
            printf("Enter password (max 39 chars):\n");
            scanf("%s", authdb[users_count].password);
            printf("Enter user address (IPv4):\n");
            memset(commandBuff, 0, sizeof(char) * 255);
            scanf("%s", commandBuff);
            authdb[users_count].user_address.s_addr = inet_addr(commandBuff);
            printf("Enter allowed service server address (IPv4):\n");
            memset(commandBuff, 0, sizeof(char) * 255);
            scanf("%s", commandBuff);
            authdb[users_count].server_address.s_addr = inet_addr(commandBuff);
            printf("Enter allowed service port:\n");
            scanf("%d", &authdb[users_count++].server_port);
            pthread_mutex_unlock(&mutex);
            printf("User added succesfully.\n");
        }
        else if (strcmp(commandBuff, "rmusr") == 0)
        {
            pthread_mutex_lock(&mutex);
            memset(commandBuff, 0, sizeof(char) * 255);
            printf("Enter username of user to remove:\n");
            scanf("%s", commandBuff);
            for (i = 0; i < users_count; ++i)
                if (strcmp(authdb[i].username, commandBuff) == 0)
                    break;
            if (i == users_count)
            {
                printf("User not found\n");
                pthread_mutex_unlock(&mutex);
                continue;
            }
            for (; i < users_count - 1; ++i)
                authdb[i] = authdb[i + 1];
            --users_count;
            pthread_mutex_unlock(&mutex);
            printf("User removed.\n");
        }
        else if (strcmp(commandBuff, "listusr") == 0)
        {
            pthread_mutex_lock(&mutex);
            printf("Nr   Username            Password            Address        ServiceAddress ServicePort\n");
            for (i = 0; i < users_count; ++i)
            {
                memset(commandBuff, 0, sizeof(char) * 255);
                memcpy(commandBuff, inet_ntoa(authdb[i].user_address), strlen(inet_ntoa(authdb[i].user_address)) + 1);
                printf("%-5d%-20s%-20s%-15s%-15s%-11d\n", i + 1, authdb[i].username, authdb[i].password, commandBuff, inet_ntoa(authdb[i].server_address), authdb[i].server_port);
            }
            pthread_mutex_unlock(&mutex);
        }

    } while (strcmp(commandBuff, "stop") != 0);

    //Shutdown main loop thread
    pthread_cancel(mainLoop);
    pthread_join(mainLoop, NULL);

    pthread_mutex_destroy(&mutex);

    close(socketfd);

    printf("Server stopped!\n");

    return 0;
}
