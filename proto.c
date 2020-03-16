#include "proto.h"

int getTSAddress(int sockfd, int port, in_addr *res)
{
    struct sockaddr_in to;
    socklen_t len = sizeof(to);
    struct sockaddr_storage sourceAddr;
    char flag = FLAG_GET_ADDR;
    int rec;
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    to.sin_port = htons(port);
    printf("Sending get address request...\n");
    sendto(sockfd, &flag, sizeof(char), 0, (struct sockaddr *)&to, len);
    rec = recvfrom(sockfd, &flag, sizeof(char), 0, (struct sockaddr *)&sourceAddr, &len);
    if(rec != sizeof(char))
        return ERROR_RCV_SIZE;
    if(((flag ^ FLAG_TS_ADDR) & 0xFF) == 0)
    {
        if(sourceAddr.ss_family != AF_INET)
            return ERROR_WRONG_IP;
        (*res).s_addr = ((struct sockaddr_in *)&sourceAddr)->sin_addr.s_addr;
        printf("Tickets server address obtained: %s\n", inet_ntoa(*res));
        return 0;
    }

    return ERROR_RESPONSE;
}

int getTicket(int sockfd, int port, in_addr sender_addr, in_addr ts_addr, in_addr service_addr, int service_port, time_t valid, char *username, char *password, ticket *res)
{
    struct sockaddr_in tsaddr;
    struct sockaddr_storage sender;
    decrypted_ticket_request dtr;
    ticket_request tr;
    int userLen = strlen(username);
    int passLen = strlen(password);
    socklen_t len = sizeof(tsaddr);
    int rec;
    decrypted_ticket dt;

    if(userLen >= 40)
        return ERROR_USERNAME;
    if(passLen >= 40)
        return ERROR_PASSWORD;
    
    dtr.sender_address = sender_addr;
    dtr.server_address = service_addr;
    dtr.server_port = service_port;
    dtr.valid = valid;
    memset(dtr.username, 0, sizeof(char) * 40);
    memset(dtr.password, 0, sizeof(char) * 40);
    memcpy(dtr.username, username, userLen + 1);
    memcpy(dtr.password, password, passLen + 1);

    if(public_encrypt(&dtr, sizeof(dtr), tr.data) != 128)
        return ERROR_ENCRYPT;

    tsaddr.sin_family = AF_INET;
    tsaddr.sin_port = htons(port);
    tsaddr.sin_addr = ts_addr;

    tr.flag = FLAG_GET_TICKET;

    sendto(sockfd, &tr, sizeof(tr), 0, (struct sockaddr *)&tsaddr, len);
    rec = recvfrom(sockfd, res, sizeof(ticket), 0, (struct sockaddr *)&sender, &len);
    if(rec == sizeof(char) && ((res->flag ^ FLAG_ERROR) & 0xFF) == 0)
        return ERROR_AUTH;
    if(rec != sizeof(ticket))
        return ERROR_RCV_SIZE;
    if(((res->flag ^ FLAG_TS_TICKET) & 0xFF) != 0)
        return ERROR_RESPONSE;

    return verify(res->data, 128, &dt) < 0 ? ERROR_VERIFY : 0;
}
