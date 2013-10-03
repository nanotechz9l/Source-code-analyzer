#include <windows.h>
#include <winsock.h>

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>

#define BANNER "Welcome to SNOW\r\n\r\nUsername: "

int greet(SOCKET client, char* username)
{
    char buf[64];

    sprintf(buf, "Hello, %s.\r\n", username);

    send(client, buf, strlen(buf), 0);
    
    return 0;
}

WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
               LPSTR lpCmdLine, int nCmdShow)
{
    WORD RequiredVersion=0x0002;
    WSADATA WSAData;
    int WSAStartupErrorCode;
    SOCKET server, client;
    struct sockaddr_in server_addr, client_addr;
    int salen;
    
    if ((WSAStartupErrorCode = WSAStartup(RequiredVersion, &WSAData)))
        return -1;

    if ((server = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
        return -2;

    ZeroMemory(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(1974);
    
    if (bind(server, (struct sockaddr*)&server_addr, sizeof(server_addr)))
        return -3;

    if (listen(server, 5))
        return -4;
    
    while ((client = accept(server, (struct sockaddr*)&client_addr, &salen))) {
        char c[1], username[10000], password[10000];
        int n = 0;
        
        send(client, BANNER, strlen(BANNER), 0);

        while ((recv(client, c, 1, 0) > 0) && (n < 10000)) {
            if (c[0] == '\r')
                continue;
            if (c[0] == '\n')
                break;
            
            username[n++] = c[0];
        }

        greet(client, username);
        
        closesocket(client);
    }
}
