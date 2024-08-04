#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h> // For _access

#define BUFFER_MAX_SIZE 1024
#define MAX_NUM_ACTIVE_CONNS 5
#define BYTE_SIZE 1
#define CUST_MAX_PATH 260

typedef struct { 
    char port_string[10]; 
    int port_int;
    char filename_string[CUST_MAX_PATH];
} server_nec_args;

int check_arguments(int argc, char* argv[], server_nec_args *p_confirmed_arguments);
void print_help();
int send_file_to_client(SOCKET connfd, const char* filename);

int main(int argc, char* argv[]) {
    server_nec_args confirmed_arguments = {.port_string="", .port_int=-1, .filename_string=""}; // initialise default
    int argument_check_status = check_arguments(argc, argv, &confirmed_arguments);
    if (argument_check_status != 0) {
        return -1; // error status already printed within function
    }

    // Initialize Winsock
    WSADATA wsa;
    int wsaInitResult = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaInitResult != 0) {
        fprintf(stderr, "Failed: WSAStartup failed with error %d\n", wsaInitResult);
        return -1;
    }
  
    // Socket create and verification
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        fprintf(stderr, "Failed: Socket Created\n");
        WSACleanup();
        return -1;
    } else {
        printf("Success: Socket Created\n");
    }

    // fills all bytes with zeroes
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr)); 

    // assigning IP and PORT numbers
    serv_addr.sin_family = AF_INET; // Setting the connection family to IPv4
    serv_addr.sin_addr.s_addr = INADDR_ANY; // Allowing connection to any ip address (from server)
    serv_addr.sin_port = htons(confirmed_arguments.port_int); // translates a short integer from host byte order to network byte order

    // Binding newly created socket to the given IP
    struct sockaddr* p_serv_addr = (struct sockaddr*)&serv_addr; // typecast from sockaddr_in to sockaddr pointer
    if ((bind(sockfd, p_serv_addr, sizeof(serv_addr))) != 0) { // If bind unsuccessful
        fprintf(stderr, "Failed: Socket Bind\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    } else {
        printf("Success: Socket Bind\n");
    }

    // Now server is ready to listen and verify
    if ((listen(sockfd, MAX_NUM_ACTIVE_CONNS)) != 0) {
        fprintf(stderr, "Failed: Listening\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    } else {
        printf("Success: Listening\n");
    }

    // accept the data packet from client and verify
    struct sockaddr_in client_info; // store addr info from connected client
    int size_client_info = sizeof(client_info); // storing byte size of addr info struct
    struct sockaddr* p_client_info = (struct sockaddr*)&client_info; // typecast from sockaddr_in to sockaddr pointer

    // accept and store client addr info in client_info --> return new socket file descriptor
    SOCKET connfd = accept(sockfd, p_client_info, &size_client_info); 
    if (connfd == INVALID_SOCKET) {
        fprintf(stderr, "Failed: Server Acceptance\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    } else {
        printf("Success: Server Acceptance\n");
    }

    // communicate between client and server (only connfd socket required)
    int send_file_result = send_file_to_client(connfd, confirmed_arguments.filename_string);
    if (send_file_result != 0) { // failed to send file
        closesocket(sockfd);
        closesocket(connfd);
        WSACleanup();
        return -1;
    }

    // once communication finished, close the connection socket
    closesocket(connfd);
    WSACleanup();
    return 0;
}

int check_arguments(int argc, char* argv[], server_nec_args *p_confirmed_arguments) {
    // checking provided argument flags
    if (argc == 1) { // responding to no arguments
        print_help();
        return 1;
    } else if (argc == 2) { // checking if help flag provided
        if (strncmp("--help", argv[1], 6) == 0) { 
            print_help();
            return 1;
        }
    }

    // looping over all provided arguments for program flag activation
    for (int index=0; index<argc; index++) {
        bool current_arg_is_last = (index+1 >= argc); // avoiding buffer overflow

        if (!current_arg_is_last) { // skipping the last argument (if a flag is provided in the last, it will not have a valid next argument)
            size_t current_arg_len = strlen(argv[index]); 
            if (current_arg_len < 2) { // checking the size of the current char (ensuring not overflowing when comparing)
                fprintf(stderr, "Failed: provided an invalid flag\n");
                return -1;
            }

            if (strncmp(argv[index], "-p", 2) == 0) { // checking if port flag provided
                char *port_arg = argv[index+1];
                if (strlen(port_arg) > 5) {
                    fprintf(stderr, "Failed: provided port too big\n");
                    return -1;
                }
                strncpy(p_confirmed_arguments->port_string, port_arg, 5); // copy required as going from char* --> char[]
            } else if (strncmp(argv[index], "-f", 2) == 0) { // checking if file flag provided
                char *file_arg = argv[index+1];
                if (strlen(file_arg) > CUST_MAX_PATH) {
                    fprintf(stderr, "Failed: provided a file location that exceeds the max size\n");
                    return -1;
                }
                strncpy(p_confirmed_arguments->filename_string, file_arg, CUST_MAX_PATH); // copy required as going from char* --> char[]
            }
        }
    }

    // checking validity of provided port
    int port_digits = atoi(p_confirmed_arguments->port_string);
    if (port_digits == 0) {
        fprintf(stderr, "Failed: invalid port provided\n");
        return -1;
    }
    p_confirmed_arguments->port_int = port_digits;

    if (p_confirmed_arguments->port_int > 65535) { // checking port validity
        fprintf(stderr, "Failed: port value out of bounds (>16-bits)\n");
        return -1;
    }

    // checking if filename exists
    if (_access(p_confirmed_arguments->filename_string, 0) == -1) {
        fprintf(stderr, "Failed: file does not exist on the local computer\n");
        return -1;
    }

    return 0;
}

void print_help() {
    char *basic_layout_help = "Layout: ./program.exe <-flag> <flag_correspondent>\n";
    char *port_help = "Port: -p <port_num>\n";
    char *file_choose_help = "File: -f <file_loc>\n";

    printf("=============\n");
    printf("%s", basic_layout_help);
    printf("%s", port_help);
    printf("%s", file_choose_help);
    printf("=============\n");
}

// sending file to client
int send_file_to_client(SOCKET connfd, const char* filename) {
    FILE *p_file = fopen(filename, "rb");
    if (p_file == NULL) {
        fprintf(stderr, "Failed: locating local file\n");
        return -1;
    } else {
        printf("Success: locating local file\n");
    }

    char file_send_buffer[BUFFER_MAX_SIZE]; // file sent in chunks of BUFFER_MAX_SIZE
    int num_bytes_read;
    int connfd_send_flags = 0; // no "special" flags for file send

    while ((num_bytes_read = fread(file_send_buffer, BYTE_SIZE, BUFFER_MAX_SIZE, p_file)) > 0) {
        if (send(connfd, file_send_buffer, num_bytes_read, connfd_send_flags) < 0) {
            fprintf(stderr, "Failed: sending file\n");
            fclose(p_file); // closing file pointer before exiting scope
            return -1;
        } else {
            printf("Success: sending file\n");
        }
    }

    fclose(p_file); // closing the pointer to the open file
    return 0;
}