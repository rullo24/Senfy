#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <windows.h>
#include <stdbool.h>

#define BUFFER_MAX_SIZE 1024
#define MAX_NUM_ACTIVE_CONNS 5
#define BYTE_SIZE 1
#define CUST_MAX_PATH 260

typedef struct { 
    char port_string[8]; 
    int port_int;
    char ip_address_string[16];
    char save_file_loc[CUST_MAX_PATH];
} client_nec_args;

int check_arguments(int argc, char* argv[], client_nec_args *p_confirmed_arguments);
int new_file_location_valid(char *new_file_save_loc, size_t size_new_file_save_loc);
int recv_file_from_server(SOCKET sockfd, const char* save_file_loc);
void print_help();

int main(int argc, char *argv[]) {
    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Failed: Winsock initialization, Error Code: %d\n", WSAGetLastError());
        return -1;
    }   

    client_nec_args confirmed_arguments = {.port_string="", .port_int=-1, .save_file_loc=""}; // initialise default
    int argument_check_status = check_arguments(argc, argv, &confirmed_arguments);
    if (argument_check_status != 0) {
        WSACleanup();
        return -1; // error status already printed within function
    }

    // socket create and verification
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        fprintf(stderr, "Failed: socket creation\n");
        WSACleanup();
        return -1;
    } else {
        printf("Success: socket creation\n");
    }

    // storing server address info
    struct sockaddr_in server_addr; 
    memset(&server_addr, 0, sizeof(server_addr)); // zeroing all bytes
 
    // assigning IP and PORT numbers
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(confirmed_arguments.ip_address_string);
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Failed: converting IPv4 address string to valid IPv4\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }
    server_addr.sin_port = htons(confirmed_arguments.port_int);
 
    // connect the client socket to server socket
    struct sockaddr* p_serv_addr = (struct sockaddr*)&server_addr; // typecast from sockaddr_in to sockaddr pointer
    printf("attempting connection...\n");
    if (connect(sockfd, p_serv_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Failed: connection to the server\n");
        closesocket(sockfd);
        WSACleanup();
        return -1;
    } else {
        printf("Success: connected to the server\n");
    }
 
    // saving the file that is sent from the server
    int recv_result = recv_file_from_server(sockfd, confirmed_arguments.save_file_loc);
    if (recv_result != 0) {
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    // close the socket after successful transfer
    closesocket(sockfd);
    WSACleanup();
}

int check_arguments(int argc, char* argv[], client_nec_args *p_confirmed_arguments) {
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
            } else if (strncmp(argv[index], "-i", 2) == 0) { // checking if file flag provided
                char *ip_arg = argv[index+1];
                if (strlen(ip_arg) > 15) {
                    fprintf(stderr, "Failed: provided ip address too big\n");
                    return -1;
                }
                strncpy(p_confirmed_arguments->ip_address_string, ip_arg, 15); // copy required as going from char* --> char[]
            } else if (strncmp(argv[index], "-f", 2) == 0) { // checking if file flag provided
                char *file_arg = argv[index+1];
                if (strlen(file_arg) > CUST_MAX_PATH) {
                    fprintf(stderr, "Failed: provided a file location that exceeds the max size\n");
                    return -1;
                }
                strncpy(p_confirmed_arguments->save_file_loc, file_arg, CUST_MAX_PATH); // copy required as going from char* --> char[]
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

    // checking if save location is available --> check if save dir exists
    int new_file_loc_valid_result = new_file_location_valid(p_confirmed_arguments->save_file_loc, strlen(p_confirmed_arguments->save_file_loc));
    if (new_file_loc_valid_result != 0) {
        fprintf(stderr, "Failed: new file location is invalid\n");
        return -1;
    }

    return 0;
}

int new_file_location_valid(char *new_file_save_loc, size_t size_new_file_save_loc) {
    char dir_path[size_new_file_save_loc]; 
    strncpy(dir_path, new_file_save_loc, size_new_file_save_loc); // copying string to dir_path as to avoid messing with file loc
   
    const char *last_slash_for_dir = strrchr(dir_path, '\\'); // gets a pointer to the last slash
        
    if (last_slash_for_dir != NULL) {
        last_slash_for_dir = '\0'; // null-terminate the dir string
    } else {
        fprintf(stderr, "Failed: invalid string provided for save location\n");
        return -1;
    }

    // checking if the parent directory to new location is valid
    DWORD file_attr = GetFileAttributes(dir_path);
    if (file_attr == INVALID_FILE_ATTRIBUTES || !(file_attr & FILE_ATTRIBUTE_DIRECTORY)) {
        fprintf(stderr, "Failed: invalid location provided as new save loc\n");
        return -1;
    }

    return 0;
}

int recv_file_from_server(SOCKET sockfd, const char* save_file_loc) {
    FILE *p_file = fopen(save_file_loc, "wb");
    if (p_file == NULL) {
        fprintf(stderr, "Failed: opening save location new file\n");
        return -1;
    } else {
        printf("Success: save location new file opened\n");
    }

    // receiving the file from the server
    char buffer[BUFFER_MAX_SIZE];
    int num_bytes_recv; // signed int
    int flags = 0;

    while ((num_bytes_recv = recv(sockfd, buffer, BUFFER_MAX_SIZE, flags)) > 0) { // receiving file chunks from connection
        if (num_bytes_recv < 0) { // a negative value is returned from recv() if an error occurs
            fprintf(stderr, "Failed: receiving file\n");
            fclose(p_file);
            return -1;
        }
        size_t unsigned_num_bytes_recv = (size_t)num_bytes_recv; // signed int --> unsigned int
        if (fwrite(buffer, 1, unsigned_num_bytes_recv, p_file) != unsigned_num_bytes_recv) { // writing the received bytes to the file pointer
            fprintf(stderr, "Failed: writing to new file\n");
            fclose(p_file);
            return -1;
        }
    }
    printf("Success: receiving file\n");

    fclose(p_file);
    return 0;
}

void print_help() {
    char *basic_layout_help = "Layout: ./program.exe <-flag> <flag_correspondent>\n";
    char *port_help = "Port: -p <port_num>\n";
    char *ip_addr_help = "IPv4: -i <connect_ip>\n";
    char *file_choose_help = "File: -f <save_file_loc>\n";

    printf("=============\n");
    printf("%s", basic_layout_help);
    printf("%s", port_help);
    printf("%s", ip_addr_help);
    printf("%s", file_choose_help);
    printf("=============\n");
}

