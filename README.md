# File Transfer Web Server and Client (C)
## Overview
This repository contains a basic file transfer web server and client, implemented in C. It facilitates sending and receiving files via the command line, and is designed to work on both Windows and Linux platforms.

## Prerequisites
- GCC compiler
- Make

## Installation
Clone the repository:
```bash
git clone https://github.com/rullo24/Senfy.git
cd Senfy
```

## Building the project:
### Client
```bash
cd client
make
```
### Server
```bash
cd server 
make
```
NOTE: The Makefiles have been created to auto compile based on the OS that they are being run on

## Usage - Client
```bash
cd client
./recv_client -p <port> -i <ip_address> -f <location_to_save_file>
```

## Usage - Server
```bash
cd server
./send_server -p <port> -f <file_to_send>
```

## Troubleshooting
- Check for network or firewall issues that may block connections.
- Ensure the server is running before attempting to send or receive files.
- Verify that the server address and port are correctly specified.
