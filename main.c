#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <netinet/sctp.h>
#include <errno.h>

/* Type lines return */
#define LINE_SUCCESS 		 0
#define LINE_ERROR_HOSTS_SET 1
#define LINE_ERROR_SYNTAX 	 2

/* Protocols */
#define UDP  1
#define TCP  2
#define SCTP 3

/* Colors */
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"

/* Utils */
#define ECHOMAX 16384
#define BUFSIZE 2048
#define CONFIG_SIZE 256
#define MAX_HOSTS 100

/* Declaration of thread condition variable and mutex */
pthread_mutex_t m; //= PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t c = PTHREAD_COND_INITIALIZER;
pthread_mutexattr_t attr;

int done = 0;
char message[ECHOMAX] = "";
int hosts_connected = 0;

typedef struct config {
	int protocol;
    unsigned hosts_are_setted;
    char hosts[MAX_HOSTS][17];
    char interface[8];
    char interface_address[INET_ADDRSTRLEN];
	unsigned port;
    int n_hosts;
} CONF;

CONF config[1];

/* Parse a line from config file. Return an error code or 0 for no error. */
int parse_config(char *buf, CONF *config) {
    char dummy[CONFIG_SIZE];
    if (sscanf(buf, " %s", dummy) == EOF) return LINE_SUCCESS; // success; blank line
    if (sscanf(buf, " %[#]", dummy) == 1) return LINE_SUCCESS; // success; comment
	if (sscanf(buf, " port = %s", dummy) == 1) {
        config->port = strtol(dummy, NULL, 10);
        return LINE_SUCCESS;
    }
    char hosts[15*MAX_HOSTS];
    if (sscanf(buf, " hosts = %s", hosts) == 1) {
        if (config->hosts_are_setted & LINE_ERROR_HOSTS_SET) return LINE_ERROR_HOSTS_SET; // error; host already set
        char *token = strtok(hosts, ",");
        int index = 0;
        while(token != NULL){
            bzero(config->hosts[index], 16);
            snprintf(config->hosts[index], sizeof(config->hosts[index]), "%s", token);
            printf("Host: [%i] %s\n", index, token);
            token = strtok(NULL, ",");
            index++;
        }
        config->n_hosts = index;
        config->hosts_are_setted |= LINE_ERROR_HOSTS_SET;
        return 0;
    }
    return LINE_ERROR_SYNTAX; // error; syntax error
}

/* Load config file to struct CONF. */
void load_config_file(char *filename) {
    FILE *f = fopen(filename, "r");
    char buf[CONFIG_SIZE];
    config->hosts_are_setted = 0u;
    int line_number = 0;
    while (fgets(buf, sizeof buf, f)) {
        ++line_number;
        int err = parse_config(buf, config);
        if (err)
            fprintf(stderr, "error line %d: %d\n", line_number, err);
    }
}

int send_tcpdump_output(int sock, int size_client_ports, int client_ports[size_client_ports]) {
    char *cmd = "sudo tcpdump --immediate-mode";    
    
    char line_tcpdump[BUFSIZE];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe.\n");
        return -1;
    }
    printf("Tcpdump started.\n");

    /* Determine numbers of lines from tcpdump to be sended */
    char lines_output_tcpdump[16384] = {0};
    int lines_per_message = 16;
    int index = 0;
    bzero(lines_output_tcpdump, 16384);

    struct sockaddr_in rem_addr;
    unsigned int sock_size = sizeof(rem_addr);
    bzero((char *)&rem_addr, sock_size);

    /* Get output of tcpdump and send */
    while (fgets(line_tcpdump, BUFSIZE, fp) != NULL) {
        if (index < lines_per_message) {
            index++;
            strcat(lines_output_tcpdump, line_tcpdump);
        }
        else {
            int size_lines = strlen(lines_output_tcpdump) + 1;
            for(int i = 0; i < config->n_hosts; i++) {
                rem_addr.sin_family = AF_INET;
                rem_addr.sin_addr.s_addr = inet_addr(config->hosts[i]);
                rem_addr.sin_port = htons(client_ports[i]);
                sendto(sock, lines_output_tcpdump, size_lines, 0, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
            }
            memset(lines_output_tcpdump, 0, 16384);
            index = 0;
        }
    }

    if (pclose(fp)) {
        printf("Command not found or exited with error status.\n");
        return -1;
    }

    return 0;
}

int send_tcpdump_output_tcp_sctp(size_t n_hosts, int client_sockets[n_hosts]) {
    char *cmd = "sudo tcpdump --immediate-mode";    
    
    char line_tcpdump[BUFSIZE];
    FILE *fp;

    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe.\n");
        return -1;
    }
    printf("Tcpdump started.\n");

    /* Determine numbers of lines from tcpdump to be sended */
    char lines_output_tcpdump[16384] = {0};
    int lines_per_message = 16;
    int index = 0;
    bzero(lines_output_tcpdump, 16384);

    /* Format hostname on message */
    char hostbuffer[256];
    gethostname(hostbuffer, sizeof(hostbuffer));
    strcat(hostbuffer, "\n");
    strcat(lines_output_tcpdump, hostbuffer);

    /* Get output of tcpdump and send */
    switch (config->protocol) {
        case TCP:
            while (fgets(line_tcpdump, BUFSIZE, fp) != NULL) {
                if (index < lines_per_message) {
                    index++;
                    strcat(lines_output_tcpdump, line_tcpdump);
                }
                else {
                    int size_lines = strlen(lines_output_tcpdump);
                    for(int i = 0; i < n_hosts; i++) {
                        send(client_sockets[i], &lines_output_tcpdump, size_lines, 0);
                    }
                    memset(lines_output_tcpdump, 0, 16384);
                    strcat(lines_output_tcpdump, hostbuffer);
                    index = 0;
                }
            }
            break;
        case SCTP:
            while (fgets(line_tcpdump, BUFSIZE, fp) != NULL) {
                if (index < lines_per_message) {
                    index++;
                    strcat(lines_output_tcpdump, line_tcpdump);
                }
                else {
                    int size_lines = strlen(lines_output_tcpdump) + 1;
                    for(int i = 0; i < n_hosts; i++) {
                        sctp_sendmsg(client_sockets[i], &lines_output_tcpdump, size_lines, NULL, 0, 0, 0, 0, 0, 0);
                    }
                    memset(lines_output_tcpdump, 0, 16384);
                    strcat(lines_output_tcpdump, hostbuffer);
                    index = 0;
                }
            }
            break;
    }

    if (pclose(fp)) {
        printf("Command not found or exited with error status.\n");
        return -1;
    }

    return 0;
}

/* Initialize a client */
void *clients(void* arg) {

    int index_host = *((int *) arg);
    free(arg);
    printf("Index host: %d\n", index_host);
    printf("Host: %s\n", config->hosts[index_host]);

	int sock;
	char line[ECHOMAX];

	struct sockaddr_in rem_addr;
    unsigned int sock_size = sizeof(rem_addr);
    bzero((char *)&rem_addr, sock_size);
	rem_addr.sin_family = AF_INET;
    rem_addr.sin_addr.s_addr = inet_addr(config->hosts[index_host]);
    rem_addr.sin_port = htons(config->port);

    /* Create sockets UDP, TCP or SCTP */
    switch (config->protocol) {
        case UDP:
            sock = socket(AF_INET, SOCK_DGRAM, 0);
            break;
        case TCP:
            sock = socket(AF_INET, SOCK_STREAM, 0);
            break;
        case SCTP:
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
            break;
    }

    if (sock < 0) {
        printf("Socket creation error.\n");
        return 0;
    }

	/* Create a connection to server if protocol is TCP or SCTP */
	switch (config->protocol) {
		case UDP:
			break;
		case TCP:
		case SCTP:
            sleep(10);
            if (connect(sock, (struct sockaddr *) &rem_addr, sizeof(rem_addr)) < 0) {
                printf("Error on connecting stream socket.\n");
                exit(1);
            }
            else {
                printf("Connected.\n");
            }
			break;
	}

    char cpy[ECHOMAX];
	do  {
        switch (config->protocol) {
            case UDP:
                if (strcmp(cpy, "tcpdump") != 0) {
                    pthread_mutex_lock(&m) ;
                    while(done == 0)
                        pthread_cond_wait(&c ,&m);
                    strcpy(cpy, message);
                    sendto(sock, cpy, strlen(cpy), 0, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
                    pthread_mutex_unlock(&m);
                }
                else if (strcmp(cpy, "tcpdump") == 0) {
                    char ip_address_client[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(rem_addr.sin_addr), ip_address_client, INET_ADDRSTRLEN);

                    recvfrom(sock, line, ECHOMAX, 0, (struct sockaddr *)&rem_addr, &sock_size);

                    printf("%sIP: %s\n", KGRN, ip_address_client);
                    printf("%s%s\n", KYEL, line);
                }
                break;
            case TCP:
                if (strcmp(cpy, "tcpdump") != 0) {
                    pthread_mutex_lock(&m);
                    while(done == 0)
                        pthread_cond_wait(&c ,&m);
                    
                    strcpy(cpy, message);
                    send(sock, &cpy, strlen(cpy) + 1, 0);
                    pthread_mutex_unlock(&m);
                    sleep(2);
                }
                else if (strcmp(cpy, "tcpdump") == 0) {
                    char ip_address_client[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(rem_addr.sin_addr), ip_address_client, INET_ADDRSTRLEN);

                    recv(sock, &line, sizeof(line) + 1, 0);

                    if(strcmp(line, "") != 0) {
                        printf("%sIP: %s\n", KGRN, ip_address_client);
                        printf("%s%s\n", KYEL, line);
                        bzero(line, ECHOMAX);
                    }
                }
                break;
            case SCTP:
                if (strcmp(cpy, "tcpdump") != 0) {
                    pthread_mutex_lock(&m);
                    while(done == 0)
                        pthread_cond_wait(&c ,&m);
                    
                    strcpy(cpy, message);
                    sctp_sendmsg(sock, &cpy, strlen(cpy) + 1, NULL, 0, 0, 0, 0, 0, 0);
                    pthread_mutex_unlock(&m);
                    sleep(2);
                }
                else if (strcmp(cpy, "tcpdump") == 0) {
                    char ip_address_client[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(rem_addr.sin_addr), ip_address_client, INET_ADDRSTRLEN);
                    sctp_recvmsg(sock, &line, sizeof(line), NULL, 0, 0, 0);

                    if(strcmp(line, "") != 0) {
                        printf("%sIP: %s\n", KGRN, ip_address_client);
                        printf("%s%s\n", KYEL, line);
                        bzero(line, ECHOMAX);
                    }
                }
                break;
        }
	} while(strcmp(line, "exit") != 0);

    /* Close remote socket */
	close(sock);

  return NULL;
}

/* Initialize server listening */
void *server(void *vargp) {

	int sock, loc_newsockfd;
    socklen_t size;
	char line[ECHOMAX];

	struct sockaddr_in loc_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons(config->port),
	};

	struct sctp_initmsg initmsg = {
		.sinit_num_ostreams = 5,
  		.sinit_max_instreams = 5,
  		.sinit_max_attempts = 4,
        .sinit_max_init_timeo = 60
	};

   	/* Create socket UDP, TCP or SCTP */
    switch (config->protocol) {
		case UDP:
            sock = socket(AF_INET, SOCK_DGRAM, 0);
			break;
		case TCP:
            sock = socket(AF_INET, SOCK_STREAM, 0);
            break;
		case SCTP:
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
			break;
	}

	if (sock < 0) {
		printf("Socket creation error.\n");
		return NULL;
	}

	if (bind(sock, (struct sockaddr *) &loc_addr, sizeof(struct sockaddr)) < 0) {
		printf("Error to bind. Port is busy.\n");
		return NULL;
	}
	
    if (config->protocol == SCTP) {
        /* SCTP needs setsockopt, */
        if (setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof (initmsg)) < 0){
            perror("setsockopt(initmsg)");
            return NULL;
        }
        listen(sock, initmsg.sinit_max_instreams); // Mudado para initmsg.sinit_max_instreams.
    }

    if (config->protocol == TCP) {
        listen(sock, 5);
    }

	printf("> Server of peer waiting connections\n");

    struct sockaddr_in rem_addr;
    unsigned int sock_size_rem_addr = sizeof(rem_addr);

    //set of socket descriptors
    fd_set readfds;
    int sd, max_sd, activity, valread;
    char buffer[1025];

    int client_socket[config->n_hosts];
    for (int i = 0; i < config->n_hosts; i++) {
        client_socket[i] = 0;
    }

    //int value = 1;
    int first = 1;
    int client_ports[config->n_hosts];
    for(int i = 0; i < config->n_hosts; i++) {
        client_ports[i] = 0;
    }
	do  {
        switch (config->protocol) {
            case UDP:
                recvfrom(sock, line, ECHOMAX, 0, (struct sockaddr *)&rem_addr, &sock_size_rem_addr);

                if (strcmp(line, "tcpdump") == 0) {
                    if (first == 1) {
                        pthread_mutex_lock(&m);
                        strcpy(message, "tcpdump");
                        done = 1;
                        pthread_cond_broadcast(&c);
                        pthread_mutex_unlock(&m);
                        first = 0;
                    }

                    int all_client_ports_received = 1;
                    for (int i = 0; i < config->n_hosts; i++) {
                        if(strcmp(config->hosts[i], inet_ntoa(rem_addr.sin_addr)) == 0) {
                            client_ports[i] = ntohs(rem_addr.sin_port);
                        }
                        if(client_ports[i] == 0)
                            all_client_ports_received = 0;
                    }

                    if (all_client_ports_received) {
                        while(1) {
                            send_tcpdump_output(sock, config->n_hosts, client_ports);
                        }
                    }
                }
                break;
            case TCP:
            case SCTP:
                //clear the socket set
                FD_ZERO(&readfds);
        
                //add master socket to set
                FD_SET(sock, &readfds);
                max_sd = sock;
                
                //add child sockets to set
                for (int i = 0; i < config->n_hosts; i++) {
                    //socket descriptor
                    sd = client_socket[i];
                    
                    //if valid socket descriptor then add to read list
                    if(sd > 0)
                        FD_SET(sd, &readfds);
                    
                    //highest file descriptor number, need it for the select function
                    if(sd > max_sd)
                        max_sd = sd;
                }

                //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
                activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

                if ((activity < 0) && (errno!=EINTR)) {
                    printf("Select error");
                }

                //If something happened on the master socket , then its an incoming connection
                if (FD_ISSET(sock, &readfds)) {
                    if ((loc_newsockfd = accept(sock, (struct sockaddr *)&loc_addr, (socklen_t*)&size)) < 0) {
                        perror("Accept error");
                        exit(EXIT_FAILURE);
                    }
                
                    //inform user of socket number - used in send and receive commands
                    //printf("New connection , socket fd is %d , ip is : %s , port : %d \n", loc_newsockfd, inet_ntoa(loc_addr.sin_addr) , ntohs(loc_addr.sin_port));
                    hosts_connected += 1;
                    
                    //add new socket to array of sockets
                    for(int i = 0; i < config->n_hosts; i++) {
                        //if position is empty
                        if(client_socket[i] == 0) {
                            client_socket[i] = loc_newsockfd;
                            //printf("Adding to list of sockets as %d\n" , i);
                            break;
                        }
                    }
                }

                //else its some IO operation on some other socket :)
                for(int i = 0; i < config->n_hosts; i++) {
                    sd = client_socket[i];
                    
                    if(FD_ISSET(sd, &readfds)) {
                        //Check if it was for closing , and also read the incoming message
                        if((valread = read(sd, buffer, 1024)) == 0) {
                            //Somebody disconnected , get his details and print
                            getpeername(sd , (struct sockaddr*)&rem_addr , (socklen_t*)&size);
                            //printf("Host disconnected , ip %s , port %d \n" , inet_ntoa(rem_addr.sin_addr) , ntohs(rem_addr.sin_port));
                            
                            //Close the socket and mark as 0 in list for reuse
                            close(sd);
                            client_socket[i] = 0;
                        }
                        //Echo back the message that came in
                        else {
                            //set the string terminating NULL byte on the end of the data read
                            buffer[valread] = '\0';
                            //printf("%s\n", buffer);
                            //send(sd, buffer, strlen(buffer), 0 );
                        }
                    }
                }

                if(hosts_connected == config->n_hosts && strcmp(buffer, "tcpdump") == 0) {
                    sleep(2);
                    pthread_mutex_lock(&m);
                    strcpy(message, "tcpdump");
                    done = 1;
                    pthread_cond_broadcast(&c);
                    pthread_mutex_unlock(&m);
                    send_tcpdump_output_tcp_sctp(config->n_hosts, client_socket);
                }

                break;
	    }
	} while(1);

  return NULL;
}

int choose_protocol() {
    char protocol[4] = "";
    printf("Type a protocol (UDP, TCP or SCTP):\n");
    scanf("%s", protocol);

   	if (strcmp(protocol, "UDP") == 0) return UDP;
    if (strcmp(protocol, "TCP") == 0) return TCP;
    if (strcmp(protocol, "SCTP") == 0) return SCTP;

    return UDP;
}

/* Initialize terminal */
void *terminal_commands(void *vargp) {
    char line_terminal[ECHOMAX];

    do  {
        scanf("%s", line_terminal);
        pthread_mutex_lock(&m);
        strcpy(message, line_terminal);
        done = 1;
        pthread_cond_broadcast(&c);
        pthread_mutex_unlock(&m);
    } while(strcmp(line_terminal, "exit"));

    return NULL;
}

int main(int argc, char **argv) {

  	if (argc != 2) {
        printf("Usage: %s config_filename.conf\n", argv[0]);
        return 0;
    }

    load_config_file(argv[1]); 
    config->protocol = choose_protocol();

    pthread_t thread_id_clients[config->n_hosts], thread_id_server;

    /* Create a thread for the server on host */
    pthread_create(&thread_id_server, NULL, server, NULL);

    /* Create a thread for clients connect to hosts */
    for(int i = 0; i < config->n_hosts; i++) {
        int *arg = malloc(sizeof(*arg));
        *arg = i;
        pthread_create(&thread_id_clients[i], NULL, clients, arg);
    }

    /* Create a thread for terminal */
    pthread_t thread_id_terminal_commands;
    pthread_create(&thread_id_terminal_commands, NULL, terminal_commands, NULL);

    /* Join threads */
    pthread_join(thread_id_terminal_commands, NULL);
    pthread_join(thread_id_server, NULL);
    for(int i = 0; i < config->n_hosts; i++) {
        pthread_join(thread_id_clients[i], NULL);
    }

    return 0;
}