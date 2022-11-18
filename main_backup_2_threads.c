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
#define ECHOMAX 1024
#define BUFSIZE 2048
#define CONFIG_SIZE 256
#define MAX_HOSTS 6

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

/* Return an error code or 0 for no error. */
int parse_config(char *buf, CONF *config) {
    char dummy[CONFIG_SIZE];
    if (sscanf(buf, " %s", dummy) == EOF) return LINE_SUCCESS; // success; blank line
    if (sscanf(buf, " %[#]", dummy) == 1) return LINE_SUCCESS; // success; comment
    if (sscanf(buf, " interface = %s", dummy) == 1) {
        bzero(config->interface, 8);
        strcpy(config->interface, dummy);
        return LINE_SUCCESS;
    }
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

/* Load config file to struct CONF */
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

int send_tcpdump_output(int sock, struct sockaddr_in rem_addr) {
    char *cmd = "sudo tcpdump";    
    
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
        case UDP:
            while (fgets(line_tcpdump, BUFSIZE, fp) != NULL) {
                if (index < lines_per_message) {
                    index++;
                    strcat(lines_output_tcpdump, line_tcpdump);
                    printf("%s", lines_output_tcpdump);
                }
                else {
                    int size_lines = strlen(lines_output_tcpdump) + 1;
                    for(int i = 0; i < config->n_hosts; i++) {
                        if(strcmp(config->hosts[i], config->interface_address) != 0) {
                            rem_addr.sin_addr.s_addr = inet_addr(config->hosts[i]);
                            sendto(sock, lines_output_tcpdump, size_lines, 0, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
                        }
                    }
                    memset(lines_output_tcpdump, 0, 16384);
                    strcat(lines_output_tcpdump, hostbuffer);
                    index = 0;
                }
            }
            break;
        case TCP:
            break;
        case SCTP:
            break;
    }

    if (pclose(fp)) {
        printf("Command not found or exited with error status.\n");
        return -1;
    }

    return 0;
}

/* Initialize clients to connect to each host (except local server) */
void *clients() {

	int sock[config->n_hosts];
	char line[ECHOMAX];

	struct sockaddr_in rem_addr;
	rem_addr.sin_family = AF_INET;
    rem_addr.sin_port = htons(config->port);

    /* Variables to get ip of interface */
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET && strcmp(ifa->ifa_name, config->interface) == 0) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            snprintf(config->interface_address, sizeof(config->interface_address), "%s", inet_ntoa(sa->sin_addr));
        }
    }
    freeifaddrs(ifap);

    /* Create sockets UDP, TCP or SCTP */
    for(int i = 0; i < config->n_hosts; i++) {
        if(strcmp(config->hosts[i], config->interface_address) != 0) {
            rem_addr.sin_addr.s_addr = inet_addr(config->hosts[i]);
            switch (config->protocol) {
                case UDP:
                    sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
                    break;
                case TCP:
                    sock[i] = socket(AF_INET, SOCK_STREAM, 0);
                    break;
                case SCTP:
                    sock[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
                    break;
            }
            if (sock[i] < 0) {
		        printf("Socket creation error.\n");
		        return 0;
	        }
        }
    }

	/* Create a connection to server if protocol is TCP or SCTP */
	switch (config->protocol) {
		case UDP:
			break;
		case TCP:
		case SCTP:
            for(int i = 0; i < config->n_hosts; i++) {
                if(strcmp(config->hosts[i], config->interface_address) != 0) {
                    rem_addr.sin_addr.s_addr = inet_addr(config->hosts[i]);
                    if (connect(sock[i], (struct sockaddr *) &rem_addr, sizeof(rem_addr)) < 0) {
                        printf("Error on connecting stream socket.\n");
                        exit(1);
                    }
                }
            }
			break;
	}

	do  {
        fgets(line, ECHOMAX, stdin);

        for(int i = 0; i < config->n_hosts; i++) {
            if(strcmp(config->hosts[i], config->interface_address) != 0) {
                rem_addr.sin_addr.s_addr = inet_addr(config->hosts[i]);
                switch (config->protocol) {
                    case UDP:
                        sendto(sock[i], line, strlen(line) + 1, 0, (struct sockaddr *)&rem_addr, sizeof(rem_addr));

                        recvfrom(sock, line_from_target, sizeof(line_from_target), 0, (struct sockaddr *)&client, &size);
                        value = 0;
                        ioctl(sock, FIONBIO, &value);
                        inet_ntop(AF_INET, &(client.sin_addr), ip_address_client, INET_ADDRSTRLEN);
                        
                        if (ip_address_client[0] != '0') {
                            printf("%sIP: %s\n", KGRN, ip_address_client);
                            printf("%s%s\n", KYEL, line_from_target);
                        }
                        break;
                    case TCP:
                        line[strcspn(line, "\n")] = 0;	
                        send(sock[i], &line, strlen(line) + 1, 0);

                        /* parametros(descritor socket, endereco da memoria, tamanho da memoria, flag) */ 
                        // recv(sock[i], &line, sizeof(line), 0);
                        // printf("Recebi %s\n", line);
                        break;
                    case SCTP:
                        fgets(line, ECHOMAX, stdin);
                        line[strcspn(line, "\n")] = 0;
                        
                        sctp_sendmsg(sock[i], &line, sizeof(line), NULL, 0, 0, 0, 0, 0, 0);
                        sctp_recvmsg(sock[i], &line, sizeof(line), NULL, 0, 0, 0);
                        printf("Recebi %s\n", line);
                        break;
                }
            }
        }
	} while(strcmp(line, "exit"));

    /* Close remote socket */ 	
    for(int i = 0; i < config->n_hosts; i++) {
        if(strcmp(config->hosts[i], config->interface_address) != 0) {
	        close(sock[i]);
        }
    }

  return 0;
}

/* Initialize server */
void *server(void *vargp) {

	int sock, loc_newsockfd;
    socklen_t size;
	char line[ECHOMAX];

	struct sockaddr_in loc_addr = {
		.sin_family = AF_INET, /* familia do protocolo */
		.sin_addr.s_addr = INADDR_ANY, /* endereco IP local */
		.sin_port = htons(config->port), /* porta local */
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
		return 0;
	}

	if (bind(sock, (struct sockaddr *) &loc_addr, sizeof(struct sockaddr)) < 0) {
		printf("Error to bind. Port is busy.\n");
		return 0;
	}
	
    if (config->protocol == SCTP) {
        /* SCTP needs setsockopt, */
        if (setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof (initmsg)) < 0){
            perror("setsockopt(initmsg)");
            exit(1);
        }
        listen(sock, initmsg.sinit_max_instreams); // Mudado para initmsg.sinit_max_instreams.
    }

    if (config->protocol == TCP) {
        /* parametros(descritor socket,	numeros de conexoes em espera sem serem aceites pelo accept)*/
        listen(sock, 5);
    }

	printf("> aguardando conexao\n");

    if (config->protocol == TCP || config->protocol == SCTP) {
        /* Accept permite aceitar um pedido de conexao, devolve um novo "socket" ja ligado ao emissor do pedido e o "socket" original*/
        size = sizeof(struct sockaddr_in);
        loc_newsockfd = accept(sock, (struct sockaddr *)&loc_addr, &size);
    }

	do  {
        switch (config->protocol) {
            case UDP:
                recvfrom(sock, line, ECHOMAX, 0, (struct sockaddr *)&loc_addr, &size);
                if (strcmp(line, "tcpdump") == 0) {
                    send_tcpdump_output(sock, loc_addr);
                }
                break;
            case TCP:
                recv(loc_newsockfd, &line, sizeof(line), 0);
                printf("Recebi %s\n", line);

                send(loc_newsockfd, &line, sizeof(line), 0);
                printf("Renvia %s\n", line);
                break;
            case SCTP:
                sctp_recvmsg(loc_newsockfd, &line, sizeof(line), NULL, 0, 0, 0);
                printf("Recebi %s\n", line);

                sctp_sendmsg(loc_newsockfd, &line, sizeof(line), NULL, 0, 0, 0, 0, 0, 0);
                printf("Renvia %s\n", line);
                break;
	    }
	} while(strcmp(line, "exit"));

	/* fechamento do socket local */ 
	close(sock);

    if (config->protocol == TCP || config->protocol == SCTP) {
	    close(loc_newsockfd);
    }

  return 0;
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

int main(int argc, char **argv) {

  	if (argc != 2) {
        printf("Usage: %s config_filename.conf\n", argv[0]);
        return 0;
    }

    load_config_file(argv[1]); 
    config->protocol = choose_protocol();
    pthread_t thread_id_clients, thread_id_server;
    
    /* Create a thread for the server on host */
    pthread_create(&thread_id_server, NULL, server, NULL);

    /* Create a thread for clients connect to hosts */
    pthread_create(&thread_id_clients, NULL, clients, NULL);

    pthread_join(thread_id_server, NULL);
    pthread_join(thread_id_clients, NULL);

    return 0;
}