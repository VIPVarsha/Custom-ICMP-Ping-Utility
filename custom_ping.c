#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <math.h>
#include<stdbool.h>

#define PACKET_SIZE     64
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define PING_SLEEP_RATE   1

int packets_sent = 0, packets_received = 0;
long min_rtt = 1e9, max_rtt = 0;
double total_rtt = 0;
int ping_count_limit = -1;

char global_target_ip[INET_ADDRSTRLEN];
char expected_org[128] = "";  // Organization name for verification

FILE *log_file = NULL;

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void get_org_name(const char *ip, char *org_buffer, size_t buf_size) {
    char command[512];
    snprintf(command, sizeof(command),
             "curl -s http://ip-api.com/json/%s | jq -r '.org'", ip);

    FILE *fp = popen(command, "r");
    if (!fp) {
        snprintf(org_buffer, buf_size, "Unknown");
        return;
    }

    fgets(org_buffer, buf_size, fp);
    org_buffer[strcspn(org_buffer, "\n")] = 0; // remove newline
    pclose(fp);
}

void build_packet(struct icmphdr *icmp, int pid, int seq) {
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = pid;
    icmp->un.echo.sequence = seq;
    icmp->checksum = checksum(icmp, sizeof(struct icmphdr));
}

void geo_ip_lookup(const char *ip) {
    printf("\n------------- Geo-IP Info for %s -------------\n\n", ip);
    char command[512];
    snprintf(command, sizeof(command),
             "curl -s http://ip-api.com/json/%s | jq -r 'to_entries[] | \"\\(.key): \\(.value)\"'", ip);
    system(command);
}

void print_statistics(const char *ip) {
    printf("\n--- Ping Statistics ---\n\n");
    printf("Packets: Sent = %d, Received = %d, Lost = %d (%.2f%% loss)\n",
           packets_sent, packets_received,
           packets_sent - packets_received,
           100.0 * (packets_sent - packets_received) / packets_sent);

    if (packets_received > 0) {
        double avg = total_rtt / packets_received;
        printf("RTT: min = %ld ms, avg = %.2f ms, max = %ld ms\n",
               min_rtt, avg, max_rtt);
    }

    geo_ip_lookup(ip);
}

void handle_interrupt(int sig) {
    print_statistics(global_target_ip);
    if (log_file) fclose(log_file);
    exit(0);
}

void pingpong(const char *target) {
    struct sockaddr_in dest_addr;
    struct icmphdr icmp_header;
    int sockfd, seq = 1;
    struct timespec start, end;
    long rtt;

    signal(SIGINT, handle_interrupt);

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    if (getaddrinfo(target, NULL, &hints, &res) != 0) {
        fprintf(stderr, "DNS resolution failed\n");
        exit(1);
    }

    dest_addr = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

    strcpy(global_target_ip, inet_ntoa(dest_addr.sin_addr));

    //  Store expected org name for spoof-check
    get_org_name(global_target_ip, expected_org, sizeof(expected_org));
    printf(" Expected Organization: %s\n", expected_org);

    // Open trace log file
    log_file = fopen("ping_trace.csv", "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(1);
    }

    // Write headers only if file is empty
    fseek(log_file, 0, SEEK_END);
    if (ftell(log_file) == 0) {
        fprintf(log_file, "Timestamp,Target,IP,Sequence,RTT(ms),TTL,Organization\n");
        fflush(log_file);
    }

    int pid = getpid();

    while (ping_count_limit == -1 || seq <= ping_count_limit) {
        build_packet(&icmp_header, pid, seq);
        packets_sent++;

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (sendto(sockfd, &icmp_header, sizeof(struct icmphdr), 0,
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
            perror("Send failed");
            continue;
        }

        char buffer[1024];
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                          (struct sockaddr *)&reply_addr, &addr_len);
        clock_gettime(CLOCK_MONOTONIC, &end);

        if (bytes_received <= 0) {
            perror("Receive failed");
            continue;
        }

        char *reply_ip = inet_ntoa(reply_addr.sin_addr);
        if (strcmp(reply_ip, global_target_ip) != 0) {
            printf("⚠  Warning: Suspicious ICMP reply from unexpected IP: %s (expected %s)\n",
                   reply_ip, global_target_ip);
            continue;
        }

        //  Verify org of reply IP
        char reply_org[128];
        get_org_name(reply_ip, reply_org, sizeof(reply_org));
        if (strcmp(reply_org, expected_org) != 0) {
            printf("⚠  WARNING!!: ICMP reply from mismatched organization\nExpected: %s\nReceived: %s\n",
                   expected_org, reply_org);
        } else {
            printf(" Verified: Reply is from expected organization (%s)\n", reply_org);
        }

        struct iphdr *ip_header = (struct iphdr *)buffer;
        struct icmphdr *icmp_reply = (struct icmphdr *)(buffer + (ip_header->ihl * 4));

        if (icmp_reply->type == ICMP_ECHO_REPLY && icmp_reply->un.echo.id == pid) {
            packets_received++;

            rtt = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;

            if (rtt < min_rtt) min_rtt = rtt;
            if (rtt > max_rtt) max_rtt = rtt;
            total_rtt += rtt;

            time_t rawtime;
            struct tm *timeinfo;
            char time_buffer[9];
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S", timeinfo);

            printf("%s Reply from %s: seq=%d, TTL=%d, RTT=%ld ms\n",
                   time_buffer, reply_ip, seq, ip_header->ttl, rtt);

            // Log to file
            fprintf(log_file, "%s,%s,%s,%d,%ld,%d,%s\n",
                    time_buffer, target, reply_ip, seq, rtt, ip_header->ttl, reply_org);
            fflush(log_file);
        }

        seq++;
        sleep(PING_SLEEP_RATE);
    }

    close(sockfd);
    if (log_file) fclose(log_file);
    print_statistics(global_target_ip);
}

//server down/online System
void check_server_down(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Could not open watchlist");
        return;
    }

    char ip[256];
    char known[100][256];   // Up to 100 entries
    bool is_up[100] = {0};
    int count = 0;

    while (fgets(ip, sizeof(ip), fp)) {
        ip[strcspn(ip, "\n")] = 0;
        strcpy(known[count++], ip);
    }
    fclose(fp);

    printf(" Watching %d hosts for online status...\n", count);

    while (1) {
        for (int i = 0; i < count; i++) {
            char command[512];
            snprintf(command, sizeof(command), "ping -c 1 -W 1 %s > /dev/null", known[i]);

            int res = system(command);
            if (res == 0 && !is_up[i]) {
                // Just came online
                printf(" Host %s is now ONLINE!\n", known[i]);
                is_up[i] = true;

                // Optional: alert sound
                printf("\a"); // terminal beep
            }
            else if (res != 0 && is_up[i]) {
                // Just went offline
                printf("⚠ Host %s went OFFLINE!\n", known[i]);
                is_up[i] = false;
            }
        }

        sleep(5); // check every 5 seconds
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 4) {
        printf("Usage: sudo ./ping <ip_or_domain> [-c <count>]\n");
        return 1;
    }

    if (argc == 4 && strcmp(argv[2], "-c") == 0) {
        ping_count_limit = atoi(argv[3]);
    }

    if (strcmp(argv[1], "--watch") == 0 && argc == 3) {
        check_server_down(argv[2]);
        return 0;
    }

    printf("Pinging %s with ICMP...\n", argv[1]);
    pingpong(argv[1]);

    return 0;
}
