#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h>
#include <ctype.h>
#include <string.h>

#define A1(addr) inet_ntoa(addr)
#define A2(addr) inet_ntoa(addr)

int i;
char *d; 
char e[PCAP_ERRBUF_SIZE]; 
pcap_t* c; 
const u_char *p; 
struct pcap_pkthdr h;
struct ether_header *ep;    
struct bpf_program f;        
bpf_u_int32 m;            
bpf_u_int32 n;   
struct in_addr a;
char ip[13];
char s[13]; 

void g(u_char *args, const struct pcap_pkthdr* ph, const u_char* pkt){ 

    int i=0; 
    static int count=0; 

    a.s_addr = n;
    strcpy(ip, A1(a));
    if (ip == NULL) {
        perror("inet_ntoa"); 
        
    }
    
    a.s_addr = m;
    strcpy(s, A2(a));
    if (s == NULL) {
        perror("inet_ntoa");
        
    }

    printf("Interface: %s\n", d);
    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", s);
    printf("\n");
    printf("Packet Count: %d\n", ++count);    
    printf("Received Packet Size: %d\n", ph->len);    
    printf("Payload:\n");                     
    for(i=0;i<ph->len;i++) { 
        if(isprint(pkt[i]))                
            printf("%c ",pkt[i]);          
        else
            printf(" . ");         
        if((i%16==0 && i!=0) || i==ph->len-1) 
            printf("\n"); 
    }

    printf("\n");
    printf("\n");

}

int main(int argc,char **argv) 
{          
 
    if(argc != 2){
        fprintf(stdout, "Usage: %s \"expression\"\n"
            ,argv[0]);
        return 0;
    } 

    d = argv[1];
     
    if(d == NULL) {
        fprintf(stderr, "Could not find interface: %s\n", e);
        exit(1);
    } 
    
    pcap_lookupnet(d, &n, &m, e);

    c = pcap_open_live(d, BUFSIZ, 1,1000, e); 

    if(c == NULL) {
        printf("pcap_open_live(): %s\n", e);
        exit(1);
    } 
    
    printf("Waiting for traffic....\n\n");
   
    pcap_loop(c, -1, g, NULL); 
    
    return 0; 
}