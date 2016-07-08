#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
char *dev;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
	
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;

	eth = (struct ethhdr *)pkt_data;
        iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
        tcph = (struct tcphdr*)(pkt_data + sizeof(struct iphdr) + sizeof(struct ethhdr));

	printf("===========================\n");
	printf("Device : %s\n", dev);
	printf("Ether Src : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
	printf("Ether Dst : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
	printf("IP Src : %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
	printf("IP Dst : %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
	printf("Src port : %u\n",ntohs(tcph->source));
    	printf("Dst Port : %u\n",ntohs(tcph->dest));
	printf("===========================\n\n");		
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handler;

	dev = pcap_lookupdev(errbuf);
	handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_loop(handler, 0, packet_handler,NULL);
	
    return 0;
	
}

