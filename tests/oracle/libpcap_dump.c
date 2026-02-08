#include <pcap/pcap.h>
#include <stdio.h>

static void print_packet(const struct pcap_pkthdr *header, const unsigned char *data)
{
    bpf_u_int32 i;

    printf("%lld.%09ld\t%u\t%u\t", (long long)header->ts.tv_sec, (long)header->ts.tv_usec, header->caplen, header->len);
    for (i = 0; i < header->caplen; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const unsigned char *data;
    pcap_t *pcap;
    int status;

    if (argc != 2) {
        fprintf(stderr, "usage: libpcap_dump FILE\n");
        return 2;
    }
    pcap = pcap_open_offline_with_tstamp_precision(argv[1], PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "libpcap_dump: %s\n", errbuf);
        return 1;
    }
    while ((status = pcap_next_ex(pcap, &header, &data)) == 1)
        print_packet(header, data);
    if (status == PCAP_ERROR)
        fprintf(stderr, "libpcap_dump: %s\n", pcap_geterr(pcap));
    pcap_close(pcap);
    return status == PCAP_ERROR ? 1 : 0;
}
