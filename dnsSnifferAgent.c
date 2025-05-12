/*
 * dns_sniffer.c
 * --------------
 * Sniffs DNS response packets on Linux and prints the domain name along with
 * its resolved IPv4 (A), IPv6 (AAAA), and CNAME records to stdout.
 *
 * Features:
 *  - Supports both IPv4 and IPv6
 *  - Handles DNS over UDP and TCP
 *  - Uses a BPF filter to capture only DNS responses (kernel-side filtering)
 *  - Parses DNS messages in user space for efficiency
 *  - Clean, modular code with detailed documentation
 *
 * Build:
 *   sudo apt install libpcap-dev
 *   make
 *
 * Usage:
 *   sudo ./dns_sniffer
 *
 *   Press Ctrl-C to terminate gracefully.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <signal.h>

/**
 * Maximum number of records (A, AAAA, or CNAME) to store per response.
 * Prevents unbounded memory usage in case of malformed or huge responses.
 */
#define MAX_ANS 100
/**
 * Global pcap handle used for capturing packets.
 * Stored here so signal handler can break the capture loop.
 */
static pcap_t *g_handle = NULL;
/**
 * Link-layer type for the capture device (Ethernet, Linux cooked, raw IP, etc.).
 * Used to compute the offset where the IP header begins.
 */
static int    g_linktype = -1;
/**
 * Signal handler for SIGINT (Ctrl-C).  Breaks out of pcap_loop cleanly.
 */
static void handle_sigint(int signum) {
    if (g_handle) pcap_breakloop(g_handle);
}

/**
 * skip_name()
 * --------------
 * Skip over a DNS-encoded name in the message buffer, handling
 * label compression pointers (RFC 1035 Section 4.1.4).
 *
 * @param msg       Pointer to the start of the DNS message
 * @param msg_len   Total length of the DNS message
 * @param ptr       Current pointer within the message to the name field
 * @returns         Number of bytes consumed from the original position
 */
static int skip_name(const uint8_t *msg, int msg_len, const uint8_t *ptr) {
    int jumped = 0, len = 0;
    // Walk until end-of-name (zero length) or compression pointer
    while ((ptr - msg) < msg_len) {
        uint8_t octet = *ptr;
        if (octet == 0) {
            // Null label: end of name
            if (!jumped) len++;
            break;
        }

        if ((octet & 0xC0) == 0xC0) {
            // Compression pointer: two-byte offset
            if (!jumped) len += 2;
            break;
        }
        // Normal label: length byte + label bytes
        ptr++;
        if (!jumped) len += octet + 1;
        ptr += octet;
    }

    return len;
}

/**
 * parse_name()
 * --------------
 * Decode a DNS name (which may include compression pointers) into
 * a human-readable dot-separated string.
 *
 * @param msg       Pointer to the start of the DNS message
 * @param msg_len   Total length of the DNS message
 * @param ptr       Pointer within the message to the name field
 * @param buf       Output buffer for the decoded name
 * @param buf_len   Size of the output buffer
 */
static void parse_name(const uint8_t *msg, int msg_len, const uint8_t *ptr,
                       char *buf, int buf_len) {
    int offset = ptr - msg, pos = 0, jumped = 0, loops = 0;
    // Loop until end-of-name or safety bound
    while (offset < msg_len && loops++ < msg_len) {
        uint8_t len = msg[offset];
        if (len == 0) {
            // End of name
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            // Compression pointer: update offset
            uint16_t p = ((len & 0x3F) << 8) | msg[offset+1];
            offset = p;
            jumped = 1;
            continue;
        }
        // Copy label into buffer
        offset++;
        if (pos + len >= buf_len) break;
        memcpy(buf + pos, msg + offset, len);
        pos += len;
        buf[pos++] = '.';
        offset += len;
    }
    // Remove trailing dot, null-terminate
    if (pos > 0 && buf[pos-1] == '.') pos--;
    buf[pos] = '\0';
}

/**
 * process_dns_message()
 * ----------------------
 * Parse a raw DNS payload (header + question + answers) and extract
 * A, AAAA, and CNAME records.  Prints the domain and record lists.
 *
 * @param payload       Pointer to the DNS payload (after UDP/TCP header)
 * @param payload_len   Length of the DNS payload
 */
static void process_dns_message(const uint8_t *payload, int payload_len) {
    // DNS header is 12 bytes
    if (payload_len < 12) return;

    // Question count (qdcount) at offset 4, answer count (ancount) at offset 6
    uint16_t qdcount = ntohs(*(uint16_t*)(payload + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(payload + 6));
    // QR bit (response) is bit 7 of byte 2
    if (!(payload[2] & 0x80) || qdcount < 1 || ancount == 0) return;

    // Skip question section to reach first answer
    const uint8_t *p = payload + 12;
    const uint8_t *name_ptr = p;
    int skip = skip_name(payload, payload_len, p);
    uint16_t qtype = ntohs(*(uint16_t*)(name_ptr + skip));
    if (qtype != 1 /*A*/ && qtype != 5 /*CNAME*/ && qtype != 28 /*AAAA*/)
        return;
    p += skip + 4;  // skip QTYPE (2) + QCLASS (2)

    // Decode queried domain into string
    char domain[256];
    parse_name(payload, payload_len, name_ptr, domain, sizeof(domain));

    // Storage for extracted records
    char *ipv4_addrs[MAX_ANS] = {0};
    char *ipv6_addrs[MAX_ANS] = {0};
    char *cname_recs [MAX_ANS] = {0};
    int cnt4 = 0, cnt6 = 0, cntc = 0;

    // Iterate over each answer resource record
    for (int i = 0; i < ancount; i++) {
        if ((p - payload) >= payload_len) break;
        // Skip RR name (could be compressed)
        int nl = skip_name(payload, payload_len, p);
        p += nl;
        // Ensure fixed RR header (type, class, ttl, rdlength) fits
        if ((p - payload + 10) > payload_len) break;

        uint16_t type    = ntohs(*(uint16_t*)p);
        uint16_t class   = ntohs(*(uint16_t*)(p+2));
        uint16_t rdlen   = ntohs(*(uint16_t*)(p+8));
        p += 10;  // Move past type, class, ttl(4), rdlength(2)
        // Bounds check RDATA length
        if ((p - payload + rdlen) > payload_len) break;

        // A record (IPv4)
        if (type == 1 && class == 1 && rdlen == 4) {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, p, buf, sizeof(buf));
            if (cnt4 < MAX_ANS) ipv4_addrs[cnt4++] = strdup(buf);
        }
        // AAAA record (IPv6)
        else if (type == 28 && class == 1 && rdlen == 16) {
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, p, buf, sizeof(buf));
            if (cnt6 < MAX_ANS) ipv6_addrs[cnt6++] = strdup(buf);
        }
        // CNAME record
        else if (type == 5 && class == 1) {
            char buf[256];
            parse_name(payload, payload_len, p, buf, sizeof(buf));
            if (cntc < MAX_ANS) cname_recs[cntc++] = strdup(buf);
        }
        // Advance past RDATA
        p += rdlen;
    }

    // Print results: domain, CNAME, IPv4, IPv6 lists
    printf("Domain: %s\n", domain);
    if (cntc) {
        printf("  CNAME(s):\n");
        for (int i = 0; i < cntc; i++) {
            printf("    %s\n", cname_recs[i]);
            free(cname_recs[i]);
        }
    }
    if (cnt4) {
        printf("  IPv4:\n");
        for (int i = 0; i < cnt4; i++) {
            printf("    %s\n", ipv4_addrs[i]);
            free(ipv4_addrs[i]);
        }
    }
    if (cnt6) {
        printf("  IPv6:\n");
        for (int i = 0; i < cnt6; i++) {
            printf("    %s\n", ipv6_addrs[i]);
            free(ipv6_addrs[i]);
        }
    }
    printf("\n");
}

/**
 * packet_handler()
 * -----------------
 * Callback invoked by libpcap for each captured packet.  Determines
 * whether the packet is IPv4 or IPv6, UDP or TCP, and extracts the
 * DNS payload for processing.
 *
 * @param args  User argument (unused)
 * @param hdr   Packet metadata (timestamp, lengths)
 * @param pkt   Raw packet data
 */
static void packet_handler(uint8_t *args,
                           const struct pcap_pkthdr *hdr,
                           const uint8_t *pkt) {
    (void)args; // unused
    // Determine link-layer header length
    int link_hdr = 0;
    if      (g_linktype == DLT_EN10MB)    link_hdr = 14;
    else if (g_linktype == DLT_LINUX_SLL) link_hdr = 16;
    /* DLT_RAW, DLT_IPV4: link_hdr=0 */

    const uint8_t *data = pkt + link_hdr;
    int datalen = hdr->caplen - link_hdr;
    if (datalen <= 0) return;

    /* IPv4 */
    if ((data[0] >> 4) == 4 && datalen >= sizeof(struct ip)) {
        struct ip   *ip4       = (struct ip*)data;
        int          ihl       = ip4->ip_hl * 4;
        /* UDP */
        if (ip4->ip_p == IPPROTO_UDP && datalen >= ihl + sizeof(struct udphdr)) {
            struct udphdr *udp = (struct udphdr*)(data + ihl);
            int payload_len    = ntohs(udp->len) - sizeof(*udp);
            const uint8_t *pl  = data + ihl + sizeof(*udp);
            process_dns_message(pl, payload_len);
        }
        /* TCP */
        else if (ip4->ip_p == IPPROTO_TCP && datalen >= ihl + sizeof(struct tcphdr)) {
            struct tcphdr *tcp = (struct tcphdr*)(data + ihl);
            int thl = tcp->doff * 4;
            const uint8_t *pl = data + ihl + thl;
            int payload_len   = datalen - ihl - thl;
            /* Skip 2-byte length prefix */
            if (payload_len > 2)
                process_dns_message(pl + 2, payload_len - 2);
        }
    }
    /* IPv6 */
    else if ((data[0] >> 4) == 6 && datalen >= sizeof(struct ip6_hdr)) {
        struct ip6_hdr *ip6 = (struct ip6_hdr*)data;
        int nh = ip6->ip6_nxt, ihl = sizeof(*ip6);
        /* UDP */
        if (nh == IPPROTO_UDP && datalen >= ihl + sizeof(struct udphdr)) {
            struct udphdr *udp = (struct udphdr*)(data + ihl);
            int payload_len    = ntohs(udp->len) - sizeof(*udp);
            const uint8_t *pl  = data + ihl + sizeof(*udp);
            process_dns_message(pl, payload_len);
        }
        /* TCP */
        else if (nh == IPPROTO_TCP && datalen >= ihl + sizeof(struct tcphdr)) {
            struct tcphdr *tcp = (struct tcphdr*)(data + ihl);
            int thl = tcp->doff * 4;
            const uint8_t *pl = data + ihl + thl;
            int payload_len   = datalen - ihl - thl;
            if (payload_len > 2)
                process_dns_message(pl + 2, payload_len - 2);
        }
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev        = "any";
    if (argc > 2) {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        dev = argv[1];
    }

    /* BPF: UDP/TCP port 53 & QR=1 */
    const char *filter_exp =
      "((udp port 53 and (udp[10] & 0x80) != 0) or "
      " (tcp port 53 and (tcp[((tcp[12] & 0xF0)>>2)+2] & 0x80) != 0))";

    signal(SIGINT, handle_sigint);

    // Open a packet-capture handle on a network interface in “live” mode.
    // - place the interface in promiscuous mode
    // - read timeout in milliseconds, i.e. max time pcap_loop/pcap_dispatch
    //   will wait for packets before returning
    g_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!g_handle) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    // Query the data-link (OSI layer 2) header type for the opened capture.
    // We need this to know how many bytes to skip before the IP header.
    g_linktype = pcap_datalink(g_handle);

    // Turn a human-readable BPF filter expression (e.g. "udp port 53")
    // into a struct bpf_program that the kernel (or libpcap) can apply.
    // Always free  bpf_program with pcap_freecode() after pcap_setfilter()
    // to avoid memory leaks.
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, filter_exp, 1, 0) < 0 ||
        pcap_setfilter(g_handle, &fp) < 0) {
        fprintf(stderr, "Failed to compile/apply filter\n");
        pcap_close(g_handle);
        return EXIT_FAILURE;
    }
    // Release the memory allocated by pcap_compile().
    pcap_freecode(&fp);

    // Enter a packet-capture loop: libpcap waits for packets,
    // applies filter, then calls callback for each matching packet,
    // until either cnt packets have been delivered (if cnt > 0),
    // we call pcap_breakloop(), or an error or EOF occurs.
    printf("Listening for DNS responses... (Ctrl-C to stop)\n");
    pcap_loop(g_handle, -1, packet_handler, NULL);

    // Shut down the capture, release all associated resources (file descriptors, memory).
    pcap_close(g_handle);
    printf("Done.\n");
    return EXIT_SUCCESS;
}
