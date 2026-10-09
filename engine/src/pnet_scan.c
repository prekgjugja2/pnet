/*
 * PNet scan engine — Windows implementation (C).
 * Uses ICMP echo + IP neighbor (ARP) table + optional NetBIOS / TCP probes.
 */
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pnet_scan.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

typedef struct {
    unsigned prefix;
    unsigned host_bits;
    char local_ip[46];
    char gateway[46];
    char local_mac[18];
    char cidr[32];
} lan_info;

static void str_copy(char *dst, size_t n, const char *src)
{
    if (!dst || n == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, n - 1);
    dst[n - 1] = '\0';
}

static void mac_format(const BYTE *addr, DWORD len, char *out, size_t outlen)
{
    out[0] = '\0';
    if (!addr || len < 6 || outlen < 18) return;
    snprintf(out, outlen, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static int is_private_v4(unsigned ip_host)
{
    unsigned b0 = (ip_host >> 24) & 0xff;
    unsigned b1 = (ip_host >> 16) & 0xff;
    if (b0 == 10) return 1;
    if (b0 == 192 && b1 == 168) return 1;
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return 1;
    return 0;
}

static void ipv4_to_str(unsigned ip_host, char *out, size_t n)
{
    snprintf(out, n, "%u.%u.%u.%u",
             (ip_host >> 24) & 0xff,
             (ip_host >> 16) & 0xff,
             (ip_host >> 8) & 0xff,
             ip_host & 0xff);
}

static unsigned str_to_ipv4(const char *s)
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/* ---- OUI vendor (compact common set) ---- */

static const char *oui_vendor(const char *mac)
{
    char hex[7];
    int i, j = 0;
    if (!mac) return "";
    for (i = 0; mac[i] && j < 6; i++) {
        if (isxdigit((unsigned char)mac[i]))
            hex[j++] = (char)toupper((unsigned char)mac[i]);
    }
    hex[6] = '\0';
    if (j < 6) return "";

#define OUI(p, v) if (strcmp(hex, p) == 0) return v
    OUI("001A11", "Google"); OUI("F4F5D8", "Google"); OUI("7C2EBD", "Google");
    OUI("001B63", "Apple"); OUI("001F5B", "Apple"); OUI("0026B0", "Apple");
    OUI("3C970E", "Wacom"); OUI("B827EB", "Raspberry Pi"); OUI("DCA632", "Raspberry Pi");
    OUI("0021E9", "TP-Link"); OUI("54AF97", "TP-Link"); OUI("E0CB4E", "ASUSTek");
    OUI("44D9E7", "Ubiquiti"); OUI("001D7E", "Cisco-Linksys"); OUI("001E13", "Cisco");
    OUI("0050F2", "Microsoft"); OUI("00155D", "Microsoft"); OUI("000C29", "VMware");
    OUI("080027", "VirtualBox"); OUI("525400", "QEMU/KVM"); OUI("00E04C", "Realtek");
    OUI("001F3B", "Intel"); OUI("B4B676", "Intel"); OUI("00B0D0", "Dell");
    OUI("24F5AA", "Samsung"); OUI("3C5A37", "Samsung"); OUI("000D4B", "Roku");
    OUI("18B430", "Nest"); OUI("6CA100", "Acer"); OUI("40AE30", "Router");
#undef OUI
    return "";
}

static void guess_type(const char *vendor, const char *host, char *out, size_t n)
{
    char hay[256];
    snprintf(hay, sizeof(hay), "%s %s", vendor ? vendor : "", host ? host : "");
    for (char *p = hay; *p; p++) *p = (char)tolower((unsigned char)*p);

    if (strstr(hay, "router") || strstr(hay, "gateway") || strstr(hay, "cisco") ||
        strstr(hay, "ubiquiti") || strstr(hay, "tp-link") || strstr(hay, "asus"))
        str_copy(out, n, "router");
    else if (strstr(hay, "iphone") || strstr(hay, "android") || strstr(hay, "pixel") || strstr(hay, "galaxy"))
        str_copy(out, n, "phone");
    else if (strstr(hay, "ipad") || strstr(hay, "tablet"))
        str_copy(out, n, "tablet");
    else if (strstr(hay, "tv") || strstr(hay, "roku") || strstr(hay, "chromecast"))
        str_copy(out, n, "tv");
    else if (strstr(hay, "xbox") || strstr(hay, "playstation") || strstr(hay, "nintendo"))
        str_copy(out, n, "console");
    else if (strstr(hay, "printer") || strstr(hay, "epson") || strstr(hay, "brother"))
        str_copy(out, n, "printer");
    else if (strstr(hay, "raspberry") || strstr(hay, "iot") || strstr(hay, "nest") || strstr(hay, "echo"))
        str_copy(out, n, "iot");
    else if (strstr(hay, "camera") || strstr(hay, "ring") || strstr(hay, "arlo"))
        str_copy(out, n, "camera");
    else if (strstr(hay, "desktop") || strstr(hay, "macbook") || strstr(hay, "pc") ||
             strstr(hay, "intel") || strstr(hay, "dell") || strstr(hay, "acer") || strstr(hay, "vmware"))
        str_copy(out, n, "computer");
    else
        str_copy(out, n, "other");
}

void pnet_scan_options_init(pnet_scan_options *opt)
{
    if (!opt) return;
    memset(opt, 0, sizeof(*opt));
    opt->ping_timeout_ms = 200;
    opt->do_netbios = 1;
    opt->do_ports = 0;
    opt->max_hosts = 254;
    opt->force_cidr = NULL;
}

static int detect_lan(lan_info *lan)
{
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    DWORD rc;
    int found = 0;

    memset(lan, 0, sizeof(*lan));
    for (int attempt = 0; attempt < 3; attempt++) {
        addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
        if (!addrs) return -1;
        rc = GetAdaptersAddresses(AF_INET,
                                  GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST |
                                  GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                  NULL, addrs, &buflen);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            free(addrs);
            addrs = NULL;
            continue;
        }
        break;
    }
    if (rc != NO_ERROR || !addrs) {
        free(addrs);
        return -1;
    }

    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        char local[46] = "";
        char gw[46] = "";
        unsigned prefix_len = 24;

        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
            SOCKADDR_IN *sa = (SOCKADDR_IN *)u->Address.lpSockaddr;
            if (!sa || sa->sin_family != AF_INET) continue;
            inet_ntop(AF_INET, &sa->sin_addr, local, sizeof(local));
            prefix_len = u->OnLinkPrefixLength;
            break;
        }
        if (!local[0]) continue;

        for (IP_ADAPTER_GATEWAY_ADDRESS *g = a->FirstGatewayAddress; g; g = g->Next) {
            SOCKADDR_IN *sa = (SOCKADDR_IN *)g->Address.lpSockaddr;
            if (!sa || sa->sin_family != AF_INET) continue;
            inet_ntop(AF_INET, &sa->sin_addr, gw, sizeof(gw));
            break;
        }

        unsigned lip = str_to_ipv4(local);
        if (!is_private_v4(lip)) continue;
        if (prefix_len == 0 || prefix_len > 30) prefix_len = 24;

        unsigned mask = prefix_len == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix_len));
        lan->prefix = lip & mask;
        lan->host_bits = 32 - prefix_len;
        str_copy(lan->local_ip, sizeof(lan->local_ip), local);
        str_copy(lan->gateway, sizeof(lan->gateway), gw);
        mac_format(a->PhysicalAddress, a->PhysicalAddressLength, lan->local_mac, sizeof(lan->local_mac));
        {
            char net[46];
            ipv4_to_str(lan->prefix, net, sizeof(net));
            snprintf(lan->cidr, sizeof(lan->cidr), "%s/%u", net, prefix_len);
        }
        found = 1;
        /* Prefer adapters that have a gateway (real LAN / Wi-Fi). */
        if (gw[0]) break;
    }

    free(addrs);
    return found ? 0 : -1;
}

static int parse_force_cidr(const char *cidr, lan_info *lan)
{
    unsigned a, b, c, d, p;
    if (!cidr || sscanf(cidr, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &p) != 5) return -1;
    if (p == 0 || p > 30) return -1;
    unsigned ip = (a << 24) | (b << 16) | (c << 8) | d;
    unsigned mask = 0xFFFFFFFFu << (32 - p);
    lan->prefix = ip & mask;
    lan->host_bits = 32 - p;
    snprintf(lan->cidr, sizeof(lan->cidr), "%u.%u.%u.%u/%u", a, b, c, d, p);
    return 0;
}

static int icmp_ping(HANDLE icmp, unsigned ip_host, int timeout_ms, int *rtt_ms)
{
    IPAddr dest = htonl(ip_host);
    char send[32];
    memset(send, 'P', sizeof(send));
    DWORD reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(send) + 16;
    char *reply = (char *)malloc(reply_size);
    if (!reply) return 0;

    DWORD n = IcmpSendEcho(icmp, dest, send, sizeof(send), NULL, reply, reply_size, (DWORD)timeout_ms);
    int ok = 0;
    if (n > 0) {
        PICMP_ECHO_REPLY er = (PICMP_ECHO_REPLY)reply;
        if (er->Status == IP_SUCCESS) {
            ok = 1;
            if (rtt_ms) *rtt_ms = (int)er->RoundTripTime;
        }
    }
    free(reply);
    return ok;
}

static void read_arp_into(pnet_scan_result *out)
{
    ULONG size = 0;
    GetIpNetTable(NULL, &size, FALSE);
    if (size == 0) return;
    MIB_IPNETTABLE *table = (MIB_IPNETTABLE *)malloc(size);
    if (!table) return;
    if (GetIpNetTable(table, &size, FALSE) != NO_ERROR) {
        free(table);
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_IPNETROW *row = &table->table[i];
        if (row->dwType == MIB_IPNET_TYPE_INVALID) continue;
        unsigned ip = ntohl(row->dwAddr);
        if (!is_private_v4(ip)) continue;
        if (row->dwPhysAddrLen < 6) continue;

        char ipstr[46], mac[18];
        ipv4_to_str(ip, ipstr, sizeof(ipstr));
        mac_format(row->bPhysAddr, row->dwPhysAddrLen, mac, sizeof(mac));
        if (strcmp(mac, "00:00:00:00:00:00") == 0 || strcmp(mac, "FF:FF:FF:FF:FF:FF") == 0)
            continue;

        int idx = -1;
        for (int d = 0; d < out->device_count; d++) {
            if (strcmp(out->devices[d].ip, ipstr) == 0) { idx = d; break; }
        }
        if (idx < 0) {
            if (out->device_count >= PNET_MAX_DEVICES) continue;
            idx = out->device_count++;
            memset(&out->devices[idx], 0, sizeof(out->devices[idx]));
            str_copy(out->devices[idx].ip, sizeof(out->devices[idx].ip), ipstr);
            out->devices[idx].online = 1;
        }
        if (!out->devices[idx].mac[0])
            str_copy(out->devices[idx].mac, sizeof(out->devices[idx].mac), mac);
    }
    free(table);
}

static void reverse_dns(pnet_device *dev)
{
    struct sockaddr_in sa;
    char host[NI_MAXHOST];
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, dev->ip, &sa.sin_addr);
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
        /* strip common suffixes */
        char *dot = strstr(host, ".local");
        if (dot) *dot = '\0';
        str_copy(dev->hostname, sizeof(dev->hostname), host);
    }
}

/* NetBIOS node status (UDP 137) — best-effort hostname. */
static void netbios_name(pnet_device *dev)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return;

    DWORD timeout = 400;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    /* Minimal NBNS name query for "*" */
    unsigned char req[50] = {
        0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
        0x00, 0x01
    };

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(137);
    inet_pton(AF_INET, dev->ip, &to.sin_addr);

    if (sendto(s, (const char *)req, sizeof(req), 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        closesocket(s);
        return;
    }

    unsigned char buf[512];
    int n = recvfrom(s, (char *)buf, sizeof(buf), 0, NULL, NULL);
    closesocket(s);
    if (n < 57) return;

    /* Names start after header; first name is often workstation. */
    int name_count = buf[56];
    if (name_count <= 0) return;
    char name[16];
    memcpy(name, buf + 57, 15);
    name[15] = '\0';
    for (int i = 14; i >= 0; i--) {
        if (name[i] == ' ') name[i] = '\0';
        else break;
    }
    if (name[0] && !dev->hostname[0])
        str_copy(dev->hostname, sizeof(dev->hostname), name);
}

static int tcp_port_open(const char *ip, uint16_t port, int timeout_ms)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wset, eset;
    FD_ZERO(&wset); FD_ZERO(&eset);
    FD_SET(s, &wset); FD_SET(s, &eset);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(0, NULL, &wset, &eset, &tv);
    int ok = 0;
    if (r > 0 && FD_ISSET(s, &wset)) {
        int err = 0;
        int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        ok = (err == 0);
    }
    closesocket(s);
    return ok;
}

static pnet_device *find_or_add(pnet_scan_result *out, const char *ip)
{
    for (int i = 0; i < out->device_count; i++) {
        if (strcmp(out->devices[i].ip, ip) == 0) return &out->devices[i];
    }
    if (out->device_count >= PNET_MAX_DEVICES) return NULL;
    pnet_device *d = &out->devices[out->device_count++];
    memset(d, 0, sizeof(*d));
    str_copy(d->ip, sizeof(d->ip), ip);
    return d;
}

typedef struct {
    HANDLE icmp;
    unsigned ip;
    int timeout_ms;
    int alive;
    int rtt_ms;
} ping_job;

static DWORD WINAPI ping_worker(LPVOID param)
{
    ping_job *job = (ping_job *)param;
    job->rtt_ms = -1;
    job->alive = 0;
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) return 0;
    job->alive = icmp_ping(icmp, job->ip, job->timeout_ms, &job->rtt_ms);
    IcmpCloseHandle(icmp);
    return 0;
}

int pnet_scan_lan(const pnet_scan_options *opt, pnet_scan_result *out)
{
    pnet_scan_options defaults;
    if (!opt) {
        pnet_scan_options_init(&defaults);
        opt = &defaults;
    }
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        str_copy(out->error, sizeof(out->error), "WSAStartup failed");
        return -1;
    }

    lan_info lan;
    memset(&lan, 0, sizeof(lan));
    if (opt->force_cidr && opt->force_cidr[0]) {
        if (parse_force_cidr(opt->force_cidr, &lan) != 0) {
            str_copy(out->error, sizeof(out->error), "Invalid force_cidr");
            WSACleanup();
            return -1;
        }
        detect_lan(&lan);
        parse_force_cidr(opt->force_cidr, &lan);
    } else if (detect_lan(&lan) != 0) {
        str_copy(out->error, sizeof(out->error), "No private LAN interface found");
        WSACleanup();
        return -1;
    }

    str_copy(out->lan_cidr, sizeof(out->lan_cidr), lan.cidr);
    str_copy(out->gateway, sizeof(out->gateway), lan.gateway);
    str_copy(out->local_ip, sizeof(out->local_ip), lan.local_ip);
    str_copy(out->local_mac, sizeof(out->local_mac), lan.local_mac);

    HANDLE icmp = INVALID_HANDLE_VALUE; /* per-thread ICMP handles used in workers */

    unsigned host_count = (1u << lan.host_bits);
    if (host_count > 2) host_count -= 2;
    if (opt->max_hosts > 0 && host_count > (unsigned)opt->max_hosts)
        host_count = (unsigned)opt->max_hosts;

    int timeout = opt->ping_timeout_ms > 0 ? opt->ping_timeout_ms : 200;
    const int batch = 64;

    ping_job *jobs = (ping_job *)calloc(host_count, sizeof(ping_job));
    HANDLE *threads = (HANDLE *)calloc(batch, sizeof(HANDLE));
    if (!jobs || !threads) {
        free(jobs);
        free(threads);
        str_copy(out->error, sizeof(out->error), "Out of memory");
        WSACleanup();
        return -1;
    }

    for (unsigned i = 0; i < host_count; i++) {
        jobs[i].icmp = INVALID_HANDLE_VALUE;
        jobs[i].ip = lan.prefix + i + 1;
        jobs[i].timeout_ms = timeout;
    }

    for (unsigned base = 0; base < host_count; base += (unsigned)batch) {
        unsigned n = host_count - base;
        if (n > (unsigned)batch) n = (unsigned)batch;
        for (unsigned t = 0; t < n; t++) {
            threads[t] = CreateThread(NULL, 0, ping_worker, &jobs[base + t], 0, NULL);
        }
        WaitForMultipleObjects(n, threads, TRUE, (DWORD)(timeout + 2000));
        for (unsigned t = 0; t < n; t++) {
            if (threads[t]) CloseHandle(threads[t]);
            if (!jobs[base + t].alive) continue;
            char ipstr[46];
            ipv4_to_str(jobs[base + t].ip, ipstr, sizeof(ipstr));
            pnet_device *d = find_or_add(out, ipstr);
            if (d) {
                d->online = 1;
                d->ping_ms = jobs[base + t].rtt_ms;
            }
        }
    }

    free(jobs);
    free(threads);

    Sleep(100);
    read_arp_into(out);

    if (out->local_ip[0]) {
        pnet_device *self = find_or_add(out, out->local_ip);
        if (self) {
            self->online = 1;
            if (!self->mac[0]) str_copy(self->mac, sizeof(self->mac), out->local_mac);
            if (!self->hostname[0]) {
                char name[PNET_NAME_LEN];
                DWORD nlen = PNET_NAME_LEN;
                if (GetComputerNameA(name, &nlen))
                    str_copy(self->hostname, sizeof(self->hostname), name);
            }
            str_copy(self->type, sizeof(self->type), "computer");
        }
    }

    for (int i = 0; i < out->device_count; i++) {
        pnet_device *d = &out->devices[i];
        if (!d->vendor[0] && d->mac[0])
            str_copy(d->vendor, sizeof(d->vendor), oui_vendor(d->mac));
        if (!d->hostname[0])
            reverse_dns(d);
        if (opt->do_netbios && !d->hostname[0])
            netbios_name(d);
        if (out->gateway[0] && strcmp(d->ip, out->gateway) == 0)
            str_copy(d->type, sizeof(d->type), "router");
        else if (!d->type[0])
            guess_type(d->vendor, d->hostname, d->type, sizeof(d->type));
        if (!d->hostname[0]) {
            if (d->vendor[0])
                snprintf(d->hostname, sizeof(d->hostname), "%s device", d->vendor);
            else
                snprintf(d->hostname, sizeof(d->hostname), "Seen %s", d->ip);
        }
        if (opt->do_ports && d->online) {
            static const uint16_t ports[] = {22, 80, 443, 445, 3389, 8080};
            for (size_t p = 0; p < sizeof(ports) / sizeof(ports[0]); p++) {
                if (d->open_port_count >= 16) break;
                if (tcp_port_open(d->ip, ports[p], 200))
                    d->open_ports[d->open_port_count++] = ports[p];
            }
        }
    }

    WSACleanup();
    return 0;
}

static void json_escape(const char *in, char *out, size_t n)
{
    size_t j = 0;
    if (!in) { out[0] = '\0'; return; }
    for (size_t i = 0; in[i] && j + 2 < n; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') {
            if (j + 3 >= n) break;
            out[j++] = '\\';
            out[j++] = c;
        } else if ((unsigned char)c < 0x20) {
            continue;
        } else {
            out[j++] = c;
        }
    }
    out[j] = '\0';
}

int pnet_result_to_json(const pnet_scan_result *result, char *buf, size_t buflen)
{
    if (!result || !buf || buflen < 8) return -1;
    size_t off = 0;
    char esc[256];

#define APPEND(...) do { \
    int _n = snprintf(buf + off, buflen - off, __VA_ARGS__); \
    if (_n < 0 || (size_t)_n >= buflen - off) return -1; \
    off += (size_t)_n; \
} while (0)

    APPEND("{\"ok\":true,\"lan_cidr\":\"%s\",\"gateway\":\"%s\",\"local_ip\":\"%s\",\"local_mac\":\"%s\",\"device_count\":%d,\"devices\":[",
           result->lan_cidr, result->gateway, result->local_ip, result->local_mac, result->device_count);

    for (int i = 0; i < result->device_count; i++) {
        const pnet_device *d = &result->devices[i];
        if (i) APPEND(",");
        json_escape(d->hostname, esc, sizeof(esc));
        APPEND("{\"ip\":\"%s\",\"mac\":\"%s\",\"hostname\":\"%s\"", d->ip, d->mac, esc);
        json_escape(d->vendor, esc, sizeof(esc));
        APPEND(",\"vendor\":\"%s\",\"type\":\"%s\",\"online\":%s,\"ping_ms\":%d,\"open_ports\":[",
               esc, d->type, d->online ? "true" : "false", d->ping_ms);
        for (int p = 0; p < d->open_port_count; p++) {
            if (p) APPEND(",");
            APPEND("%u", (unsigned)d->open_ports[p]);
        }
        APPEND("]}");
    }
    APPEND("]}");
#undef APPEND
    return (int)off;
}
