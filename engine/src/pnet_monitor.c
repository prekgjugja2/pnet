/*
 * PNet traffic monitor — Windows (C).
 * Captures interface byte counters, TCP/UDP owners, and process names.
 */
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pnet_monitor.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

static void str_copy(char *dst, size_t n, const char *src)
{
    if (!dst || n == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, n - 1);
    dst[n - 1] = '\0';
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

static unsigned str_to_ipv4(const char *s)
{
    unsigned a, b, c, d;
    if (!s || sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static void ipv4_to_str(unsigned ip_host, char *out, size_t n)
{
    snprintf(out, n, "%u.%u.%u.%u",
             (ip_host >> 24) & 0xff,
             (ip_host >> 16) & 0xff,
             (ip_host >> 8) & 0xff,
             ip_host & 0xff);
}

static int pick_local_ip(char *out, size_t n)
{
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    DWORD rc;
    int found = 0;
    out[0] = '\0';
    for (int pass = 0; pass < 8 && !found; pass++) {
        addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
        if (!addrs) return 0;
        rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, addrs, &buflen);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            free(addrs);
            addrs = NULL;
            continue;
        }
        if (rc != NO_ERROR) {
            free(addrs);
            return 0;
        }
        for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
                if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
                struct sockaddr_in *sin = (struct sockaddr_in *)u->Address.lpSockaddr;
                unsigned ip = ntohl(sin->sin_addr.s_addr);
                if (!is_private_v4(ip)) continue;
                ipv4_to_str(ip, out, n);
                found = 1;
                break;
            }
            if (found) break;
        }
        free(addrs);
        addrs = NULL;
        if (!found) break;
    }
    return found;
}

static int pick_adapter_bytes(uint64_t *in_bytes, uint64_t *out_bytes, char *adapter, size_t adapter_n)
{
    PMIB_IF_TABLE2 table = NULL;
    if (GetIfTable2(&table) != NO_ERROR || !table) return 0;
    uint64_t best_in = 0, best_out = 0;
    char best_name[128] = "";
    for (ULONG i = 0; i < table->NumEntries; i++) {
        MIB_IF_ROW2 *row = &table->Table[i];
        if (row->OperStatus != IfOperStatusUp) continue;
        if (row->Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (row->MediaConnectState != MediaConnectStateConnected) continue;
        if (row->InOctets + row->OutOctets >= best_in + best_out) {
            best_in = row->InOctets;
            best_out = row->OutOctets;
            WideCharToMultiByte(CP_UTF8, 0, row->Description, -1, best_name, (int)sizeof(best_name), NULL, NULL);
        }
    }
    FreeMibTable(table);
    if (best_in == 0 && best_out == 0) return 0;
    *in_bytes = best_in;
    *out_bytes = best_out;
    str_copy(adapter, adapter_n, best_name);
    return 1;
}

typedef struct {
    uint32_t pid;
    int tcp_established;
    int udp_endpoints;
    int remote_public;
    int remote_lan;
} pid_stats;

static pid_stats *find_pid(pid_stats *list, int *count, uint32_t pid)
{
    for (int i = 0; i < *count; i++) {
        if (list[i].pid == pid) return &list[i];
    }
    if (*count >= PNET_MON_MAX_APPS) return NULL;
    pid_stats *slot = &list[(*count)++];
    memset(slot, 0, sizeof(*slot));
    slot->pid = pid;
    return slot;
}

static void count_remote(const char *ip, pid_stats *slot)
{
    unsigned v4 = str_to_ipv4(ip);
    if (v4 == 0) return;
    if (is_private_v4(v4)) slot->remote_lan++;
    else slot->remote_public++;
}

static void read_tcp(pid_stats *list, int *count)
{
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(table);
        return;
    }
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &table->table[i];
        if (row->dwState != MIB_TCP_STATE_ESTAB) continue;
        pid_stats *slot = find_pid(list, count, row->dwOwningPid);
        if (!slot) continue;
        slot->tcp_established++;
        char rip[46];
        ipv4_to_str(ntohl(row->dwRemoteAddr), rip, sizeof(rip));
        count_remote(rip, slot);
    }
    free(table);
}

static void read_udp(pid_stats *list, int *count)
{
    PMIB_UDPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!table) return;
    if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        free(table);
        return;
    }
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *row = &table->table[i];
        if (row->dwLocalAddr == 0) continue;
        pid_stats *slot = find_pid(list, count, row->dwOwningPid);
        if (!slot) continue;
        slot->udp_endpoints++;
    }
    free(table);
}

static void basename_only(const char *path, char *out, size_t n)
{
    const char *base = path;
    const char *p = path ? strrchr(path, '\\') : NULL;
    if (!p) p = path ? strrchr(path, '/') : NULL;
    if (p) base = p + 1;
    str_copy(out, n, base ? base : "");
}

static void friendly_name(const char *exe, char *out, size_t n)
{
    char lower[PNET_MON_NAME_LEN];
    str_copy(lower, sizeof(lower), exe ? exe : "");
    for (char *p = lower; *p; p++) *p = (char)tolower((unsigned char)*p);

    if (strcmp(lower, "chrome.exe") == 0) str_copy(out, n, "Google Chrome");
    else if (strcmp(lower, "msedge.exe") == 0) str_copy(out, n, "Microsoft Edge");
    else if (strcmp(lower, "firefox.exe") == 0) str_copy(out, n, "Firefox");
    else if (strcmp(lower, "opera.exe") == 0) str_copy(out, n, "Opera");
    else if (strcmp(lower, "brave.exe") == 0) str_copy(out, n, "Brave");
    else if (strcmp(lower, "discord.exe") == 0) str_copy(out, n, "Discord");
    else if (strcmp(lower, "spotify.exe") == 0) str_copy(out, n, "Spotify");
    else if (strcmp(lower, "steam.exe") == 0) str_copy(out, n, "Steam");
    else if (strcmp(lower, "zoom.exe") == 0) str_copy(out, n, "Zoom");
    else if (strcmp(lower, "teams.exe") == 0 || strcmp(lower, "ms-teams.exe") == 0) str_copy(out, n, "Microsoft Teams");
    else if (strcmp(lower, "onedrive.exe") == 0) str_copy(out, n, "OneDrive");
    else if (strcmp(lower, "dropbox.exe") == 0) str_copy(out, n, "Dropbox");
    else if (strcmp(lower, "python.exe") == 0) str_copy(out, n, "Python");
    else if (strcmp(lower, "node.exe") == 0) str_copy(out, n, "Node.js");
    else if (strcmp(lower, "httpd.exe") == 0 || strcmp(lower, "apache.exe") == 0) str_copy(out, n, "Apache");
    else if (strcmp(lower, "mysqld.exe") == 0) str_copy(out, n, "MySQL");
    else if (strcmp(lower, "svchost.exe") == 0) str_copy(out, n, "Windows Service Host");
    else if (strcmp(lower, "system") == 0) str_copy(out, n, "System");
    else {
        char tmp[PNET_MON_NAME_LEN];
        str_copy(tmp, sizeof(tmp), exe ? exe : "Unknown");
        size_t len = strlen(tmp);
        if (len > 4 && _stricmp(tmp + len - 4, ".exe") == 0) tmp[len - 4] = '\0';
        if (tmp[0]) tmp[0] = (char)toupper((unsigned char)tmp[0]);
        str_copy(out, n, tmp);
    }
}

static int process_name_from_snapshot(uint32_t pid, char *exe, size_t exe_n)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return 0;
    }
    do {
        if (pe.th32ProcessID == pid) {
            str_copy(exe, exe_n, pe.szExeFile);
            CloseHandle(snap);
            return 1;
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return 0;
}

static int read_process(uint32_t pid, char *name, size_t name_n, char *path, size_t path_n)
{
    char base[PNET_MON_NAME_LEN];
    path[0] = '\0';
    base[0] = '\0';

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (proc) {
        char exe_path[PNET_MON_PATH_LEN];
        DWORD plen = PNET_MON_PATH_LEN;
        if (QueryFullProcessImageNameA(proc, 0, exe_path, &plen)) {
            str_copy(path, path_n, exe_path);
            basename_only(exe_path, base, sizeof(base));
        }
        CloseHandle(proc);
    }
    if (base[0] == '\0') {
        if (!process_name_from_snapshot(pid, base, sizeof(base))) {
            if (pid == 0 || pid == 4) {
                friendly_name("System", name, name_n);
                return 0;
            }
            str_copy(name, name_n, "Unknown");
            return 0;
        }
    }
    friendly_name(base, name, name_n);
    return 1;
}

void pnet_monitor_snapshot_init(pnet_monitor_snapshot *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
}

int pnet_monitor_capture(pnet_monitor_snapshot *out)
{
    if (!out) return -1;
    pnet_monitor_snapshot_init(out);
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        str_copy(out->error, sizeof(out->error), "Winsock init failed");
        return -1;
    }

    pick_local_ip(out->local_ip, sizeof(out->local_ip));
    if (!pick_adapter_bytes(&out->bytes_in, &out->bytes_out, out->adapter, sizeof(out->adapter))) {
        str_copy(out->error, sizeof(out->error), "No active network adapter");
        WSACleanup();
        return -1;
    }

    pid_stats stats[PNET_MON_MAX_APPS];
    int stat_count = 0;
    memset(stats, 0, sizeof(stats));
    read_tcp(stats, &stat_count);
    read_udp(stats, &stat_count);

    for (int i = 0; i < stat_count; i++) {
        if (out->app_count >= PNET_MON_MAX_APPS) break;
        pid_stats *st = &stats[i];
        if (st->tcp_established == 0 && st->udp_endpoints == 0) continue;
        pnet_mon_app *app = &out->apps[out->app_count++];
        app->pid = st->pid;
        app->tcp_established = st->tcp_established;
        app->udp_endpoints = st->udp_endpoints;
        app->remote_public = st->remote_public;
        app->remote_lan = st->remote_lan;
        read_process(st->pid, app->name, sizeof(app->name), app->path, sizeof(app->path));
    }

    WSACleanup();
    return 0;
}

static int json_escape(const char *src, char *dst, size_t n)
{
    size_t w = 0;
    if (!dst || n == 0) return -1;
    for (const char *p = src ? src : ""; *p; p++) {
        const char *rep = NULL;
        char c = *p;
        if (c == '\\' || c == '"') {
            if (w + 2 >= n) return -1;
            dst[w++] = '\\';
            dst[w++] = c;
            continue;
        }
        if (c == '\n') rep = "\\n";
        else if (c == '\r') rep = "\\r";
        else if (c == '\t') rep = "\\t";
        if (rep) {
            size_t rl = strlen(rep);
            if (w + rl >= n) return -1;
            memcpy(dst + w, rep, rl);
            w += rl;
            continue;
        }
        if ((unsigned char)c < 0x20) continue;
        if (w + 1 >= n) return -1;
        dst[w++] = c;
    }
    if (w >= n) return -1;
    dst[w] = '\0';
    return (int)w;
}

int pnet_monitor_to_json(const pnet_monitor_snapshot *snap, char *buf, size_t buflen)
{
    if (!snap || !buf || buflen < 64) return -1;
    char esc_name[PNET_MON_NAME_LEN * 2];
    char esc_path[PNET_MON_PATH_LEN * 2];
    char esc_adapter[256];
    char esc_ip[96];
    json_escape(snap->local_ip, esc_ip, sizeof(esc_ip));
    json_escape(snap->adapter, esc_adapter, sizeof(esc_adapter));

    int n = snprintf(buf, buflen,
        "{\"ok\":true,\"local_ip\":\"%s\",\"adapter\":\"%s\",\"bytes_in\":%llu,\"bytes_out\":%llu,\"apps\":[",
        esc_ip, esc_adapter,
        (unsigned long long)snap->bytes_in,
        (unsigned long long)snap->bytes_out);
    if (n < 0 || (size_t)n >= buflen) return -1;

    for (int i = 0; i < snap->app_count; i++) {
        const pnet_mon_app *app = &snap->apps[i];
        json_escape(app->name, esc_name, sizeof(esc_name));
        json_escape(app->path, esc_path, sizeof(esc_path));
        int m = snprintf(buf + n, buflen - (size_t)n,
            "%s{\"pid\":%u,\"name\":\"%s\",\"path\":\"%s\",\"tcp\":%d,\"udp\":%d,\"remote_public\":%d,\"remote_lan\":%d}",
            i ? "," : "",
            (unsigned)app->pid, esc_name, esc_path,
            app->tcp_established, app->udp_endpoints, app->remote_public, app->remote_lan);
        if (m < 0 || (size_t)n + (size_t)m >= buflen) return -1;
        n += m;
    }
    if ((size_t)n + 2 >= buflen) return -1;
    buf[n++] = ']';
    buf[n++] = '}';
    buf[n] = '\0';
    return n;
}
