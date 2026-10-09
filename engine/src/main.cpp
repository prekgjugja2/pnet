/*
 * PNet scanner CLI — C++ front-end over the C discovery engine.
 * Usage:
 *   pnet_scan.exe [--json] [--ports] [--cidr 192.168.0.0/24] [--timeout 200]
 */
#include "pnet_scan.h"
#include "pnet_monitor.h"

#include <cstdio>
#include <cstring>
#include <string>

static void print_table(const pnet_scan_result &r)
{
    std::printf("PNet scan  %s\n", r.lan_cidr);
    std::printf("Gateway    %s\n", r.gateway[0] ? r.gateway : "-");
    std::printf("This PC    %s  %s\n", r.local_ip, r.local_mac);
    std::printf("Devices    %d\n\n", r.device_count);
    std::printf("%-16s %-18s %-8s %-6s %-12s %s\n",
                "IP", "MAC", "Status", "ms", "Vendor", "Name");
    std::printf("%-16s %-18s %-8s %-6s %-12s %s\n",
                "---------------", "-----------------", "-------", "-----", "-----------", "----");
    for (int i = 0; i < r.device_count; i++) {
        const pnet_device &d = r.devices[i];
        std::printf("%-16s %-18s %-8s %-6d %-12s %s\n",
                    d.ip,
                    d.mac[0] ? d.mac : "-",
                    d.online ? "online" : "offline",
                    d.ping_ms,
                    d.vendor[0] ? d.vendor : "-",
                    d.hostname);
        if (d.open_port_count > 0) {
            std::printf("  ports: ");
            for (int p = 0; p < d.open_port_count; p++)
                std::printf("%s%u", p ? "," : "", (unsigned)d.open_ports[p]);
            std::printf("\n");
        }
    }
}

static int run_monitor(bool as_json)
{
    pnet_monitor_snapshot snap;
    if (pnet_monitor_capture(&snap) != 0) {
        if (as_json) {
            std::printf("{\"ok\":false,\"error\":\"%s\"}\n",
                        snap.error[0] ? snap.error : "monitor failed");
        } else {
            std::fprintf(stderr, "Monitor failed: %s\n",
                         snap.error[0] ? snap.error : "unknown error");
        }
        return 1;
    }
    if (as_json) {
        std::string buf(512 * 1024, '\0');
        int n = pnet_monitor_to_json(&snap, &buf[0], buf.size());
        if (n < 0) {
            std::fprintf(stderr, "JSON buffer too small\n");
            return 1;
        }
        buf.resize((size_t)n);
        std::fwrite(buf.data(), 1, buf.size(), stdout);
        std::fputc('\n', stdout);
    } else {
        std::printf("PNet monitor  %s\n", snap.local_ip);
        std::printf("Adapter     %s\n", snap.adapter);
        std::printf("Bytes in    %llu\n", (unsigned long long)snap.bytes_in);
        std::printf("Bytes out   %llu\n", (unsigned long long)snap.bytes_out);
        std::printf("Apps        %d\n\n", snap.app_count);
        for (int i = 0; i < snap.app_count; i++) {
            const pnet_mon_app &a = snap.apps[i];
            std::printf("%-24s tcp=%d udp=%d public=%d lan=%d\n",
                        a.name, a.tcp_established, a.udp_endpoints,
                        a.remote_public, a.remote_lan);
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    pnet_scan_options opt;
    pnet_scan_options_init(&opt);
    bool as_json = false;
    bool monitor = false;
    const char *cidr = nullptr;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--json") == 0) {
            as_json = true;
        } else if (std::strcmp(argv[i], "--monitor") == 0) {
            monitor = true;
        } else if (std::strcmp(argv[i], "--ports") == 0) {
            opt.do_ports = 1;
        } else if (std::strcmp(argv[i], "--no-netbios") == 0) {
            opt.do_netbios = 0;
        } else if (std::strcmp(argv[i], "--cidr") == 0 && i + 1 < argc) {
            cidr = argv[++i];
        } else if (std::strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            opt.ping_timeout_ms = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            std::printf("Usage: pnet_scan [--json] [--monitor] [--ports] [--cidr x.x.x.x/24] [--timeout ms]\n");
            return 0;
        }
    }

    if (monitor) {
        return run_monitor(as_json);
    }

    opt.force_cidr = cidr;

    pnet_scan_result result;
    if (pnet_scan_lan(&opt, &result) != 0) {
        if (as_json)
            std::printf("{\"ok\":false,\"error\":\"%s\"}\n",
                        result.error[0] ? result.error : "scan failed");
        else
            std::fprintf(stderr, "Scan failed: %s\n",
                         result.error[0] ? result.error : "unknown error");
        return 1;
    }

    if (as_json) {
        /* Large enough for ~512 devices */
        std::string buf(2 * 1024 * 1024, '\0');
        int n = pnet_result_to_json(&result, &buf[0], buf.size());
        if (n < 0) {
            std::fprintf(stderr, "JSON buffer too small\n");
            return 1;
        }
        buf.resize((size_t)n);
        std::fwrite(buf.data(), 1, buf.size(), stdout);
        std::fputc('\n', stdout);
    } else {
        print_table(result);
    }
    return 0;
}
