/*
 * PNet Core Network Scanner Engine
 * C API — portable discovery primitives used by the C++ orchestrator.
 */
#ifndef PNET_SCAN_H
#define PNET_SCAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define PNET_MAX_DEVICES 512
#define PNET_NAME_LEN 128
#define PNET_VENDOR_LEN 64
#define PNET_TYPE_LEN 32

typedef struct pnet_device {
    char ip[46];
    char mac[18];
    char hostname[PNET_NAME_LEN];
    char vendor[PNET_VENDOR_LEN];
    char type[PNET_TYPE_LEN];
    int online;
    int ping_ms;
    uint16_t open_ports[16];
    int open_port_count;
} pnet_device;

typedef struct pnet_scan_result {
    char lan_cidr[32];
    char gateway[46];
    char local_ip[46];
    char local_mac[18];
    int device_count;
    pnet_device devices[PNET_MAX_DEVICES];
    char error[256];
} pnet_scan_result;

typedef struct pnet_scan_options {
    int ping_timeout_ms;   /* default 200 */
    int do_netbios;        /* default 1 */
    int do_ports;          /* default 0 — common ports */
    int max_hosts;         /* default 254 */
    const char *force_cidr;/* optional "192.168.0.0/24" */
} pnet_scan_options;

void pnet_scan_options_init(pnet_scan_options *opt);
int pnet_scan_lan(const pnet_scan_options *opt, pnet_scan_result *out);
int pnet_result_to_json(const pnet_scan_result *result, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* PNET_SCAN_H */
