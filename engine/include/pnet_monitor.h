/*
 * PNet traffic monitor — Windows process + connection snapshot.
 */
#ifndef PNET_MONITOR_H
#define PNET_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define PNET_MON_MAX_APPS 256
#define PNET_MON_NAME_LEN 128
#define PNET_MON_PATH_LEN 260

typedef struct pnet_mon_app {
    uint32_t pid;
    char name[PNET_MON_NAME_LEN];
    char path[PNET_MON_PATH_LEN];
    int tcp_established;
    int udp_endpoints;
    int remote_public;
    int remote_lan;
} pnet_mon_app;

typedef struct pnet_monitor_snapshot {
    char local_ip[46];
    char adapter[128];
    uint64_t bytes_in;
    uint64_t bytes_out;
    int app_count;
    pnet_mon_app apps[PNET_MON_MAX_APPS];
    char error[256];
} pnet_monitor_snapshot;

void pnet_monitor_snapshot_init(pnet_monitor_snapshot *out);
int pnet_monitor_capture(pnet_monitor_snapshot *out);
int pnet_monitor_to_json(const pnet_monitor_snapshot *snap, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* PNET_MONITOR_H */
