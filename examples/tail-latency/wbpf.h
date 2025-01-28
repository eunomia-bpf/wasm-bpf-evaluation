#ifndef WBPF_H
#define WBPF_H


enum wbpf_sync_mode{
    WBPF_SYNC_CREATE=0,
    WBPF_SYNC_FLUSH=1,
    WBPF_SYNC_NOTIFY=2,
    WBPF_SYNC_COLLECT=3,
};

struct wbpf_sync_info{
    int sync_mode;
    union{
            char sync_ip[10][16];
            int trace_id;
    };

};

#endif /* WBPF_H */
