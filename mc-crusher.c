/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *  mc-crusher - make the rabbit fear you
 *
 *       https://github.com/dormando/mc-crusher
 *
 *  Copyright 2011 Dormando.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      dormando <dormando@rydia.net>
 */
/*
 * basic logic for replay real workload:
 *      read workload into a giant global buffer
 *      each thread keeps unique index on global buffer
 *      upon completion of current request, the thread
 *      increment the counter. when counter end it wrap back
 *      to beginning of the buffer.
 * 
 *      1. add path and workload replay flag
 *      2. add workload to buffer during initialization
 *      3. modified "run_counter"
 *      4. add workload buffer index to each connections
 *      
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <event.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <sysexits.h>
#include <stddef.h>
#include <sys/stat.h>
#include <signal.h>
#ifdef USE_TLS
#include <openssl/ssl.h>
#include <poll.h>
#endif
// for pow() for zipf calculations.
#include <math.h>

#include "protocol_binary.h"
#include "pcg-basic.h"
#include "itoa_ljust.h"
#include "murmur3.h" //junyaoy 01/13/2022
#include "twitter_2020.h"
#include <sched.h>


#define SHARED_RBUF_SIZE 1024 * 64
#define SHARED_VALUE_SIZE 1024 * 1024

//junyaoy 12/20/2021
#define RBUF_SIZE 1024 * 64
#define WBUF_SIZE 1024 * 64
#define VALUE_MAX_SIZE 1024 * 1024
#define HIT 0
#define MISS 1
//junyaoy 01/13/2022
#define INDEX_INIT_INTERVAL 40000

//junyaoy 01/20/2022
#define SIM_TYPE 1 //simple preprocessed traces
#define TW_TYPE 2 //twitter trace see twitter_2020.c for format

//junyaoy 2/12/2022
#define LAT_WARM_CNT 1000
// avoiding some hacks for finding member size.
#define SOCK_MAX 100



char host_default[NI_MAXHOST] = "127.0.0.1";
char port_num_default[NI_MAXSERV] = "11211";
char sock_path_default[SOCK_MAX];
int alarm_fired = 0;

//junyaoy 01/13/2022 global pointer for workload buffer
uint64_t *global_workload_buf;
uint64_t workload_len;
uint8_t workload_type; //1/22/2022
uint64_t conn_init_index;


//junyaoy 1/17/2022 use to stop program after all connection exits
uint32_t total_threads;
uint32_t exited_num;
pthread_mutex_t exit_lock;

//junyaoy 2/12/2022 use to protect append to latency file
pthread_mutex_t lat_append_lock;

#ifdef USE_TLS
SSL_CTX *global_ctx;
#endif

enum conn_states {
    conn_connecting = 0,
    conn_sending,
    conn_reading,
    conn_sleeping,
    //junyaoy 12/20/2021
    //new state for setback purpose
    conn_setback_reading
};

enum conn_rand {
    conn_rand_off = 0,
    conn_rand_uniform,
    conn_rand_zipf,
    conn_rand_workload //junyaoy 01/13/2022 explicit workload option 
};

typedef struct _mc_thread {
    pthread_t thread_id;
    uint32_t cpu_num; //junyaoy optional 
    struct event_base *base;
    unsigned char *shared_value;
    unsigned char *shared_rbuf;
} mc_thread;

// data shared within a single template.
// a thread can have multiple templates in it, so key_prefix/value can't be
// part of mc_thread.
// TODO: Move more of the static values in here. counts/etc.
typedef struct _mc_tshared {
    size_t key_prefix_len;
    size_t cmd_postfix_len;
    unsigned char key_prefix[284];
    unsigned char second_key_prefix[284]; //this is used for setback //junyaoy 12/16/2021
    unsigned char cmd_postfix[1024];
    unsigned char value[VALUE_MAX_SIZE];     /* manually specified seed value */
} mc_tshared;

//every connection use it's own connection struct
struct connection {
    /* Owner thread */
    mc_thread *t;
    /* some same-template shared data */
    mc_tshared *s;

    /* host */
    char host[NI_MAXHOST];
    char port_num[NI_MAXSERV];

    /* Event stuff */
    int fd;
    struct event ev;
    enum conn_states state;
    enum conn_states next_state;
    short ev_flags;
#ifdef USE_TLS
    SSL *ssl;
#endif

    /* Counters, bits, flags for individual senders/getters. */
    int mget_count;                /* # of ascii mget keys to send at once */
    int value_size;
    int use_shared_value;
    int wbuf_written;
    int wbuf_towrite;
    uint32_t expire;
    uint32_t flags;
    /*junyaoy 
      for setback purpose, record hit or miss*/
    int read_info;

    uint64_t pipelines; /* number of repeated commands per write */
    int usleep; /* us to sleep between write runs */
    uint64_t stop_after; /* run this many write events then stop */
    /* Buffers */
    uint64_t *cur_key;
    uint64_t *write_count;
    uint32_t key_count;
    unsigned char *wbuf_pos;
    uint64_t workload_buf_index; //junyaoy 01/13/2022

    /* random number handling */
    pcg32_random_t rng; // every connection can have its own rng.
    enum conn_rand rand; // randomized options for run_counter().
    double zipf_skew;
    double zipf_t; // precalc against the skew
    uint32_t murmur3_seed; //junyaoy 01/13/2022

    /* time pacing */
    struct timeval next_sleep;
    struct timeval tosleep;
    
    //junyaoy change reader return to void*
    /* reader/writer function pointers */
    void (*writer)(void *arg);
    void (*reader)(void *arg);
  

    /* helper function specific to the generic ascii writer */
    int (*ascii_format)(struct connection *c);
    int (*bin_format)(struct connection *c);
    int (*bin_prep_cmd)(struct connection *c);
    
    struct timeval st; //jy
    int latency_dump_len;
    FILE* latency_dump_fd; //2/10/2022
    int latency_curr_index;
    uint32_t *resp_times; //junyaoy 2/10/2022 dump certain number of response time
    //junyaoy 12/016/2021  per connection buffer, used for setback
    unsigned char rbuf[RBUF_SIZE]; //check server return content to identify miss
    unsigned char wbuf[WBUF_SIZE]; // putting this at the end to get more of the above into fewer cachelines.
};


/*junyaoy 12/20/2021 modified prototype**/
static void ascii_write_flat_to_client_noupdate(void *arg);
static inline void run_setback_write(struct connection *c);
static void setback_read_from_client(void *arg);

static void client_handler(const int fd, const short which, void *arg);
static void sleep_handler(const int fd, const short which, void *arg);
static void setup_thread(mc_thread *t);
static void create_thread(mc_thread *t);
static void start_template(struct connection *template, int conns_tomake, bool use_sock);
static inline void run_write(struct connection *c);

static uint32_t zipf_sample(pcg32_random_t *rng, double t, double skew);
static double zipf_calc_t(uint32_t n, double skew);

static int update_conn_event(struct connection *c, const int new_flags)
{
    if (c->ev_flags == new_flags) return 2;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = new_flags;
    event_set(&c->ev, c->fd, new_flags, client_handler, (void *)c);
    event_base_set(c->t->base, &c->ev);

    if (event_add(&c->ev, 0) == -1) return 0;
    return 1;
}

static int update_conn_event_sleep(struct connection *c)
{
    struct timeval t = {.tv_sec = 0, .tv_usec = 0};
    struct timeval now;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = 0; // clear event flags in case we ping-pong to other modes
    evtimer_set(&c->ev, sleep_handler, (void *)c);
    event_base_set(c->t->base, &c->ev);

    gettimeofday(&now, NULL);

    // every time we come into this loop, we've run once. which means we
    // always have to advance the next_sleep timer.
    if (c->next_sleep.tv_sec == 0) {
        // initialize next_sleep as late as possible to avoid spamming.
        gettimeofday(&c->next_sleep, NULL);
    }
    memcpy(&t, &c->next_sleep, sizeof(struct timeval));
    timeradd(&t, &c->tosleep, &c->next_sleep);

    timersub(&c->next_sleep, &now, &t);
    // so far as I can tell, it treats times in the past as "Wake up
    // immediately".
    evtimer_add(&c->ev, &t);

    return 1;
}

static void write_flat(struct connection *c, enum conn_states next_state) {
    int written = 0;
#ifdef USE_TLS
    written = SSL_write(c->ssl, c->wbuf + c->wbuf_written, c->wbuf_towrite);
#else
    written = write(c->fd, c->wbuf + c->wbuf_written, c->wbuf_towrite);
#endif
    if (written == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
            // the sender always checks for reads. not necessary to change?
            c->state = conn_sending;
            return;
        } else {
            perror("Write error to client");
            exit(1);
            return;
        }
    }

    c->wbuf_towrite -= written;
    if (c->wbuf_towrite > 0) {
        update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
        //fprintf(stderr, "Draining flat buffer %d by (%d)\n", c->wbuf_towrite, written);
        c->wbuf_written += written;
        c->state = conn_sending;
    } else {
        //jy write done, start timer 02/12/2022 
        gettimeofday(&(c->st), NULL); 
        //
        c->state = next_state;
        if (c->state == conn_reading) {
            update_conn_event(c, EV_READ | EV_PERSIST);
        } else if (c->state == conn_sending) {
            update_conn_event(c, EV_READ | EV_WRITE | EV_PERSIST);
        } else if (c->state == conn_sleeping) {
            update_conn_event_sleep(c);
        }
    }
}

static inline void run_counter(struct connection *c) {
    ++*c->write_count; // for limiting requests in a particular test
    switch (c->rand) {
        case conn_rand_off:
            if (++*c->cur_key >= c->key_count) {
                //fprintf(stdout, "Did %llu writes\n", (unsigned long long)c->key_count);
                *c->cur_key = 0;
            }
            break;
        case conn_rand_uniform:
            *c->cur_key = pcg32_boundedrand_r(&c->rng, c->key_count);
            break;
        case conn_rand_zipf:
            *c->cur_key = zipf_sample(&c->rng, c->zipf_t, c->zipf_skew);
            break;
        case conn_rand_workload: //junyaoy 1/13/2022
            *c->cur_key = global_workload_buf[c->workload_buf_index];
            if (++c->workload_buf_index >= workload_len){
                c->workload_buf_index = 0;
            }
            break;
    }
}

// adapted from: https://medium.com/@jasoncrease/rejection-sampling-the-zipf-distribution-6b359792cffa
static uint32_t zipf_sample(pcg32_random_t *rng, double t, double skew) {
    double inv_B;
    double X, R;
    double inv_skew = 1.0 / (1.0 - skew);
    for (;;) {
        // always need two random samples, so exploit some cache coherency and
        // grab them at the same time.
        double rand_b = pcg32_double_r(rng);
        double rand_y = pcg32_double_r(rng);

        double t_b = rand_b * t;
        // inv cdf for b.
        if (t_b <= 1) {
            inv_B = t_b;
        } else {
            inv_B = pow(t_b * (1.0 - skew) + skew, inv_skew);
        }

        X = floor(inv_B - 1.0);
        R = pow(X, -skew) /
            ((X <= 1.0 ? 1.0 / t : pow(inv_B, -skew) / t) * t);

        if (rand_y < R) {
            return (uint32_t)X;
        }
    }
}

static double zipf_calc_t(uint32_t n, double skew) {
    return (pow((double)n, 1.0 - skew) - skew) / (1 - skew);
}

/* === BINARY PROTOCOL === */

static int bin_key_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    return (p - (char *)c->wbuf_pos);
}

// can generalize this a bit further.
static int bin_prep_getq(struct connection *c) {
    protocol_binary_request_get *pkt = (protocol_binary_request_get *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_GETQ;

    int l = sizeof(protocol_binary_request_get);
    c->wbuf_pos += l;
    return l;
}

static int bin_prep_get(struct connection *c) {
    protocol_binary_request_get *pkt = (protocol_binary_request_get *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_GET;

    int l = sizeof(protocol_binary_request_get);
    c->wbuf_pos += l;
    return l;
}

static int bin_prep_set(struct connection *c) {
    protocol_binary_request_set *pkt = (protocol_binary_request_set *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_SET;
    pkt->message.header.request.extlen = 8; /* flags + exptime */
    pkt->message.body.flags = htonl(c->flags);
    pkt->message.body.expiration = htonl(c->expire);

    int l = sizeof(protocol_binary_request_header) + 8;
    c->wbuf_pos += l;
    return l;
}

/* slightly crazy; since bin_prep_set changes wbuf_pos create the packet
 * pointer first, run original prep, then switch the command out.
 */
static int bin_prep_setq(struct connection *c) {
    protocol_binary_request_set *pkt = (protocol_binary_request_set *)c->wbuf_pos;
    int l = bin_prep_set(c);
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_SETQ;
    // Continue to send since we don't expect to read anything.
    c->next_state = conn_sending;
    return l;
}

static int bin_prep_touch(struct connection *c) {
    protocol_binary_request_touch *pkt = (protocol_binary_request_touch *)c->wbuf_pos;
    pkt->message.header.request.opcode = PROTOCOL_BINARY_CMD_TOUCH;
    pkt->message.header.request.extlen = 4; /* exptime */
    pkt->message.body.expiration = htonl(c->expire);

    int l = sizeof(protocol_binary_request_header) + 4;
    c->wbuf_pos += l;
    return l;
}

static void bin_write_flat_to_client(void *arg) {
    struct connection *c = arg;
    protocol_binary_request_header *pkt = (protocol_binary_request_header *)c->wbuf_pos;
    memset(pkt, 0, sizeof(protocol_binary_request_header));
    pkt->request.magic = PROTOCOL_BINARY_REQ;

    c->bin_prep_cmd(c);
    // FIXME: move wbuf_pos here instead of in the func.
    int keylen = c->bin_format(c);
    c->wbuf_pos += keylen;
    int bodylen = keylen + pkt->request.extlen;
    pkt->request.keylen = htons(keylen);

    if (c->value_size) {
        bodylen += c->value_size;
        if (c->use_shared_value) {
            memcpy(c->wbuf_pos, c->t->shared_value, c->value_size);
        } else {
            memcpy(c->wbuf_pos, c->s->value, c->value_size);
        }
        c->wbuf_pos += c->value_size;
    }

    pkt->request.bodylen = htonl(bodylen);
    run_counter(c);
}

/* === ASCII PROTOCOL TESTS === */

static int ascii_mget_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    *p = ' ';
    return (p - (char *)c->wbuf_pos) + 1;
}

static void ascii_write_flat_mget_to_client(void *arg) {
    struct connection *c = arg;
    int i;
    memcpy(c->wbuf_pos, "get ", 4);
    c->wbuf_pos += 4;

    for (i = 0; i < c->mget_count; i++) {
        c->wbuf_pos += ascii_mget_format(c);
        run_counter(c);
    }

    c->wbuf_pos[0] = '\r';
    c->wbuf_pos[1] = '\n';
    c->wbuf_pos += 2;
}




static int ascii_set_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    *p = ' ';
    p = itoa_u32(c->flags, p+1);
    *p = ' ';
    p = itoa_u32(c->expire, p+1);
    *p = ' ';
    p = itoa_u32(c->value_size, p+1);
    *p = '\r';
    *(p+1) = '\n';
    return (p - (char *)c->wbuf_pos) + 2;
}

static int ascii_incrdecr_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    *p = ' ';
    *(p+1) = '1';
    *(p+2) = '\r';
    *(p+3) = '\n';
    return (p - (char *)c->wbuf_pos) + 4;
}

static int ascii_touch_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    *p = ' ';
    p = itoa_u32(c->expire, p+1);
    *p = '\r';
    *(p+1) = '\n';
    return (p - (char *)c->wbuf_pos) + 2;
}

// get, delete, and so on.
static int ascii_single_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    // printf("write: %c%c%c\n",p[0],p[1],p[2]);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    *p = ' ';
    *(p+1) = '\r';
    *(p+2) = '\n';
    return (p - (char *)c->wbuf_pos) + 3;
}

// meta commands: cmd key flags tokens
static int ascii_metacmd_format(struct connection *c) {
    char *p = c->wbuf_pos;
    memcpy(p, c->s->key_prefix, c->s->key_prefix_len);
    p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
    // now the flags/tokens
    if (c->s->cmd_postfix_len) {
        *p = ' ';
        p++;
        memcpy(p, c->s->cmd_postfix, c->s->cmd_postfix_len);
        p += c->s->cmd_postfix_len;
    }
    *(p) = '\r';
    *(p+1) = '\n';
    return (p - (char *)c->wbuf_pos) + 2;
}


//junyaoy 12/16/2021
static int ascii_getset_format(struct connection *c) {
 
        //this is not a good check
        //consider buff per connection or use flag later
        char *p = c->wbuf_pos;
        memcpy(p, c->s->second_key_prefix, c->s->key_prefix_len);
        p = itoa_u64(*c->cur_key, p + c->s->key_prefix_len);
        *p = ' ';
        p = itoa_u32(c->flags, p+1);
        *p = ' ';
        p = itoa_u32(c->expire, p+1);
        *p = ' ';
        p = itoa_u32(c->value_size, p+1);
        *p = '\r';
        *(p+1) = '\n';
        return (p - (char *)c->wbuf_pos) + 2;
   
}

// for fast-writing to wbuf
// WARNING: sets can easily blow this up :(
static void ascii_write_flat_to_client(void *arg) {
    struct connection *c = arg;
    c->wbuf_pos += c->ascii_format(c);
    if (c->value_size) {
        if (c->use_shared_value) {
            memcpy(c->wbuf_pos, c->t->shared_value, c->value_size);
        } else {
            memcpy(c->wbuf_pos, c->s->value, c->value_size);
        }
        c->wbuf_pos += c->value_size;
        c->wbuf_pos[0] = '\r';
        c->wbuf_pos[1] = '\n';
        c->wbuf_pos += 2;
    }
    run_counter(c);
}


static void ascii_write_flat_to_client_noupdate(void *arg) {
    struct connection *c = arg;
    c->wbuf_pos += c->ascii_format(c);
    if (c->value_size && c->read_info==MISS) {
        if (c->use_shared_value) {
            memcpy(c->wbuf_pos, c->t->shared_value, c->value_size);
        } else {
            memcpy(c->wbuf_pos, c->s->value, c->value_size);
        }
        c->wbuf_pos += c->value_size;
        c->wbuf_pos[0] = '\r';
        c->wbuf_pos[1] = '\n';
        c->wbuf_pos += 2;
    }
}

/* === READERS === */
// Seems like leaving some data in SSL_read causes wobbles in performance.
// SSL_read() returns after each individual TLS frame read, not with a full read
// buffer.
#ifdef USE_TLS
#define READ_MIN 1
#else
#define READ_MIN 2096
#endif

static void read_from_client(void *arg) {
    struct connection *c = arg;
    int rbytes = 0;
    for (;;) {
#ifdef USE_TLS
        rbytes = SSL_read(c->ssl, c->rbuf, RBUF_SIZE);
#else
        rbytes = read(c->fd, c->rbuf, RBUF_SIZE);
#endif  

        if (rbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                exit(-1);
                break;
            } else {
                perror("Read error from client");
            }
        }else if(rbytes > 0){
            //server response get
            //02/12/2022 store duration
            struct timeval et;
            gettimeofday(&et, NULL);
            if (*(c->write_count) > LAT_WARM_CNT && c->latency_curr_index < c->latency_dump_len) { 
                //warmup time
                c->resp_times[c->latency_curr_index]= ((et.tv_sec - (c->st).tv_sec) * 1000000) + (et.tv_usec - (c->st).tv_usec);
                c->latency_curr_index++;
            }
        }
       
        if (rbytes < READ_MIN)
            break; /* don't call read() again unless we may get data */
        //junyaoy 12/10/2021 test
        
    }
}

//junyaoy 12/06/1997
static inline void run_setback_write(struct connection *c) {
    int i;
    c->wbuf_pos = c->wbuf;
   
    c->wbuf_pos += ascii_getset_format(c);
    if (c->value_size) {
        if (c->use_shared_value) {
            memcpy(c->wbuf_pos, c->t->shared_value, c->value_size);
        } else {
            memcpy(c->wbuf_pos, c->s->value, c->value_size);
        }
        c->wbuf_pos += c->value_size;
        c->wbuf_pos[0] = '\r';
        c->wbuf_pos[1] = '\n';
        c->wbuf_pos += 2;

    //    printf("write: %.100sdone\n",c->wbuf);
    }
    {
        // not using iovecs, save some libc/kernel looping.
        c->wbuf_towrite = c->wbuf_pos - (unsigned char *)&c->wbuf;
        c->wbuf_written = 0;
        //fprintf(stderr, "WBUF towrite: %d\n", c->wbuf_towrite);
        int count = 0;
        int fuck = 0;
        for(;;) {
            int written = 0;
            #ifdef USE_TLS
                written = SSL_write(c->ssl, c->wbuf + c->wbuf_written, c->wbuf_towrite);
            #else   
                written = write(c->fd, c->wbuf + c->wbuf_written, c->wbuf_towrite);
            #endif


          //      printf("\nwritten: %d count:%d towrite:%d\n", written, fuck++, c->wbuf_towrite);
                
                if(written == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        count++;
                        if (count < 11){
                            continue;
                        }else{
                            break;
                        }
                    } else {
                        perror("Write error to client");
                        exit(1);
                        return;
                    }
                }else{


                    c->wbuf_towrite -= written;
                    c->wbuf_written += written;
                    if(c->wbuf_towrite <= 0) {
                        c->state = c->next_state;
                        update_conn_event(c, EV_READ | EV_PERSIST);
                        return;
                    }else{
                        continue;
                    }
                }

              

        }
    }
}



//junyaoy 12/16/2021
//setback_reader function
static void setback_read_from_client(void *arg) {
    struct connection *c = arg;
    int rbytes = 0;
    int count = 0;
    for (;;) {
#ifdef USE_TLS
        rbytes = SSL_read(c->ssl, c->rbuf, RBUF_SIZE);
#else
        rbytes = read(c->fd, c->rbuf, RBUF_SIZE);
#endif
        if (rbytes == -1) {
         
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                count++;
                if(count < 11)
                    continue; //get miss/hit info //after 10 times stop
                else
                    break;
            } else {
                perror("Read error from client");
            }
        }else if (rbytes > 0){
    //        printf("rbuf:%.100s, size:%d\n",c->rbuf,rbytes);
            if (strncmp(c->rbuf, "END",3) == 0) {
                memset(c->rbuf,0,(size_t)RBUF_SIZE);
                c->read_info = MISS;
                //this is miss donot store latency
                //wait for set done
                return;         
            } else {
                //02/12/2022 jy store latency if hit
                struct timeval et;
                gettimeofday(&et, NULL);
                if (*(c->write_count) > LAT_WARM_CNT && c->latency_curr_index < c->latency_dump_len) { 
                    c->resp_times[c->latency_curr_index]= ((et.tv_sec - (c->st).tv_sec) * 1000000) + (et.tv_usec - (c->st).tv_usec);
                    c->latency_curr_index++;
                }
            }
            memset(c->rbuf,0,(size_t)RBUF_SIZE);
            break;
        }
       
        if (rbytes < READ_MIN)
            break; /* don't call read() again unless we may get data */
        
    }

    //update counter infomation, after know it is hit
    run_counter(c); 
    c->read_info = HIT;
    return;
}


/* === HANDLERS === */

static void sleep_handler(const int fd, const short which, void *arg) {
    struct connection *c = (struct connection *)arg;
    c->next_state = conn_sleeping;
    c->reader(c);
    run_write(c);
}

static inline void run_write(struct connection *c) {
    int i;
    c->wbuf_pos = c->wbuf;
    //set up bufer, for actual write
    //curr key also updated after filled the buffer
    //*we need to set up the set back command here 
    //so on miss, we can fire this
    //
    for (i = 0; i < c->pipelines; i++) {
        c->writer(c);
    //    printf("write: %.100sdone\n",c->wbuf);
    }
    {
        // not using iovecs, save some libc/kernel looping.
        c->wbuf_towrite = c->wbuf_pos - (unsigned char *)&c->wbuf;
        c->wbuf_written = 0;
        //fprintf(stderr, "WBUF towrite: %d\n", c->wbuf_towrite);
        write_flat(c, c->next_state);
    }
    if (c->stop_after && *c->write_count >= c->stop_after) {
        //dump out latency to the specified file
        //protect it, just to makesure append to file works properly
        pthread_mutex_lock(&lat_append_lock);
        for (int i = 0; i<c->latency_curr_index; i++) {
            fprintf(c->latency_dump_fd, "%d\n", c->resp_times[i]);
        }
        pthread_mutex_unlock(&lat_append_lock);
        event_del(&c->ev);
    }
}

static void client_handler(const int fd, const short which, void *arg) {
    int ret_info;//junyaoy 12/20/2021 check hit/miss
    struct connection *c = (struct connection *)arg;
    int err = 0;
    socklen_t errsize = sizeof(err);
    int written = 0;
   // printf("\n\n\n\nwrite count: %llu\n", *c->write_count); 
    switch (c->state) {
    case conn_connecting:
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &errsize) < 0) {
            return;
        }
        if (err != 0) {
            return;
        }
        c->state = conn_sending;
        update_conn_event(c, EV_READ | EV_PERSIST);
       
    case conn_sending:
        if (which & EV_READ) {
            c->reader(c);
        }

       
        if (which & EV_WRITE) {

            //if last write field,attempt to write it first
            if (c->wbuf_towrite) {
                write_flat(c, c->next_state);
            }

            if (c->wbuf_towrite == 0) {
                run_write(c);
            }
        }
        break;
    case conn_reading:
        c->reader(c);

        c->state = conn_sending;
        if (c->wbuf_towrite <= 0){
            run_write(c);
        }
        break;
    case conn_setback_reading:
        c->reader(c);
  //      printf("to_write: %d, flag: %d\n",c->wbuf_towrite, which);
        if(c->read_info == HIT){
    //        printf("\nhit\n");
            c->state = conn_sending;
            if (c->wbuf_towrite <= 0){
                run_write(c);
            }
        }else{
      //      printf("\nmiss\n");
            //setback
            run_setback_write(c);
            
        }
        break;
    }
}

/* === TLS code === */

#ifdef USE_TLS
// Can add/ignore flags/settings explicitly here.
static int ssl_init(void) {
    OPENSSL_init_ssl(0, NULL);

    global_ctx = SSL_CTX_new(TLS_client_method());
    if (global_ctx == NULL) {
        fprintf(stderr, "failed to initialize OpenSSL\n");
        exit(1);
    }
    int flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
    SSL_CTX_set_options(global_ctx, flags);
    fprintf(stderr, "Initialized OpenSSL\n");
}
#endif

#define U_PER_S 1000000
static void timeval_split(const uint64_t in, long int *outs, long int *outu) {
    if (in >= U_PER_S) {
        *outs = in / U_PER_S;
        *outu = in - (*outs * U_PER_S);
    } else {
        *outs = 0;
        *outu = in;
    }
}

static int new_connection(struct connection *t, char *sock_path)
{
    int sock;
    struct addrinfo *ai;
    struct addrinfo *ai_next;
    struct addrinfo hints = { .ai_flags = AI_PASSIVE,
                              .ai_family = AF_UNSPEC };
    struct sockaddr_un un_addr;
    int flags = 1;
    int error;
    struct connection *c = (struct connection *)malloc(sizeof(struct connection));
    memcpy(c, t, sizeof(struct connection));

    //junyaoy 02/20/2022 if latency fd != null, allocate a buffer for it
    if (c->latency_dump_fd != NULL && c->latency_dump_len != 0) {
        c->resp_times = malloc(sizeof(uint32_t)*c->latency_dump_len);
    } 

    // no reason to avoid initializing an rng. this gives us a sequence unique
    // to the memory address of this particular connection.
    // could also mix or adjust time, but according to the PCG documentation
    // this shouldn't matter and we're not after secure randomization.
    // TODO: Should find some way to make this deterministic.
    pcg32_srandom_r(&c->rng, time(NULL), (intptr_t)c);
    if (t->rand == conn_rand_zipf) {
        c->zipf_t = zipf_calc_t(c->key_count, c->zipf_skew);
    }

    if (c->rand == conn_rand_workload) {
        c->workload_buf_index = conn_init_index;
        conn_init_index = conn_init_index + INDEX_INIT_INTERVAL % workload_len;
    }

    if (sock_path == NULL) {
        error = getaddrinfo(c->host, c->port_num, &hints, &ai);
        if (error != 0) {
            if (error != EAI_SYSTEM) {
                fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
            } else {
                perror("getaddrinfo()");
            }
            freeaddrinfo(ai);
            return -1;
        }

        for (ai_next = ai; ai_next; ai_next = ai_next->ai_next) {
            sock = socket(ai_next->ai_family, ai_next->ai_socktype, ai_next->ai_protocol);
            if (sock == -1) {
                perror("socket");
                continue;
            } else {
                break;
            }
        }

        if (sock < 0) {
            fprintf(stderr, "getaddrinfo failed to provide any valid addresses: %s[%s]\n",
                    c->host, c->port_num);
            freeaddrinfo(ai);
            return -1;
        }

        if ( (flags = fcntl(sock, F_GETFL, 0)) < 0 ||
            fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sock);
            freeaddrinfo(ai);
            return -1;
        }

        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

        if (connect(sock, ai_next->ai_addr, ai_next->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                close(sock);
                freeaddrinfo(ai);
                return -1;
            }
        }

        freeaddrinfo(ai);
    } else {
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock == -1) {
            perror("socket");
            return -1;
        }

        if ( (flags = fcntl(sock, F_GETFL, 0)) < 0 ||
            fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sock);
            return -1;
        }

        memset(&un_addr, 0, sizeof(un_addr));
        un_addr.sun_family = AF_UNIX;
        strncpy(un_addr.sun_path, sock_path, SOCK_MAX-1);
        if (connect(sock, (struct sockaddr *)&un_addr, sizeof(un_addr)) == -1) {
            if (errno != EINPROGRESS) {
                close(sock);
                perror("Failed to connect to unix socket");
                return -1;
            }
        }
    }

    c->fd = sock;
    c->state = conn_connecting;
    c->ev_flags = EV_WRITE;
#ifdef USE_TLS
    c->ssl = SSL_new(global_ctx);
    SSL_set_fd(c->ssl, sock);
    // we want the benchmark to generally start all at once. I don't want to
    // spread the handshake stuff through the code either.
    for (;;) {
        struct pollfd p = { .fd = sock };
        int ret = SSL_connect(c->ssl);
        if (ret == 1) {
            break;
        }
        switch (SSL_get_error(c->ssl, ret)) {
            case SSL_ERROR_WANT_READ:
                p.events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                p.events = POLLOUT;
                break;
            default:
                perror("Unhandled OpenSSL error while connecting");
                exit(1);
        }
        poll(&p, 1, 5000 * 1000);
        if ((p.revents & (POLLIN|POLLOUT)) == 0) {
            fprintf(stderr, "Socket hangup while waiting for SSL connection\n");
            exit(1);
        }
    }
#endif

    if (c->usleep) {
        // spread out the initial wakeup times
        long int initsleep = pcg32_boundedrand_r(&c->rng, c->usleep);
        long int initsleep_s = 0;
        timeval_split(c->usleep, &c->tosleep.tv_sec, &c->tosleep.tv_usec);
        timeval_split(initsleep, &initsleep_s, &initsleep);
        struct timeval t = {.tv_sec = initsleep_s, .tv_usec = initsleep};
        evtimer_set(&c->ev, sleep_handler, (void *)c);
        event_base_set(c->t->base, &c->ev);
        evtimer_add(&c->ev, &t);
    } else {
        event_set(&c->ev, sock, c->ev_flags, client_handler, (void *)c);
        event_base_set(c->t->base, &c->ev);
        event_add(&c->ev, NULL);
    }

    return sock;
}

/* Get a little verbose to avoid a big if/else if tree */
static void parse_config_line(mc_thread *main_thread, char *line, bool use_sock) {
    char *in_progress, *token;
    struct connection template;
    int conns_tomake = 1;
    int newsock;
    int i, x;
    char *tmp;
    char *sender = NULL;
    char *reader = NULL;
    int add_space = 0;
    int new_thread = 0;
    uint32_t* cpu_afin_arr = NULL; // junyaoy 01/30/2022
    char *cpu_afin_path = NULL;
    char key_prefix_tmp[270];
    char cmd_postfix_tmp[1024];
    //junyaoy 01/13/2022 
    char *workload_path_tmp;
    char *latency_dump_path_tmp = NULL;

    enum {
        SEND = 0,
        RECV,
        TIME,
        USLEEP,
        COUNT,
        CONNS,
        EXPIRE,
        FLAGS,
        KEY_PREFIX,
        CMD_POSTFIX,
        KEY_LEN,
        KEY_GENERATE,
        VALUE_SIZE,
        VALUE_RANGE,
        VALUE_RANGE_STEP,
        MGET_COUNT,
        VALUE,
        LIVE_RAND,
        LIVE_RAND_ZIPF,
        REAL_WORKLOAD, //junyaoy 1/13/2022
        STOP_AFTER,
        KEY_COUNT,
        HOST,
        PORT,
        THREAD,
        PIPELINES,
        ZIPF_SKEW,
        WORKLOAD_PATH, //junyaoy 1/13/2022
        WORKLOAD_LENGTH, //junyaoy 1/13/2022 if length is larger than workload, fit entire trace in to buffer.
        WORKLOAD_TYPE, //junyaoy 1/13/2022 handle separate trace type, mostly for later potential complex trace treament
        CPU_AFIN_PATH, //junyaoy /1/30/2022
        LATENCY_DUMP_PATH, //junyaoy 2/10/2022
        LATENCY_DUMP_LEN //junyaoy 2/10/2022 dump len per connection
    };

    char *const key_options[] = {
        [SEND]             = "send",
        [RECV]             = "recv",
        [TIME]             = "time",
        [USLEEP]           = "usleep",
        [COUNT]            = "count",
        [CONNS]            = "conns",
        [EXPIRE]           = "expire",
        [FLAGS]            = "flags",
        [KEY_PREFIX]       = "key_prefix",
        [CMD_POSTFIX]      = "cmd_postfix",
        [KEY_LEN]          = "key_len",
        [KEY_GENERATE]     = "key_generate",
        [VALUE_SIZE]       = "value_size",
        [VALUE_RANGE]      = "value_range",
        [VALUE_RANGE_STEP] = "value_range_step",
        [MGET_COUNT]       = "mget_count",
        [VALUE]            = "value",
        [LIVE_RAND]        = "live_rand",
        [LIVE_RAND_ZIPF]   = "live_rand_zipf",
        [REAL_WORKLOAD]    = "real_workload", //junyaoy
        [STOP_AFTER]       = "stop_after",
        [KEY_COUNT]        = "key_count",
        [HOST]             = "host",
        [PORT]             = "port",
        [THREAD]           = "thread",
        [PIPELINES]        = "pipelines",
        [ZIPF_SKEW]        = "zipf_skew",
        [WORKLOAD_PATH]    = "workload_path", //Junyaoy 1/13/2022
        [WORKLOAD_LENGTH]  = "workload_length",
        [WORKLOAD_TYPE]    = "workload_type", //junyaoy see MACROs above
        [CPU_AFIN_PATH]    = "cpu_afin_path",
        [LATENCY_DUMP_PATH] = "latency_dump_path", //junyaoy 2/10/2022
        [LATENCY_DUMP_LEN] =  "latency_dump_len", //junyaoy 2/10/2022 dump len per connection
        NULL
    };


    memset(&template, 0, sizeof(struct connection));
    /* Set defaults into template */
    strcpy(key_prefix_tmp, "foo");
    cmd_postfix_tmp[0] = 0;
    template.t = main_thread;
    template.mget_count = 2;
    template.value_size = 0;
    template.use_shared_value = 1;
    template.wbuf_written = 0;
    template.wbuf_towrite = 0;
    template.key_count = 200000;
    template.rand = conn_rand_off;
    template.zipf_skew = 0.25; // default to a relatively gentle curve.
    template.pipelines = 1;
    template.expire = 0;
    template.flags = 0;
    strcpy(template.host, host_default);
    strcpy(template.port_num, port_num_default);
    template.next_state = conn_reading;
    template.s = calloc(1, sizeof(mc_tshared));
    template.s->value[0] = '\0';
    
    template.read_info = HIT;
    template.resp_times = NULL; //default null
    template.latency_dump_fd = NULL;
    template.latency_dump_len = 0;


    /* Chomp the ending newline */
    tmp = rindex(line, '\n');
    if (tmp != NULL) 
        *tmp = '\0';
    while ((token = strtok_r(line, ",", &in_progress)) != NULL) {
        int key = 0;
        char *value = NULL;
        value = index(token, '=');
        *value = '\0';
        value++;
        
        line = NULL; /* lazy */
        while (key_options[key] != NULL) {
            if (strcmp(token, key_options[key]) == 0)
                break;
            key++;
        }
        fprintf(stderr, "id %d for key %s value %s\n", key, token, value);

        switch (key) {
        case SEND:
            sender = value;
            break;
        case RECV:
            reader = value;
            template.reader = read_from_client;
            break;
        case CONNS:
            conns_tomake = atoi(value);
            break;
        case COUNT:
            break;
        case EXPIRE:
            // TODO: import strtoul wrappers
            template.expire = atoi(value);
            break;
        case FLAGS:
            template.flags = atoi(value);
            break;
        case KEY_PREFIX:
            strcpy(key_prefix_tmp, value);
            break;
        case CMD_POSTFIX:
            strcpy(cmd_postfix_tmp, value);
            break;
        case MGET_COUNT:
            template.mget_count = atoi(value);
            break;
        case VALUE_SIZE:
            template.value_size = atoi(value);
            break;
        case VALUE:
            strcpy(template.s->value, value);
            template.value_size = strlen(value);
            template.use_shared_value = 0;
            break;
        case LIVE_RAND:
            template.rand = conn_rand_uniform;
            break;
        case LIVE_RAND_ZIPF:
            template.rand = conn_rand_zipf;
            break;
        case REAL_WORKLOAD:
            //junyaoy 01/13/2022
            template.rand = conn_rand_workload;
            break;
        case STOP_AFTER:
            template.stop_after = atoi(value);
            break;
        case KEY_COUNT:
            template.key_count = atoi(value);
            break;
        case HOST:
            strcpy(template.host, value);
            break;
        case PORT:
            strcpy(template.port_num, value);
            break;
        case USLEEP:
            template.usleep = atoi(value);
            break;
        case THREAD:
            new_thread = atoi(value);
            total_threads += new_thread; //junyaoy 1/17/2022
            break;
        case PIPELINES:
            template.pipelines = atoi(value);
            break;
        case ZIPF_SKEW:
            template.zipf_skew = strtod(value, NULL);
            break;
        case WORKLOAD_PATH:
            //junyaoy 01/13/2022
            workload_path_tmp = strdup(value);
            break;
        case WORKLOAD_LENGTH:
            //junyaoy 01/13/2022
            workload_len = strtoull(value, NULL, 10);
            break;
        case WORKLOAD_TYPE:
            //junyaoy 01/20/2022
            if (strcmp(value, "twitter") == 0) {
                workload_type = TW_TYPE;
            }
            break;
        case CPU_AFIN_PATH:
            //junyaoy 01/30/2022
            cpu_afin_path = strdup(value);
            break;
        case LATENCY_DUMP_LEN:
            template.latency_dump_len = atoi(value);
            template.latency_curr_index = 0;
            break;
        case LATENCY_DUMP_PATH:
            latency_dump_path_tmp = strdup(value);
        }
    }
    //collect latency to a file 02/10/2022 jy
    if (latency_dump_path_tmp != NULL) {
        if (template.latency_dump_len <= 0) {
            perror("latency len error\n");
            exit(-1);
        }
        if((template.latency_dump_fd = fopen(latency_dump_path_tmp,"a")) == NULL)
        { perror("open error for latency dump\n"); exit(-1); }
        
    }
    if (template.rand == conn_rand_workload) {
        //default to 0, 
        //randomize it in new_connection()
        template.workload_buf_index = 0; 
        
        if (global_workload_buf == NULL && workload_len != 0) {
            
            global_workload_buf = malloc(workload_len*sizeof(uint64_t));
            if (global_workload_buf == NULL) {
                perror("global buffer allocation failed\n");
                exit(-1);
            }

           
            //process and feed all request to global buff
            //if global buff is not null, skip it
            //use the workload specify in the first config line as default workload
            //for all workload.
            printf("workload loading start...\n");
            
            if (workload_type == TW_TYPE) {
                tw_iterator_t* itr = tw_trace_init(workload_path_tmp, 10000, CONTINUE);
                tw_ref_t* ref = NULL;
                unsigned long cnt = 0;
                while((cnt < workload_len) &&
                      !tw_trace_finished(itr)) {
                    ref = tw_trace_next(itr);
                    global_workload_buf[cnt] = ref->murmur3_hashed_key[1];
                    cnt++;
                }
            }else {
                 //open new file, report error if failed
                FILE* rfd;
                if((rfd = fopen(workload_path_tmp,"r")) == NULL)
                { perror("open error for read workload"); exit(-1); }
                ssize_t read;
                char* line = NULL;
                size_t len = 0;
                char* token;
                char* raw_key;
                unsigned long cnt = 0;
                uint64_t murmur3_key[2];
                read = getline(&line, &len, rfd);
                while ( (cnt < workload_len) && 
                    ((read = getline(&line, &len, rfd)) != -1)) {

                
                    token = strtok(line, "\n");
                    raw_key = strdup(token); //dup the key
                    MurmurHash3_x64_128(raw_key,
                                        strlen(raw_key),
                                        205103, //deterministic seed
                                        murmur3_key);
                    free(raw_key);
                    global_workload_buf[cnt] = murmur3_key[1];
                    cnt++;
                }

                workload_len = cnt;
                printf("workload loading complete! ins:%llu\n",workload_len);
                free(workload_path_tmp);
                free((void*)line);
                fclose(rfd);
            }
        }
        
    }
   
    if (strcmp(sender, "ascii_getset") == 0) {
        template.writer = ascii_write_flat_to_client_noupdate;
        template.ascii_format = ascii_single_format;
        sprintf(template.s->key_prefix, "get %s", key_prefix_tmp);
        sprintf(template.s->second_key_prefix, "set %s", key_prefix_tmp);
        template.reader = setback_read_from_client;
        template.next_state = conn_setback_reading;
    } else if (strcmp(sender, "ascii_get") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_single_format;
        sprintf(template.s->key_prefix, "get %s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_set") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_set_format;
        sprintf(template.s->key_prefix, "set %s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_mget") == 0) {
        template.writer = ascii_write_flat_mget_to_client;
        sprintf(template.s->key_prefix, "%s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_incr") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_incrdecr_format;
        sprintf(template.s->key_prefix, "incr %s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_delete") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_single_format;
        sprintf(template.s->key_prefix, "delete %s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_decr") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_incrdecr_format;
        sprintf(template.s->key_prefix, "decr %s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_touch") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_touch_format;
        sprintf(template.s->key_prefix, "touch %s", key_prefix_tmp);
    } else if (strcmp(sender, "ascii_mg") == 0) {
        template.writer = ascii_write_flat_to_client;
        template.ascii_format = ascii_metacmd_format;
        sprintf(template.s->key_prefix, "mg %s", key_prefix_tmp);
        sprintf(template.s->cmd_postfix, "%s", cmd_postfix_tmp);
    } else if (strcmp(sender, "bin_get") == 0) {
        template.writer = bin_write_flat_to_client;
        template.bin_prep_cmd = bin_prep_get;
        template.bin_format = bin_key_format;
        strcpy(template.s->key_prefix, key_prefix_tmp);
    } else if (strcmp(sender, "bin_getq") == 0) {
        template.writer = bin_write_flat_to_client;
        template.bin_prep_cmd = bin_prep_getq;
        template.bin_format = bin_key_format;
        strcpy(template.s->key_prefix, key_prefix_tmp);
    } else if (strcmp(sender, "bin_set") == 0) {
        template.writer = bin_write_flat_to_client;
        template.bin_prep_cmd = bin_prep_set;
        template.bin_format = bin_key_format;
        strcpy(template.s->key_prefix, key_prefix_tmp);
    } else if (strcmp(sender, "bin_setq") == 0) {
        template.writer = bin_write_flat_to_client;
        template.bin_prep_cmd = bin_prep_setq;
        template.bin_format = bin_key_format;
        strcpy(template.s->key_prefix, key_prefix_tmp);
    } else if (strcmp(sender, "bin_touch") == 0) {
        template.writer = bin_write_flat_to_client;
        template.bin_prep_cmd = bin_prep_touch;
        template.bin_format = bin_key_format;
        strcpy(template.s->key_prefix, key_prefix_tmp);
    } else {
        fprintf(stderr, "Unknown command writer: %s\n", sender);
        exit(1);
    }

    template.s->key_prefix_len = strlen(template.s->key_prefix);
    template.s->cmd_postfix_len = strlen(template.s->cmd_postfix);

    if (new_thread != 0) {

        //junyaoy 01/30/2022
        //get cpu assignment
        //
        if(cpu_afin_path != NULL) {

        
            cpu_afin_arr = malloc(new_thread*sizeof(uint32_t));

            FILE* cpu_rfd;
            if((cpu_rfd = fopen(cpu_afin_path,"r")) == NULL)
            { perror("open error for read workload"); exit(-1); }
            ssize_t read;
            char* line = NULL;
            size_t len = 0;
            char* token;
            char* raw_key;
            unsigned long cnt = 0;
            while ((cnt < new_thread) &&
                ((read = getline(&line, &len, cpu_rfd)) != -1)) {

            
                token = strtok(line, "\n");
                raw_key = strdup(token); //dup the key
                cpu_afin_arr[cnt] = strtoul(raw_key,NULL, 10);
                free(raw_key);
                cnt++;
            }


            free(cpu_afin_path);
            free((void*)line);
            fclose(cpu_rfd);
        //
        }
        // spawn N threads with very similar configurations. allows sharing
        // the key blob memory.
        for (x = 0; x < new_thread; x++) {
            template.t = calloc(1, sizeof(mc_thread));
            setup_thread(template.t);
            start_template(&template, conns_tomake, use_sock);
            if(cpu_afin_arr != NULL){
                template.t->cpu_num = cpu_afin_arr[x];
            }
            create_thread(template.t);
        }
    } else {
        start_template(&template, conns_tomake, use_sock);
    }
}

static void start_template(struct connection *template, int conns_tomake, bool use_sock) {
    template->cur_key = (uint64_t *)malloc(sizeof(uint64_t));
    template->write_count = (uint64_t *)malloc(sizeof(uint64_t));
    // TODO: randomize run counter if conn_rand_off.
    *template->cur_key = 0;
    *template->write_count = 0;

    int i, newsock;
    for (i = 0; i < conns_tomake; i++) {
        if (use_sock) {
            newsock = new_connection(template, (char *)&sock_path_default);
        } else {
            newsock = new_connection(template, NULL);
        }
        if (newsock < 0) {
            if (use_sock) {
                fprintf(stderr, "Failed to connect: %s\n", sock_path_default);
            } else {
                fprintf(stderr, "Failed to connect: %s[%s]\n", template->host, template->port_num);
            }
            exit(1);
        }
    }
}

static void *thread_runner(void *arg) {
    mc_thread *t = arg;
    int ret = event_base_loop(t->base, 0);
    fprintf(stderr, "Thread exiting: %d\n", ret);
    //exit when all connection are done,
    pthread_mutex_lock(&exit_lock);
    exited_num += 1;
    if(exited_num == total_threads+1) {
        fprintf(stderr, "all %lu threads exited.\n", total_threads);
        exit(-1);
    }
    pthread_mutex_unlock(&exit_lock);
    return NULL;
}

static void setup_thread(mc_thread *t) {
    t->base = event_init();
    if (!t->base) {
        fprintf(stderr, "Cannot allocate event base\n");
        exit(1);
    }
    t->cpu_num = -1; //junyaoy
    t->shared_value = calloc(SHARED_VALUE_SIZE, sizeof(unsigned char));
    t->shared_rbuf = calloc(SHARED_RBUF_SIZE, sizeof(unsigned char));
}

static void create_thread(mc_thread *t) {
    pthread_attr_t attr;
    int ret;

    pthread_attr_init(&attr);
    if (t->cpu_num != -1) {
        //get a number
    
        cpu_set_t m;
 

        CPU_ZERO(&m);
        sched_getaffinity(0, sizeof(cpu_set_t), &m);

       
        if (CPU_ISSET(t->cpu_num, &m)) {
            CPU_ZERO(&m);
            CPU_SET(t->cpu_num, &m);
            if ((ret = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &m)) != 0) {
                fprintf(stderr, "Can't set thread affinity: %s\n",
                        strerror(ret));
                exit(1);
            }
        }
        
    }
    
    
    if ((ret = pthread_create(&t->thread_id, &attr, thread_runner, t)) != 0) {
        fprintf(stderr, "Cannot create thread: %s\n", strerror(ret));
        exit(1);
    }
}

static void alarm_handler(int signal) {
    alarm_fired = 1;
}

int main(int argc, char **argv)
{
    FILE *cfd = NULL;
    char line[4096];
    int timeout = 0;
    bool use_sock = false;
    double zipf_s = 0;
    int zipf_n = 0;
    // kill buffering of stdout so a parent process can monitor it.
    setvbuf(stdout, NULL, _IONBF, 0);
    mc_thread *main_thread = NULL;
    main_thread = calloc(1, sizeof(mc_thread));
    setup_thread(main_thread); 

    global_workload_buf = NULL; //junyaoy 01/13/2022
    workload_len = 0;
    workload_type = SIM_TYPE; //default to preprocessed workload type
    conn_init_index = 0;


    
    //junyaoy 1/17/2022
    total_threads = 0;
    exited_num = 0;
    if (pthread_mutex_init(&exit_lock, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }
    if (pthread_mutex_init(&lat_append_lock, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }
#ifdef USE_TLS
    ssl_init();
#endif

    const struct option longopts[] = {
        // standard operational options
        {"ip", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        // connect instead to a unix socket
        {"sock", required_argument, 0, 's'},
        {"conf", required_argument, 0, 'c'},
        {"timeout", required_argument, 0, 't'},
        // test mode for zipf distributions
        {"zipf-n", required_argument, 0, 'z'},
        {"zipf-s", required_argument, 0, 'x'},
        // end of options.
        {0, 0, 0, 0}
    };
    int optindex;
    int c;
    while (-1 != (c = getopt_long(argc, argv, "", longopts, &optindex))) {
        switch (c) {
        case 'i':
            strncpy(host_default, optarg, NI_MAXHOST);
            printf("ip address default: %s\n", host_default);
            break;
        case 'p':
            strncpy(port_num_default, optarg, NI_MAXSERV);
            printf("port default: %s\n", port_num_default);
            break;
        case 's':
            strncpy(sock_path_default, optarg, SOCK_MAX-1);
            printf("unix socket path: %s\n", sock_path_default);
            use_sock = true;
            break;
        case 'c':
            cfd = fopen(optarg, "r");
            if (cfd == NULL) {
                perror("Opening config file");
                exit(1);
            }
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'z':
            zipf_n = atoi(optarg);
            break;
        case 'x':
            zipf_s = strtod(optarg, NULL);
            break;
        default:
            fprintf(stderr, "Unknown option\n");
        }
    }

    // zipf tester. dumps a bunch of numbers then exits.
    if (zipf_n != 0 && zipf_s != 0) {
        int x;
        pcg32_random_t rng;
        pcg32_srandom_r(&rng, time(NULL), 54u);
        double zipf_t = zipf_calc_t(zipf_n, zipf_s);
        for (x = 0; x < 10000000; x++) {
            fprintf(stdout, "%u\n", zipf_sample(&rng, zipf_t, zipf_s));
        }
        exit(1);
    }

    if (cfd == NULL) {
        fprintf(stderr, "error: use --conf [file] to specify a config file\n");
        exit(1);
    }

    while (fgets(line, 4096, cfd) != NULL) {
        parse_config_line(main_thread, line, use_sock);
    }
    fclose(cfd);

    create_thread(main_thread);

    if (timeout != 0) {
        struct sigaction sig_h;

        sig_h.sa_handler = alarm_handler;
        sig_h.sa_flags = 0;

        sigaction(SIGALRM, &sig_h, NULL);
        fprintf(stderr, "setting a timeout\n");
        alarm(timeout);
    }
    // TODO: Fire a signal at parent when threads exit? since they shouldn't.
    printf("done initializing\n");
    pause();
    if (alarm_fired) {
        printf("timed run complete\n");
    }
    return 0;
}
