/*
   p0f - Python Wrapper by Vivek Chand vivekchand19@gmail.com

   p0f - main entry point and all the pcap / unix socket innards
   -------------------------------------------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#define _GNU_SOURCE
#define _FROM_P0F

#include<Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <time.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "tools/p0f-client.c"
#include <sys/time.h>

#include <pcap.h>

#ifdef NET_BPF
#  include <net/bpf.h>
#else
#  include <pcap-bpf.h>
#endif /* !NET_BPF */

#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "readfp.h"
#include "api.h"
#include "tcp.h"
#include "fp_http.h"
#include "p0f.h"

#ifndef PF_INET6
#  define PF_INET6          10
#endif /* !PF_INET6 */

#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0
#endif /* !O_NOFOLLOW */

#ifndef O_LARGEFILE
#  define O_LARGEFILE 0
#endif /* !O_LARGEFILE */

#ifndef BUF_SZ
#define BUF_SZ 200
#endif /* !BUF_SZ */

static u8 *use_iface,                   /* Interface to listen on             */
          *orig_rule,                   /* Original filter rule               */
          *switch_user,                 /* Target username                    */
          *log_file,                    /* Binary log file name               */
          *api_sock,                    /* API socket file name               */
          *fp_file,                     /* Location of p0f.fp                 */
          *read_file;                   /* File to read pcap data from        */

static u32
  api_max_conn    = API_MAX_CONN;       /* Maximum number of API connections  */

u32
  max_conn        = MAX_CONN,           /* Connection entry count limit       */
  max_hosts       = MAX_HOSTS,          /* Host cache entry count limit       */
  conn_max_age    = CONN_MAX_AGE,       /* Maximum age of a connection entry  */
  host_idle_limit = HOST_IDLE_LIMIT;    /* Host cache idle timeout            */

static struct api_client *api_cl;       /* Array with API client state        */
          
static s32 null_fd = -1,                /* File descriptor of /dev/null       */
           api_fd = -1;                 /* API socket descriptor              */

static FILE* lf;                        /* Log file stream                    */

static u8 stop_soon;                    /* Ctrl-C or so pressed?              */

u8 daemon_mode;                         /* Running in daemon mode?            */

static u8 set_promisc;                  /* Use promiscuous mode?              */
         
static pcap_t *pt;                      /* PCAP capture thingy                */

s32 link_type;                          /* PCAP link type                     */

u32 hash_seed;                          /* Hash seed                          */

static u8 obs_fields;                   /* No of pending observation fields   */

/* Memory allocator data: */

#ifdef DEBUG_BUILD
struct TRK_obj* TRK[ALLOC_BUCKETS];
u32 TRK_cnt[ALLOC_BUCKETS];
#endif /* DEBUG_BUILD */

#define LOGF(_x...) fprintf(lf, _x)

/* Display usage information */

static void usage(void) {

  ERRORF(

"Usage: p0f [ ...options... ] [ 'filter rule' ]\n"
"\n"
"Network interface options:\n"
"\n"
"  -i iface  - listen on the specified network interface\n"
"  -r file   - read offline pcap data from a given file\n"
"  -p        - put the listening interface in promiscuous mode\n"
"  -L        - list all available interfaces\n"
"\n"
"Operating mode and output settings:\n"
"\n"
"  -f file   - read fingerprint database from 'file' (%s)\n"
"  -o file   - write information to the specified log file\n"
#ifndef __CYGWIN__
"  -s name   - answer to API queries at a named unix socket\n"
#endif /* !__CYGWIN__ */
"  -u user   - switch to the specified unprivileged account and chroot\n"
"  -d        - fork into background (requires -o or -s)\n"
"\n"
"Performance-related options:\n"
"\n"
#ifndef __CYGWIN__
"  -S limit  - limit number of parallel API connections (%u)\n"
#endif /* !__CYGWIN__ */
"  -t c,h    - set connection / host cache age limits (%us,%um)\n"
"  -m c,h    - cap the number of active connections / hosts (%u,%u)\n"
"\n"
"Optional filter expressions (man tcpdump) can be specified in the command\n"
"line to prevent p0f from looking at incidental network traffic.\n"
"\n"
"Problems? You can reach the author at <lcamtuf@coredump.cx>.\n",

    FP_FILE,
#ifndef __CYGWIN__
    API_MAX_CONN,
#endif /* !__CYGWIN__ */
    CONN_MAX_AGE, HOST_IDLE_LIMIT, MAX_CONN,  MAX_HOSTS);

  exit(1);

}


/* Obtain hash seed: */

static void get_hash_seed(void) {

  s32 f = open("/dev/urandom", O_RDONLY);

  if (f < 0) printf("\n FATAL: Cannot open /dev/urandom for reading.");

#ifndef DEBUG_BUILD

  /* In debug versions, use a constant seed. */

  if (read(f, &hash_seed, sizeof(hash_seed)) != sizeof(hash_seed))
    printf("\n FATAL: Cannot read data from /dev/urandom.");

#endif /* !DEBUG_BUILD */

  close(f);

}


/* Get rid of unnecessary file descriptors */

static void close_spare_fds(void) {

  s32 i, closed = 0;
  DIR* d;
  struct dirent* de;

  d = opendir("/proc/self/fd");

  if (!d) {
    /* Best we could do... */
    for (i = 3; i < 256; i++) 
      if (!close(i)) closed++;
    return;
  }

  while ((de = readdir(d))) {
    i = atol(de->d_name);
    if (i > 2 && !close(i)) closed++;
  }

  closedir(d);

  if (closed)
    SAYF("[+] Closed %u file descriptor%s.\n", closed, closed == 1 ? "" : "s" );

}


/* Create or open log file */

static void open_log(void) {

  struct stat st;
  s32 log_fd;

  log_fd = open((char*)log_file, O_WRONLY | O_APPEND | O_NOFOLLOW | O_LARGEFILE);

  if (log_fd >= 0) {

    if (fstat(log_fd, &st)) printf("\n FATAL: fstat() on '%s' failed.", log_file);

    if (!S_ISREG(st.st_mode)) printf("\n FATAL: '%s' is not a regular file.", log_file);

  } else {

    if (errno != ENOENT) printf("\n FATAL: Cannot open '%s'.", log_file);

    log_fd = open((char*)log_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  LOG_MODE);

    if (log_fd < 0) printf("\n FATAL: Cannot open '%s'.", log_file);

  }

  if (flock(log_fd, LOCK_EX | LOCK_NB))
    printf("\n FATAL: '%s' is being used by another process.", log_file);

  lf = fdopen(log_fd, "a");

  if (!lf) printf("\n FATAL: fdopen() on '%s' failed.", log_file);

  SAYF("[+] Log file '%s' opened for writing.\n", log_file);

}


/* Create and start listening on API socket */

static void open_api(void) {

  s32 old_umask;
  u32 i;

  struct sockaddr_un u;
  struct stat st;

  api_fd = socket(PF_UNIX, SOCK_STREAM, 0);

  if (api_fd < 0) printf("\n FATAL: socket(PF_UNIX) failed.");

  memset(&u, 0, sizeof(u));
  u.sun_family = AF_UNIX;

  if (strlen((char*)api_sock) >= sizeof(u.sun_path))
    printf("\n FATAL: API socket filename is too long for sockaddr_un (blame Unix).");

  strcpy(u.sun_path, (char*)api_sock);

  /* This is bad, but you can't do any better with standard unix socket
     semantics today :-( */

  if (!stat((char*)api_sock, &st) && !S_ISSOCK(st.st_mode))
    printf("\n FATAL: '%s' exists but is not a socket.", api_sock);

  if (unlink((char*)api_sock) && errno != ENOENT)
    printf("\n FATAL: unlink('%s') failed.", api_sock);

  old_umask = umask(0777 ^ API_MODE);

  if (bind(api_fd, (struct sockaddr*)&u, sizeof(u)))
    printf("\n FATAL: bind() on '%s' failed.", api_sock);
  
  umask(old_umask);

  if (listen(api_fd, api_max_conn))
    printf("\n FATAL: listen() on '%s' failed.", api_sock);

  if (fcntl(api_fd, F_SETFL, O_NONBLOCK))
    printf("\n FATAL: fcntl() to set O_NONBLOCK on API listen socket fails.");

  api_cl = DFL_ck_alloc(api_max_conn * sizeof(struct api_client));

  for (i = 0; i < api_max_conn; i++) api_cl[i].fd = -1;

  SAYF("[+] Listening on API socket '%s' (max %u clients).\n",
       api_sock, api_max_conn);

}


/* Open log entry. */

void start_observation(char* keyword, u8 field_cnt, u8 to_srv,
                       struct packet_flow* f) {

  if (obs_fields) printf("\n FATAL: Premature end of observation.");

  if (!daemon_mode) {

    SAYF(".-[ %s/%u -> ", addr_to_str(f->client->addr, f->client->ip_ver),
         f->cli_port);
    SAYF("%s/%u (%s) ]-\n|\n", addr_to_str(f->server->addr, f->client->ip_ver),
         f->srv_port, keyword);

    SAYF("| %-8s = %s/%u\n", to_srv ? "client" : "server", 
         addr_to_str(to_srv ? f->client->addr :
         f->server->addr, f->client->ip_ver),
         to_srv ? f->cli_port : f->srv_port);

  }

  if (log_file) {

    u8 tmp[64];

    time_t ut = get_unix_time();
    struct tm* lt = localtime(&ut);

    strftime((char*)tmp, 64, "%Y/%m/%d %H:%M:%S", lt);

    LOGF("[%s] mod=%s|cli=%s/%u|",tmp, keyword, addr_to_str(f->client->addr,
         f->client->ip_ver), f->cli_port);

    LOGF("srv=%s/%u|subj=%s", addr_to_str(f->server->addr, f->server->ip_ver),
         f->srv_port, to_srv ? "cli" : "srv");

  }

  obs_fields = field_cnt;

}


/* Add log item. */

void add_observation_field(char* key, u8* value) {

  if (!obs_fields) printf("\n FATAL: Unexpected observation field ('%s').", key);

  if (!daemon_mode)
    SAYF("| %-8s = %s\n", key, value ? value : (u8*)"???");

  if (log_file) LOGF("|%s=%s", key, value ? value : (u8*)"???");

  obs_fields--;

  if (!obs_fields) {

    if (!daemon_mode) SAYF("|\n`----\n\n");

    if (log_file) LOGF("\n");

  }

}


/* Show PCAP interface list */

static void list_interfaces(void) {

  char pcap_err[PCAP_ERRBUF_SIZE];
  pcap_if_t *dev;
  u8 i = 0;

  /* There is a bug in several years' worth of libpcap releases that causes it
     to SEGV here if /sys/class/net is not readable. See http://goo.gl/nEnGx */

  if (access("/sys/class/net", R_OK | X_OK) && errno != ENOENT)
    printf("\n FATAL: This operation requires access to /sys/class/net/, sorry.");

  if (pcap_findalldevs(&dev, pcap_err) == -1)
    printf("\n FATAL: pcap_findalldevs: %s\n", pcap_err);

  if (!dev) printf("\n FATAL: Can't find any interfaces. Maybe you need to be root?");

  SAYF("\n-- Available interfaces --\n");

  do {

    pcap_addr_t *a = dev->addresses;

    SAYF("\n%3d: Name        : %s\n", i++, dev->name);
    SAYF("     Description : %s\n", dev->description ? dev->description : "-");

    /* Let's try to find something we can actually display. */

    while (a && a->addr->sa_family != PF_INET && a->addr->sa_family != PF_INET6)
      a = a->next;

    if (a) {

      if (a->addr->sa_family == PF_INET)
        SAYF("     IP address  : %s\n", addr_to_str(((u8*)a->addr) + 4, IP_VER4));
      else
        SAYF("     IP address  : %s\n", addr_to_str(((u8*)a->addr) + 8, IP_VER6));

     } else SAYF("     IP address  : (none)\n");

  } while ((dev = dev->next));

  SAYF("\n");

  pcap_freealldevs(dev);

}



#ifdef __CYGWIN__

/* List PCAP-recognized interfaces */

static u8* find_interface(int num) {

  char pcap_err[PCAP_ERRBUF_SIZE];
  pcap_if_t *dev;

  if (pcap_findalldevs(&dev, pcap_err) == -1)
    printf("\n FATAL: pcap_findalldevs: %s\n", pcap_err);

  do {

    if (!num--) {
      u8* ret = DFL_ck_strdup((char*)dev->name);
      pcap_freealldevs(dev);
      return ret;
    }

  } while ((dev = dev->next));

  printf("\n FATAL: Interface not found (use -L to list all).");

}

#endif /* __CYGWIN__ */


/* Initialize PCAP capture */

static void prepare_pcap(void) {

  char pcap_err[PCAP_ERRBUF_SIZE];
  u8* orig_iface = use_iface;

  if (read_file) {

    if (set_promisc)
      printf("\n FATAL: Dude, how am I supposed to make a file promiscuous?");

    if (use_iface)
      printf("\n FATAL: Options -i and -r are mutually exclusive.");

    if (access((char*)read_file, R_OK))
      printf("\n FATAL: Can't access file '%s'.", read_file);

    pt = pcap_open_offline((char*)read_file, pcap_err);

    if (!pt) printf("\n FATAL: pcap_open_offline: %s", pcap_err);

    SAYF("[+] Will read pcap data from file '%s'.\n", read_file);

  } else {

    if (!use_iface) {

      /* See the earlier note on libpcap SEGV - same problem here.
         Also, this retusns something stupid on Windows, but hey... */
     
      if (!access("/sys/class/net", R_OK | X_OK) || errno == ENOENT)
        use_iface = (u8*)pcap_lookupdev(pcap_err);

      if (!use_iface)
        printf("\n FATAL: libpcap is out of ideas; use -i to specify interface.");

    }

#ifdef __CYGWIN__

    /* On Windows, interface names are unwieldy, and people prefer to use
       numerical IDs. */

    else {

      int iface_id;

      if (sscanf((char*)use_iface, "%u", &iface_id) == 1) {
        use_iface = find_interface(iface_id);
      }
  
    }

    pt = pcap_open_live((char*)use_iface, SNAPLEN, set_promisc, 250, pcap_err);

#else 

    /* PCAP timeouts tend to be broken, so we'll use a minimum value
       and rely on select() instead. */

    pt = pcap_open_live((char*)use_iface, SNAPLEN, set_promisc, 1, pcap_err);

#endif /* ^__CYGWIN__ */

    if (!orig_iface)
      SAYF("[+] Intercepting traffic on default interface '%s'.\n", use_iface);
    else
      SAYF("[+] Intercepting traffic on interface '%s'.\n", use_iface);

    if (!pt) printf("\n FATAL: pcap_open_live: %s", pcap_err);

  }

  link_type = pcap_datalink(pt);

}


/* Initialize BPF filtering */

static void prepare_bpf(void) {

  struct bpf_program flt;

  u8*  final_rule;
  u8   vlan_support;

  /* VLAN matching is somewhat brain-dead: you need to request it explicitly,
     and it alters the semantics of the remainder of the expression. */

  vlan_support = (pcap_datalink(pt) == DLT_EN10MB);

retry_no_vlan:

  if (!orig_rule) {

    if (vlan_support) {
      final_rule = (u8*)"tcp or (vlan and tcp)";
    } else {
      final_rule = (u8*)"tcp";
    }

  } else {

    if (vlan_support) {

      final_rule = ck_alloc(strlen((char*)orig_rule) * 2 + 64);

      sprintf((char*)final_rule, "(tcp and (%s)) or (vlan and tcp and (%s))",
              orig_rule, orig_rule);

    } else {

      final_rule = ck_alloc(strlen((char*)orig_rule) + 16);

      sprintf((char*)final_rule, "tcp and (%s)", orig_rule);

    }

  }

  DEBUG("[#] Computed rule: %s\n", final_rule);

  if (pcap_compile(pt, &flt, (char*)final_rule, 1, 0)) {

    if (vlan_support) {

      if (orig_rule) ck_free(final_rule);
      vlan_support = 0;
      goto retry_no_vlan;

    }

    pcap_perror(pt, "[-] pcap_compile");

    if (!orig_rule)
      printf("\n FATAL: pcap_compile() didn't work, strange");
    else
      printf("\n FATAL: Syntax error! See 'man tcpdump' for help on filters.");

  }

  if (pcap_setfilter(pt, &flt))
    printf("\n FATAL: pcap_setfilter() didn't work, strange.");

  pcap_freecode(&flt);

  if (!orig_rule) {

    SAYF("[+] Default packet filtering configured%s.\n",
         vlan_support ? " [+VLAN]" : "");

  } else {

    SAYF("[+] Custom filtering rule enabled: %s%s\n",
         orig_rule ? orig_rule : (u8*)"tcp",
         vlan_support ? " [+VLAN]" : "");

    ck_free(final_rule);

  }

}


/* Drop privileges and chroot(), with some sanity checks */

static void drop_privs(void) {

  struct passwd* pw;

  pw = getpwnam((char*)switch_user);

  if (!pw) printf("\n FATAL: User '%s' not found.", switch_user);

  if (!strcmp(pw->pw_dir, "/"))
    printf("\n FATAL: User '%s' must have a dedicated home directory.", switch_user);

  if (!pw->pw_uid || !pw->pw_gid)
    printf("\n FATAL: User '%s' must be non-root.", switch_user);

  if (initgroups(pw->pw_name, pw->pw_gid))
    printf("\n FATAL: initgroups() for '%s' failed.", switch_user);

  if (chdir(pw->pw_dir))
    printf("\n FATAL: chdir('%s') failed.", pw->pw_dir);

  if (chroot(pw->pw_dir))
    printf("\n FATAL: chroot('%s') failed.", pw->pw_dir);

  if (chdir("/"))
    printf("\n FATAL: chdir('/') after chroot('%s') failed.", pw->pw_dir);

  if (!access("/proc/", F_OK) || !access("/sys/", F_OK))
    printf("\n FATAL: User '%s' must have a dedicated home directory.", switch_user);

  if (setgid(pw->pw_gid))
    printf("\n FATAL: setgid(%u) failed.", pw->pw_gid);

  if (setuid(pw->pw_uid))
    printf("\n FATAL: setuid(%u) failed.", pw->pw_uid);

  if (getegid() != pw->pw_gid || geteuid() != pw->pw_uid)
    printf("\n FATAL: Inconsistent euid / egid after dropping privs.");

  SAYF("[+] Privileges dropped: uid %u, gid %u, root '%s'.\n",
       pw->pw_uid, pw->pw_gid, pw->pw_dir);

}


/* Enter daemon mode. */

static void fork_off(void) {

  s32 npid;

  fflush(0);

  npid = fork();

  if (npid < 0) printf("\n FATAL: fork() failed.");

  if (!npid) {

    /* Let's assume all this is fairly unlikely to fail, so we can live
       with the parent possibly proclaiming success prematurely. */

    if (dup2(null_fd, 0) < 0) printf("\n FATAL: dup2() failed.");

    /* If stderr is redirected to a file, keep that fd and use it for
       normal output. */

    if (isatty(2)) {

      if (dup2(null_fd, 1) < 0 || dup2(null_fd, 2) < 0)
        printf("\n FATAL: dup2() failed.");

    } else {

      if (dup2(2, 1) < 0) printf("\n FATAL: dup2() failed.");

    }

    close(null_fd);
    null_fd = -1;

    if (chdir("/")) printf("\n FATAL: chdir('/') failed.");

    setsid();

  } else {

    SAYF("[+] Daemon process created, PID %u (stderr %s).\n", npid,
      isatty(2) ? "not kept" : "kept as-is");

    SAYF("\nGood luck, you're on your own now!\n");

    exit(0);

  }

}


/* Handler for Ctrl-C and related signals */

static void abort_handler(int sig) {
  if (stop_soon) exit(1);
  stop_soon = 1;
}


#ifndef __CYGWIN__

/* Regenerate pollfd data for poll() */

static u32 regen_pfds(struct pollfd* pfds, struct api_client** ctable) {
  u32 i, count = 2;

  pfds[0].fd     = pcap_fileno(pt);
  pfds[0].events = (POLLIN | POLLERR | POLLHUP);

  DEBUG("[#] Recomputing pollfd data, pcap_fd = %d.\n", pfds[0].fd);

  if (!api_sock) return 1;

  pfds[1].fd     = api_fd;
  pfds[1].events = (POLLIN | POLLERR | POLLHUP);

  for (i = 0; i < api_max_conn; i++) {

    if (api_cl[i].fd == -1) continue;

    ctable[count] = api_cl + i;

    /* If we haven't received a complete query yet, wait for POLLIN.
       Otherwise, we want to write stuff. */

    if (api_cl[i].in_off < sizeof(struct p0f_api_query))
      pfds[count].events = (POLLIN | POLLERR | POLLHUP);
    else
      pfds[count].events = (POLLOUT | POLLERR | POLLHUP);

    pfds[count++].fd   = api_cl[i].fd;

  }

  return count;

}

#endif /* !__CYGWIN__ */


/* Event loop! Accepts and dispatches pcap data, API queries, etc. */

static void live_event_loop(void) {
#ifndef __CYGWIN__

  /* The huge problem with winpcap on cygwin is that you can't get a file
     descriptor suitable for poll() / select() out of it:

     http://www.winpcap.org/pipermail/winpcap-users/2009-April/003179.html

     The only alternatives seem to be additional processes / threads, a
     nasty busy loop, or a ton of Windows-specific code. If you need APi
     queries on Windows, you are welcome to fix this :-) */

  struct pollfd *pfds;
  struct api_client** ctable;
  u32 pfd_count;

  /* We need room for pcap, and possibly api_fd + api_clients. */

  pfds = ck_alloc((1 + (api_sock ? (1 + api_max_conn) : 0)) *
                  sizeof(struct pollfd));

  ctable = ck_alloc((1 + (api_sock ? (1 + api_max_conn) : 0)) *
                    sizeof(struct api_client*));

  pfd_count = regen_pfds(pfds, ctable);

  if (!daemon_mode) 
    SAYF("[+] Entered main event loop.\n\n");

  while (!stop_soon) {

    s32 pret, i;
    u32 cur;

    /* We use a 250 ms timeout to keep Ctrl-C responsive without resortng to
       silly sigaction hackery or unsafe signal handler code. */

poll_again:

    pret = poll(pfds, pfd_count, 250);

    if (pret < 0) {
      if (errno == EINTR) break;
      printf("\n FATAL: poll() failed.");
    }

    if (!pret) { if (log_file) fflush(lf); continue; }

    /* Examine pfds... */

    for (cur = 0; cur < pfd_count; cur++) {

      if (pfds[cur].revents & POLLOUT) switch (cur) {

        case 0: case 1:

          printf("\n FATAL: Unexpected POLLOUT on fd %d.\n", cur);

        default:

          /* Write API response, restart state when complete. */

          if (ctable[cur]->in_off < sizeof(struct p0f_api_query))
            printf("\n FATAL: Inconsistent p0f_api_response state.\n");

          i = write(pfds[cur].fd, 
                   ((char*)&ctable[cur]->out_data) + ctable[cur]->out_off,
                   sizeof(struct p0f_api_response) - ctable[cur]->out_off);

          if (i <= 0) printf("\n FATAL: write() on API socket fails despite POLLOUT.");

          ctable[cur]->out_off += i;

          /* All done? Back to square zero then! */

          if (ctable[cur]->out_off == sizeof(struct p0f_api_response)) {

             ctable[cur]->in_off = ctable[cur]->out_off = 0;
             pfds[cur].events   = (POLLIN | POLLERR | POLLHUP);

          }

      }

      if (pfds[cur].revents & POLLIN) switch (cur) {
 
        case 0:

          /* Process traffic on the capture interface. */

          if (pcap_dispatch(pt, -1, (pcap_handler)parse_packet, 0) < 0)
            printf("\n FATAL: Packet capture interface is down.");

          break;

        case 1:

          /* Accept new API connection, limits permitting. */

          if (!api_sock) printf("\n FATAL: Unexpected API connection.");

          if (pfd_count - 2 < api_max_conn) {

            for (i = 0; i < api_max_conn && api_cl[i].fd >= 0; i++);

            if (i == api_max_conn) printf("\n FATAL: Inconsistent API connection data.");

            api_cl[i].fd = accept(api_fd, NULL, NULL);

            if (api_cl[i].fd < 0) {

              WARN("Unable to handle API connection: accept() fails.");

            } else {

              if (fcntl(api_cl[i].fd, F_SETFL, O_NONBLOCK))
                printf("\n FATAL: fcntl() to set O_NONBLOCK on API connection fails.");

              api_cl[i].in_off = api_cl[i].out_off = 0;
              pfd_count = regen_pfds(pfds, ctable);

              DEBUG("[#] Accepted new API connection, fd %d.\n", api_cl[i].fd);

              goto poll_again;

            }

          } else WARN("Too many API connections (use -S to adjust).\n");

          break;

        default:

          /* Receive API query, dispatch when complete. */

          if (ctable[cur]->in_off >= sizeof(struct p0f_api_query))
            printf("\n FATAL: Inconsistent p0f_api_query state.\n");

          i = read(pfds[cur].fd, 
                   ((char*)&ctable[cur]->in_data) + ctable[cur]->in_off,
                   sizeof(struct p0f_api_query) - ctable[cur]->in_off);

          if (i < 0) printf("\n FATAL: read() on API socket fails despite POLLIN.");

          ctable[cur]->in_off += i;

          /* Query in place? Compute response and prepare to send it back. */

          if (ctable[cur]->in_off == sizeof(struct p0f_api_query)) {

            handle_query(&ctable[cur]->in_data, &ctable[cur]->out_data);
            pfds[cur].events = (POLLOUT | POLLERR | POLLHUP);

          }

      }

      if (pfds[cur].revents & (POLLERR | POLLHUP)) switch (cur) {

        case 0:

          printf("\n FATAL: Packet capture interface is down.");

        case 1:

          printf("\n FATAL: API socket is down.");

        default:

          /* Shut down API connection and free its state. */

          DEBUG("[#] API connection on fd %d closed.\n", pfds[cur].fd);

          close(pfds[cur].fd);
          ctable[cur]->fd = -1;
 
          pfd_count = regen_pfds(pfds, ctable);
          goto poll_again;

      }

      /* Processed all reported updates already? If so, bail out early. */

      if (pfds[cur].revents && !--pret) break;

    }

  }

  ck_free(ctable);
  ck_free(pfds);

#else

  if (!daemon_mode) 
    SAYF("[+] Entered main event loop.\n\n");

  /* Ugh. The only way to keep SIGINT and other signals working is to have this
     funny loop with dummy I/O every 250 ms. Signal handlers don't get called
     in pcap_dispatch() or pcap_loop() unless there's I/O. */

  while (!stop_soon) {

    s32 ret = pcap_dispatch(pt, -1, (pcap_handler)parse_packet, 0);

    if (ret < 0) return;

    if (log_file && !ret) fflush(lf);

    write(2, NULL, 0);

  }

#endif /* ^!__CYGWIN__ */

  WARN("User-initiated shutdown.");

}


/* Simple event loop for processing offline captures. */

static void offline_event_loop(void) {

  if (!daemon_mode) 
    SAYF("[+] Processing capture data.\n\n");

  while (!stop_soon)  {

    if (pcap_dispatch(pt, -1, (pcap_handler)parse_packet, 0) <= 0) return;

  }

  WARN("User-initiated shutdown.");

}




int run(){
   // Returns 
   // 0 - Success
   // -1 - API mode looks down on ofline captures.
   // -2 - api_max_con makes sense only with api_sock.
   // -3 - Daemon mode and offline captures don't mix.
   // -4 - Daemon mode requires log_file or api_sock.
   // -5 - [!] Note: under cygwin, switch_user is largely useless
   // -6 - [!] Consider specifying switch_user in daemon mode (see README)
   int ret = 0; 

  if (read_file && api_sock){
	printf("\nFATAL: API mode looks down on ofline captures");
	ret = -1;
  }
  if (!api_sock && api_max_conn != API_MAX_CONN){
	printf("\nFATAL: api_max_con makes sense only with api_sock.");
	ret = -2;
  }
  if (daemon_mode) {

    if (read_file){
	printf("\nFATAL: Daemon mode and offline captures don't mix.");
	ret = -3;
    }
    if (!log_file && !api_sock){
	printf("\nFATAL: Daemon mode requires log_file or api_sock.");
	ret = -4;
    }
#ifdef __CYGWIN__
    if (switch_user) {
	printf("\n[!] Note: under cygwin, switch_user is largely useless");
	ret = -5;
    }
#else

    if (!switch_user) {
	printf("\n[!] Consider specifying switch_user in daemon mode (see README)");
	ret = -6;
    }
#endif /* ^__CYGWIN__ */

  }

  tzset();
  setlocale(LC_TIME, "C");

  close_spare_fds();

  get_hash_seed();

  http_init();

  read_config(fp_file ? fp_file : (u8*)FP_FILE);

  prepare_pcap();
  prepare_bpf();

  if (log_file) open_log();
  if (api_sock) open_api();
  
  if (daemon_mode) {
    null_fd = open("/dev/null", O_RDONLY);
    if (null_fd < 0) printf("\nFATAL: Cannot open '/dev/null'.");
  }
  
  if (switch_user) drop_privs();

  if (daemon_mode) fork_off();

  signal(SIGHUP, daemon_mode ? SIG_IGN : abort_handler);
  signal(SIGINT, abort_handler);
  signal(SIGTERM, abort_handler);

  if (read_file) offline_event_loop(); else live_event_loop();

  if (!daemon_mode)
    printf("\nAll done. Processed %llu packets.\n", packet_cnt);

#ifdef DEBUG_BUILD
  destroy_all_hosts();
  TRK_report();
#endif /* DEBUG_BUILD */

  return ret;
}

static PyObject* p0fmod_set_fp_file(PyObject *self,PyObject *args){ // -f
	// Returns
	// 0 - success
	// -1 - Multiple fingerprint files not supported.
	char* input;
	char in[BUF_SZ];
	int ret=0;

	if(!PyArg_ParseTuple(args, "s" , &input))
		return NULL;

        if (fp_file) {
		printf("\nFATAL: Multiple fingerprint files not supported. ");
		ret = -1;
	}
	else{
		fp_file = malloc(sizeof(in));
		sscanf(input,"%s",in);
		memcpy(fp_file,in,sizeof(in));
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_iface(PyObject *self,PyObject *args){ // -i
	// Returns
	// 0 - success
	// -1 - Multiple iface not supported (try '-i any').
	int ret=0;
	char *input;
	char in[BUF_SZ];

	if(!PyArg_ParseTuple(args, "s" , &input))
		return NULL;

        if (use_iface){
		printf("\nFATAL: Multiple iface not supported (try '-i any') ");
		ret = -1;
	}
	else{
		use_iface = malloc(sizeof(in));
		sscanf(input,"%s",in);
		memcpy(use_iface,in,sizeof(in));
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_list_interfaces(PyObject *self,PyObject *args){ // -L
	// Returns
	// 0 - success
	int ret=0;
	list_interfaces();
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_read_file(PyObject *self,PyObject *args){ // -r
	// Returns
	// 0 - success
	// -1 - Multiple read_file not supported.

        char* input;
	char in[BUF_SZ];
        int ret=0;

        if(!PyArg_ParseTuple(args, "s" , &input))
                return NULL;

        if (read_file){
		printf("\nFATAL: Multiple read_file not supported.");
		ret = -1;
	}
	else{
		read_file = malloc(sizeof(in));
		sscanf(input,"%s",in);
		memcpy(read_file,in,sizeof(in));
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_log_file(PyObject *self,PyObject *args){ // -o
	// Returns
	// 0 - success
	// -1 - Multiple log_file not supported.

        char* input;
	char in[BUF_SZ];
        int ret=0;

        if(!PyArg_ParseTuple(args, "s" , &input))
                return NULL;

        if (log_file){
		printf("\nFATAL: Multiple log_file not supported.");
		ret = -1;
	}
	else{
		log_file = malloc(sizeof(in));
		sscanf(input,"%s",in);
		memcpy(log_file,in,sizeof(in));
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_api_sock(PyObject *self,PyObject *args){ //-s
	// Returns
	// 0 - success
	// -1 - Multiple API Sockets not supported.
	// -2 - API mode not supported on Windows (see README).
        int ret=0;
#ifdef __CYGWIN__
      printf("\nFATAL: API mode not supported on Windows (see README).");
      ret = -2;
#else
        char* input;
	char in[BUF_SZ];

        if(!PyArg_ParseTuple(args, "s" , &input))
                return NULL;

	if (api_sock){
		printf("\nFATAL: Multiple API Sockets not supported.");
		ret = -1;
	}
	else{
		api_sock = malloc(sizeof(in));
		sscanf(input,"%s",in);
		memcpy(api_sock,in,sizeof(in));
	}
#endif /* ^__CYGWIN__ */
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_en_daemon_mode(PyObject *self,PyObject *args){ // -d
	// Returns
	// 0 - success
	// -1 - Double werewolf mode not supported yet.
        int ret=0;

        if (daemon_mode){
		printf("\nFATAL: Double werewolf mode not supported yet. ");
		ret = -1;
	}
	else
		daemon_mode = 1;
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_switch_user(PyObject *self,PyObject *args){ // -u
	// Returns
	// 0 - success
	// -1 - Split personality mode not supported.
        char* input;
	char in[BUF_SZ];
        int ret=0;
    
        if(!PyArg_ParseTuple(args, "s" , &input))
                return NULL;

        if (switch_user){
		printf("\nFATAL: Split personality mode not supported.");
		ret = -1;
	}
	else{
		switch_user = malloc(sizeof(in));
		sscanf(input,"%s",in);
		memcpy(switch_user,in,sizeof(in));
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_en_promisc_mode(PyObject *self,PyObject *args){ // -p
	// Returns
	// 0 - success
	// -1 - Even more promiscuous? People will call me slutty!
        int ret=0;

	if (set_promisc){
		printf("\nFATAL: Even more promiscuous? People will call me slutty!");
		ret = -1;
	}
	else
		set_promisc = 1;
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_api_max_conn(PyObject *self,PyObject *args){ // -S
        // Returns
        // 0 - success
        // -1 - Multiple max_conn values not supported.
        // -2 - Outlandish value specified for max_conn.
	// -3 - API mode not supported on Windows (see README)
        int input;
        int ret=0;
#ifdef __CYGWIN__
	 printf("\nFATAL: API mode not supported on Windows (see README)");
	 ret = -3;
#else
      	if(!PyArg_ParseTuple(args, "l" , &input))
                return NULL;

        if (api_max_conn != API_MAX_CONN){
		printf("\nFATAL: Multiple max_conn values not supported.");
		ret = -1;
	}else
	        api_max_conn = input;

	if(!api_max_conn || api_max_conn > 100){
		printf("\nFATAL: Outlandish value specified for max_conn.");
	        ret = -2;
	}
#endif /* ^__CYGWIN__ */

        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_max_conn(PyObject *self,PyObject *args){ // -m
        // Returns
        // 0 - success
        // -1 - Multiple max_conn values not supported.
        // -2 - Outlandish value specified for max_conn.

        int input;
        int ret=0;

      	if(!PyArg_ParseTuple(args, "l" , &input))
                return NULL;

        if (max_conn != MAX_CONN || max_hosts != MAX_HOSTS){
		printf("\nFATAL: Multiple max_conn values not supported.");
		ret = -1;
	}
	else
	{
	  max_conn = input;
          if (!max_conn || max_conn > 100000){
		printf("\nFATAL: Outlandish value specified for max_conn.");
		ret = -2;
	  }
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_max_hosts(PyObject *self,PyObject *args){ // -m
        // Returns
        // 0 - success
        // -1 - Multiple max_hosts values not supported.
        // -2 - Outlandish value specified for max_hosts.

        int input;
        int ret=0;

      	if(!PyArg_ParseTuple(args, "l" , &input))
                return NULL;

	if (max_hosts != MAX_HOSTS){
		printf("\nFATAL: Multiple max_hosts values not supported. ");
		ret = -1;
	}
	else 
	{
	     max_hosts = input;
    	     if (!max_hosts || max_hosts > 500000){
		printf("\nFATAL: Outlandish value specified for max_hosts.");
		ret = -2;
	     }
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_conn_max_age(PyObject *self,PyObject *args){ // -t
	// Returns
	// 0 - success
	// -1 - Multiple conn_max_age values not supported.
 	// -2 - Outlandish value specified for conn_max_age.

        int input;
        int ret=0;

      	if(!PyArg_ParseTuple(args, "l" , &input))
                return NULL;

        if (conn_max_age != CONN_MAX_AGE){
	  printf("\nFATAL: Multiple conn_max_age values not supported.");
	  ret = -1;
	}
	else
	{ 
	  conn_max_age = input;
	  if (!conn_max_age || conn_max_age > 1000000 ){	
	    printf("\nFATAL: Outlandish value specified for conn_max_age.");
	    ret = -2;
	  }
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_set_host_idle_limit(PyObject *self,PyObject *args){ // -t
        // Returns
        // 0 - success
        // -1 - Multiple host_idle_limit values not supported.
        // -2 - Outlandish value specified for host_idle_limit.

        int input;
        int ret=0;

      	if(!PyArg_ParseTuple(args, "s" , &input))
                return NULL;

        if(host_idle_limit != HOST_IDLE_LIMIT){
		printf("\nFATAL: Multiple host_idle_limit values not supported.");
		ret = -1;
	}
	else
	{
	  host_idle_limit = input; 
 	  if(!host_idle_limit || host_idle_limit > 1000000)
	  {
	      printf("\nFATAL: Outlandish value specified for host_idle_limit.");
	      ret = -2;
	  }
	}
        return Py_BuildValue("i",ret);
}

static PyObject* p0fmod_start_p0f(PyObject *self,PyObject *args){
   // Returns 
   // 0 - Success
   // -1 - API mode looks down on ofline captures.
   // -2 - api_max_con makes sense only with api_sock.
   // -3 - Daemon mode and offline captures don't mix.
   // -4 - Daemon mode requires log_file or api_sock.
   // -5 - [!] Note: under cygwin, switch_user is largely useless
   // -6 - [!] Consider specifying switch_user in daemon mode (see README)

	int ret = 0;
	ret = run();
        return Py_BuildValue("i",ret);
}


	char *buf;
	struct p0f_api_query *q;

static PyObject* p0fmod_mk_query(PyObject *self,PyObject *args){
	char *input;
	
        if(!PyArg_ParseTuple(args, "s" , &input))
                return NULL;
	q = malloc(sizeof(struct p0f_api_query));

	q->magic = P0F_QUERY_MAGIC;
	if (strchr(input, ':')) {
	    parse_addr6(input, q->addr);
	    q->addr_type = P0F_ADDR_IPV6;
  	} else {
	    parse_addr4(input, q->addr);
	    q->addr_type = P0F_ADDR_IPV4;
  	}
	
	buf = (char*)malloc(sizeof(*q));
	memcpy(buf,q,sizeof(*q));


        return Py_BuildValue("s",buf);
}


	struct p0f_api_response *r;

static PyObject* p0fmod_ck_response(PyObject *self,PyObject *args){
	int ret = 0;
        char *input;

        if(!PyArg_ParseTuple(args, "s#" , &input))
                return NULL;
        r = malloc(sizeof(struct p0f_api_response));
	r = (struct p0f_api_response*)input;
	
        if (r->magic != P0F_RESP_MAGIC) {
	    printf("\nFATAL: Bad response magic (0x%08x).", r->magic);
	    ret = -1;
	}
	else if (r->status == P0F_STATUS_BADQUERY) {
	    printf("\nP0f did not understand the query.");
	    ret = -2;
	}
	else if (r->status == P0F_STATUS_NOMATCH) {
	    printf("\n No matching host in p0f cache. That's all we know.");
	    ret = -3;
	}
	else
	{
		  time_t ut;
		  struct tm* t;
	   	  u8 tmp[128];

		  ut = r->first_seen;
		  t = localtime(&ut);
		  strftime((char*)tmp, 128, "%Y/%m/%d %H:%M:%S", t);

		  printf("\nFirst seen    = %s\n", tmp);

		  ut = r->last_seen;
		  t = localtime(&ut);
		  strftime((char*)tmp, 128, "%Y/%m/%d %H:%M:%S", t);

		  printf("Last update   = %s\n", tmp);
		  printf("Total flows   = %u\n", r->total_conn);

		  if (!r->os_name[0])
		    printf("Detected OS   = ???\n");
		  else
		    printf("nDetected OS   = %s %s%s%s\n", r->os_name, r->os_flavor,
		         (r->os_match_q & P0F_MATCH_GENERIC) ? " [generic]" : "",
		         (r->os_match_q & P0F_MATCH_FUZZY) ? " [fuzzy]" : "");

		  if (!r->http_name[0])
		    printf("HTTP software = ???\n");
		  else
		    printf("HTTP software = %s %s (ID %s)\n", r->http_name, r->http_flavor,
		         (r->bad_sw == 2) ? "is fake" : (r->bad_sw ? "OS mismatch" : "seems legit"));

		  if (!r->link_type[0])
		    printf("Network link  = ???\n");
		  else
		    printf("Network link  = %s\n", r->link_type);


		  if (!r->language[0])
		    printf("Language      = ???\n");
		  else
		    printf("Language      = %s\n", r->language);


  		  if (r->distance == -1)
    		    printf("Distance      = ???\n");
  		  else
    		    printf("Distance      = %u\n", r->distance);

  		  if (r->last_nat) {
    			ut = r->last_nat;
		        t = localtime(&ut);
    			strftime((char*)tmp, 128, "%Y/%m/%d %H:%M:%S", t);
    			printf("IP sharing    = %s\n", tmp);
  		   }

		   if (r->last_chg) {
		        ut = r->last_chg;
		        t = localtime(&ut);
		        strftime((char*)tmp, 128, "%Y/%m/%d %H:%M:%S", t);
		        printf("Sys change    = %s\n", tmp);
		    }

    		    if (r->uptime_min) {
    			printf("Uptime        = %u days %u hrs %u min (modulo %u days)\n",
         		r->uptime_min / 60 / 24, (r->uptime_min / 60) % 24, r->uptime_min % 60,
         		r->up_mod_days);
  		     }

	}
	

        return Py_BuildValue("i",ret);
}

static PyMethodDef p0fmod_methods[] = {
 //"PythonName"     C-function Name, 	argument presentation, description
 {"set_fp_file",    p0fmod_set_fp_file,    	   METH_VARARGS,   "List Interfaces"}, // -f
 {"set_iface",      p0fmod_set_iface,       METH_VARARGS,   "Listen to Interface"}, // -i
 {"list_interfaces",p0fmod_list_interfaces, METH_NOARGS,   "List Interfaces"}, // -L
 {"set_read_file",  p0fmod_set_read_file,       METH_VARARGS,   "reads pcap captures from specified filename"}, // -r
 {"set_log_file",   p0fmod_set_log_file,        METH_VARARGS,   "reads pcap captures from specified filename"}, // -o
 {"set_api_sock",   p0fmod_set_api_sock,        METH_VARARGS,   "set connection / host cache age limits (30s,120m)"}, // -s
 {"en_daemon_mode",  p0fmod_en_daemon_mode,     METH_NOARGS,   "Enable Daemon Mode"}, // -d
 {"switch_user",    p0fmod_switch_user,     METH_NOARGS,   "Drop Privilege"}, // -u
 {"en_promisc_mode",    p0fmod_en_promisc_mode,     METH_NOARGS,   "Puts the interface specified with -i in promiscuous mode"}, // -p
 {"set_api_max_conn",p0fmod_set_api_max_conn,    METH_VARARGS,   "Max no. of Simultaneous API Conn."}, // -S
 {"set_max_conn",p0fmod_set_max_conn,    METH_VARARGS,   "Max no. of Conn."}, // -m
 {"set_max_hosts",p0fmod_set_max_hosts,    METH_VARARGS,   "Max no. of Hosts."}, // -m
 {"set_conn_max_age",p0fmod_set_conn_max_age,    METH_VARARGS,   "timeout for collecting signarures for a connection"},
 {"set_host_idle_limit",p0fmod_set_host_idle_limit,    METH_VARARGS,   "timeout for purging idle hosts from in-memory cache"},
 
 {"start_p0f",    p0fmod_start_p0f,    METH_VARARGS,   "Start Passive OS Fingerprinting"},
 {"mk_query",    p0fmod_mk_query,    METH_VARARGS,   "Query p0f via api_sock"},
 {"ck_response",    p0fmod_ck_response,    METH_VARARGS,   "p0f Response via api_sock"},
 {NULL , NULL , 0 , NULL}        /* Sentinel */
};


/* Main entry point */
PyMODINIT_FUNC initp0fmod(void) {
        PyObject *m;
        m = Py_InitModule("p0fmod",p0fmod_methods);

        if(m==NULL)
                return;

 	setlinebuf(stdout);
	printf("\n--- p0f 3.06b by Michal Zalewski <lcamtuf@coredump.cx> ---\n\n");

	if (getuid() != geteuid())
	printf("\nFATAL: Please don't make me setuid. See README for more.\n");
}


