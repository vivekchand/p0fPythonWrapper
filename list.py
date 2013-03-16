static PyMethodDef p0fmod_methods[] = {
 //"PythonName"     C-function Name,    argument presentation, description
 {"set_fp_file",    p0fmod_set_fp_file,            METH_VARARGS,   "List Interfaces"}, // -f
 {"set_iface",      p0fmod_set_iface,       METH_VARARGS,   "Listen to Interface"}, // -i
 {"list_interfaces",p0fmod_list_interfaces, METH_NOARGS,   "List Interfaces"}, // -L
 {"set_read_file",  p0fmod_set_read_file,       METH_VARARGS,   "reads pcap captures from specified filename"}, // -r
 {"set_log_file",   p0fmod_set_log_file,        METH_VARARGS,   "reads pcap captures from specified filename"}, // -o
 {"set_api_sock",   p0fmod_set_api_sock,        METH_VARARGS,   "set connection / host cache age limits (30s,120m)"}, // -s
 {"en_daemon_mode"  p0fmod_en_daemon_mode,     METH_NOARGS,   "Enable Daemon Mode"}, // -d
 {"switch_user",    p0fmod_switch_user,     METH_NOARGS,   "Drop Privilege"}, // -u
 {"set_promisc",    p0fmod_set_promisc,     METH_NOARGS,   "Puts the interface specified with -i in promiscuous mode"}, // -p
 {"set_api_max_conn",p0fmod_set_api_max_conn,    METH_VARARGS,   "Max no. of Simultaneous API Conn."},
 {"set_max_conn",p0fmod_set_max_conn,    METH_VARARGS,   "Max no. of Conn."},
 {"set_max_hosts",p0fmod_set_max_hosts,    METH_VARARGS,   "Max no. of Hosts."},
 {"set_conn_max_age,",p0fmod_set_conn_max_age,    METH_VARARGS,   "timeout for collecting signarures for a connection"},
 {"set_host_idle_limit,",p0fmod_set_host_idle_limit,    METH_VARARGS,   "timeout for purging idle hosts from in-memory cache"},
 
 {"start_p0f",    p0fmod_start_p0f,    METH_VARARGS,   "Start Passive OS Fingerprinting"},
 {NULL , NULL , 0 , NULL}        /* Sentinel */
};

