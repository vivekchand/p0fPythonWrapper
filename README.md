	=====================================================================
		Passive OS Fingerprinting (p0f) Python Wrapper (p0fmod) 
				by Vivek Chand (vivekchand19@gmail.com)
	     
	=====================================================================

  Want to See it in github page?
  	http://vivekchand19.github.io/p0fPythonWrapper/

  What is this?
	http://lcamtuf.coredump.cx/p0f3/

	 Passive OS Fingerprinting Python Wrapper has the following APIs:

	set_fp_file(fname) - set fingerprint file name
	set_iface(iface)   - set specific n/w interface
	list_interfaces()  - list all avail. n/w interfaces 
	set_read_file(fname)  - reads pcap captures frm the read file
	set_log_file(fname)  - appends grep-friendly log data to the specified file
	set_api_sock(fname) - listens for API queries on the specified filesystem socket
	en_daemon_mode() - runs p0f in daemon mode
	switch_user(user) - causes p0f to drop privileges
	en_promisc_mode() - puts the interface specified with iface in promiscuous mode
	set_api_max_conn(num) - sets the maximum number of simultaneous API connections
	set_max_conn(c) - sets the maximum number of connections (c) to be tracked
	set_max_hosts(h) - sets the maximum number of hosts (h) to be tracked
	set_conn_max_age(c) - sets the timeout for collecting signatures for any connection (c)
	set_host_idle_limit(h) - sets the timeout for collecting signatures for purging idle hosts

	start_p0f() - Once p0f is configured with the above APIs, Passive OS Fingerprinting
		      can be started by calling this API.


	Miscellaneous APIs:
	-------------------
	mk_query(ip_addr) - Prepares the query ready for sending to p0f 
	ck_response(response_data) - Prints info of query if response is valid


	Import p0fmod as:
	-----------------
	    import p0fmod


	Examples:
	---------
		run.py  - A simple script that runs p0f on eth0 interface
		client.py - A simple script that lets to query for an IP addr with a Domain socket to p0f server
				usage:
				sudo run.py
				sudo	client.py /path/to/socket host_ip
				
	Build & Install p0fmod:
	-----------------------
		python setup.py build && sudo python setup.py install		


Detailed Description of APIs:
=============================

set_fp_file:
------------
	reads fingerprint database (p0f.fp) from the specified location.

	The default location is ./p0f.fp. If you want to install p0f, you
        may want to change FP_FILE in config.h to /etc/p0f.fp.

	Usage:	
		set_fp_file(fname)

	Returns:
        	 0 - success
	        -1 - Multiple fingerprint files not supported.


set_iface:
----------
	asks p0f to listen on a specific network interface. On un*x, you
        should reference the interface by name (e.g., eth0). On Windows,
        you can use adapter index instead (0, 1, 2...).	

	If you do not specify an interface, libpcap will probably pick
        the first working interface in your system.

	Usage:
		set_iface(iface)
		
	Returns:
        	 0 - success
                -1 - Multiple iface not supported (try '-i any').


list_interfaces:
----------------
	 lists all available network interfaces, then quits. Particularly
         useful on Windows, where the system-generated interface names
         are impossible to memorize.	

	 Usage:
		list_interfaces()

	
	 Returns:
        	 0 - success

set_read_file:
--------------
	instead of listening for live traffic, reads pcap captures from
        the specified file. The data can be collected with tcpdump or any
        other compatible tool.

	Make sure that snapshot length is large enough not to truncate packets; the
        default may be too small.

	Usage:
		set_read_file(fname)

	Returns:
		0 - success
               -1 - Multiple read_file not supported.


set_log_file:
-------------
	 appends grep-friendly log data to the specified file. The log
         contains all observations made by p0f about every matching
         connection, and may grow large; plan accordingly.

         Only one instance of p0f should be writing to a particular file
         at any given time; where supported, advisory locking is used to
         avoid problems.

	 Usage:
		set_log_file(fname)

	 Returns:
        	 0 - success
        	-1 - Multiple log_file not supported.


set_api_sock:
-------------
	listens for API queries on the specified filesystem socket. This
        allows other programs to ask p0f about its current thoughts about
        a particular host. More information about the API protocol can be
        found in section 4 below.

        Only one instance of p0f can be listening on a particular socket
        at any given time. The mode is also incompatible with read_file mode.

	Usage:
		set_api_sock(fname)

	Returns:
		 0 - success
                -1 - Multiple API Sockets not supported.
                -2 - API mode not supported on Windows 

en_daemon_mode:
---------------
	runs p0f in daemon mode: the program will fork into background
        and continue writing to the specified log file or API socket. It
        will continue running until killed, until the listening interface
        is shut down, or until some other fatal error is encountered.

        This mode requires either log_file or api_sock to be specified.

	Usage:
		en_daemon_mode()

	Returns:
        	 0 - success
         	-1 - Double werewolf mode not supported yet.

	
switch_user:
------------
	causes p0f to drop privileges, switching to the specified user
        and chroot()ing itself to said user's home directory.

        This mode is *highly* advisable (but not required) on un*x
        systems, especially in daemon mode.

	Usage:
		switch_user(user)
	

More arcane settings (you probably don't need to touch these):
==============================================================

en_promisc_mode:
----------------
	puts the interface specified with iface in promiscuous mode. If
        supported by the firmware, the card will also process frames not
        addressed to it.

	Usage:
		en_promisc_mode()

	Returns:
		 0 - success
        	-1 - Even more promiscuous? People will call me slutty!

set_api_max_conn:
-----------------
	sets the maximum number of simultaneous API connections. The
        default is 20; the upper cap is 100.

	Usage:
		set_api_max_conn(num)
	
	Returns:
	         0 - success
        	-1 - Multiple max_conn values not supported.
  	        -2 - Outlandish value specified for max_conn.
	        -3 - API mode not supported on Windows 

set_max_conn:
-------------
	sets the maximum number of connections (c) to be tracked  
	(default: c = 1,000). 

	Usage:
		set_max_conn(c)

	Returns:
		 0 - success
        	-1 - Multiple max_conn values not supported.
        	-2 - Outlandish value specified for max_conn.



set_max_hosts:
--------------
	sets the maximum number of hosts (h) to be tracked 
	(default: h = 10,000).

	Usage:
		set_max_hosts(h)

	Returns:
        	 0 - success
        	-1 - Multiple max_hosts values not supported.
        	-2 - Outlandish value specified for max_hosts.


        Once the limit for c & h is reached, the oldest 10% entries 
	gets pruned to make room for new data.

        This setting effectively controls the memory footprint of p0f.
        The cost of tracking a single host is under 400 bytes; active
        connections have a worst-case footprint of about 18 kB. High
        limits have some CPU impact, too, by the virtue of complicating
        data lookups in the cache.

        NOTE: P0f tracks connections only until the handshake is done,
        and if protocol-level fingerprinting is possible, until few
        initial kilobytes of data have been exchanged. This means that
        most connections are dropped from the cache in under 5 seconds;
        consequently, the 'c' variable can be much lower than the real
        number of parallel connections happening on the wire.


set_conn_max_age:
-----------------
	sets the timeout for collecting signatures for any connection (c)
	(default: 30s)

	The value must be just high enough to reliably capture SYN, SYN+ACK, 
	and the initial few kB of traffic. Low-performance sites may want 
	to increase it slightly.

	Usage:
		set_conn_max_age(c)

	Returns:
 	        0 - success
               -1 - Multiple conn_max_age values not supported.
               -2 - Outlandish value specified for conn_max_age.

set_host_idle_limit:
--------------------
	sets the timeout for collecting signatures for purging idle hosts 
	from in-memory cache (h)
	(default: 120min)

	This value governs for how long API queries about a previously seen host 
	can be made; and what's the maximum interval between signatures to still 
	trigger NAT detection and so on.

        Raising it is usually not advisable; lowering it to 5-10 minutes may make 
	sense for high-traffic servers, where it is possible to see several unrelated 
	visitors subsequently obtaining the same dynamic IP from their ISP.

	Usage:
		set_host_idle_limit(h)

	Returns:
	        0 - success
               -1 - Multiple host_idle_limit values not supported.
               -2 - Outlandish value specified for host_idle_limit.
	

start_p0f:
----------
	Once p0f is configured with the above APIs, Passive OS Fingerprinting 
	can be started by calling this API.
	
	Usage:
		start_p0f()

	Returns:
   		 0 - Success
  		-1 - API mode looks down on ofline captures.
		-2 - api_max_con makes sense only with api_sock.
		-3 - Daemon mode and offline captures don't mix.
		-4 - Daemon mode requires log_file or api_sock.
		-5 - [!] Note: under cygwin, switch_user is largely useless
		-6 - [!] Consider specifying switch_user in daemon mode 

-------------------------------------------------------------------------------------------------------------
