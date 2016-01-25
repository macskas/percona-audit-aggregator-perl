# percona-audit-aggregator-perl

For audit reasons, I had to collect 25000+ connect/s. But raw syslog was just a waste of space even with zfs compression. So I aggregate logs.

I forward all the logs to the syslog-ng first and after that I forward it to the perl daemon/daemons.

### extra modules needed
* JSON::XS
* Digest::MD5

### basic modules needed (usually part of the base system)
* IO::Handle
* IO::Select
* IO::Socket
* Getopt::Std
* POSIX
* Fcntl
* Time::HiRes

### related mysql configuration
```
[mysqld]
plugin-load=audit_log.so
audit_log_handler               = SYSLOG
audit_log_policy                = LOGINS
audit_log_syslog_ident          = percona-audit
audit_log_format                = JSON
audit_log_syslog_facility       = LOG_LOCAL0
audit_log_syslog_priority       = LOG_NOTICE
```

### related syslog-ng config
```
filter f_percona_audit_filtered {
    facility (local0) and
    level (notice) and
    program("percona-audit") and not
    (
        message("\"user\": \"debian-sys-maint\"")
        or
        message("\"name\":\"Quit\"")
    );
};

destination d_percona_audit_perl {
    udp("127.0.0.1" port(9514) template("${FULLHOST},${SOURCEIP},${MSGONLY}"));
};


log {
        # your original source
        source (s_51401);
        filter (f_percona_audit_filtered);
        destination (d_percona_audit_perl);
        flags(final);
};
```
