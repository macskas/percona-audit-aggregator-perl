#!/usr/bin/perl

use strict;
use warnings;
use POSIX;
use IO::Handle;
use IO::Select;
use IO::Socket;
use JSON::XS;
use Getopt::Std;
use POSIX qw/strftime/;
use Digest::MD5 qw(md5_hex);
use Fcntl qw(:flock);
use Time::HiRes qw/tv_interval gettimeofday/;

my $listenPort = 9514;

my $flush_iterator = 0;
my $aggregate_updated = [gettimeofday];
my $aggregate_requests = 10000;
my $request_per_second = 0;
my $aggregate_seconds = 60;
my $percona_audit_basedir = "/storage/compressed/percona-audit";
my $wType = "worker";
my $stat = {
    'data'	=> {},
    'requests'	=> 0
};
our ($opt_d, $opt_k, $opt_h);
my $muted = 0;
my $lockfile = "/tmp/audit-udp-server.lock";
my $lockfh;

sub info()
{
    my $msg = shift;
    return if ($muted);
    printf ("[%s-%d] %s > %s\n", $wType, $$, scalar localtime, $msg);
}

sub info_start()
{
    my $msg = shift;
    return if ($muted);
    printf ("[%s-%d] %s > %s", $wType, $$, scalar localtime, $msg);
}

sub info_end()
{
    my $msg = shift;
    return if ($muted);
    printf ("%s\n", $msg);
}

sub error()
{
    my $msg = shift;
    if (!$muted) {
	printf("[%s-%d] %s > ERROR > %s\n", $wType, $$, scalar localtime, $msg);
    }
    exit(1);
}

sub doUdpServer()
{
    my($sock, $newmsg, $hishost, $MAXLEN);
    $MAXLEN = 8192;
    my $PORTNO = $listenPort;
    &info_start("UDP server starting on $PORTNO ... ");
    $sock = IO::Socket::INET->new(
	LocalPort => $PORTNO,
	Proto => 'udp'
    );
    if (!defined($sock) || !$sock) {
	&info_end("error. ($!)");
	&error("udpServer listen error on port $PORTNO")
    }
    &info_end("done.");

    while ($sock->recv($newmsg, $MAXLEN)) {
	&doWorker($newmsg);
    }
    &info("UDP server stopped.");
}

sub decode_json_eval($)
{
    my $input = shift || "";
    my $out = 0;
    eval {
        $out = decode_json($input);
        1;
    } or do {
        my $e = $@;
        $out = 0;
    };

    return $out;
}

sub addConnection()
{
    my ($hostname, $ip, $client_user, $client_host, $client_ip, $client_db) = @_;
    my $now = time();
    my $atime = $now - ($now % $aggregate_seconds);
    
    if (!defined($stat->{'data'}->{"$atime"})) {
	$stat->{'data'}->{"$atime"} = {};
    }
    
    my $hash_main = md5_hex("$hostname|$ip");
    my $hash_sub = md5_hex("$client_user|$client_host|$client_ip|$client_db");
    if (!defined($stat->{'data'}->{"$atime"}->{"$hash_main"})) {
	$stat->{'data'}->{"$atime"}->{"$hash_main"} = {
	    'created_at'	=> $now,
	    'updated_at'	=> $now,
	    'ip'		=> $ip,
	    'hostname'		=> $hostname,
	    'connects'		=> 0,
	    'connections'	=> {}
	};
    }
    
    if (!defined($stat->{'data'}->{"$atime"}->{"$hash_main"}->{'connections'}->{"$hash_sub"})) {
	$stat->{'data'}->{"$atime"}->{"$hash_main"}->{'connections'}->{"$hash_sub"} = {
	    'created_at'	=> $now,
	    'updated_at'	=> $now,
	    'connects'		=> 0,
	    'user'		=> $client_user,
	    'host'		=> $client_host,
	    'ip'		=> $client_ip,
	    'db'		=> $client_db
	}
    }
    $stat->{'data'}->{"$atime"}->{"$hash_main"}->{'connects'}++;
    $stat->{'data'}->{"$atime"}->{"$hash_main"}->{'updated_at'} = $now;
    $stat->{'data'}->{"$atime"}->{"$hash_main"}->{'connections'}->{"$hash_sub"}->{'connects'}++;
    $stat->{'data'}->{"$atime"}->{"$hash_main"}->{'connections'}->{"$hash_sub"}->{'updated_at'} = $now;
}

sub gc()
{
    &info_start("GC ... ");
    my $tsnum = scalar keys %{$stat->{'data'}};
    if ($tsnum < 2) {
	&info_end("Not enough data. ($tsnum group)");
	return;
    }
    &info_end("done.");
    my $selected_ts = 0;
    foreach my $cur (sort {$a<=>$b} keys %{$stat->{'data'}}) {
	$selected_ts = $cur;
	last;
    }
    &info_start("GC saving ... ");
    if (!$selected_ts) {
	&info_end("failed.");
	return;
    }
    &save_stat($stat->{'data'}->{"$selected_ts"});
    delete $stat->{'data'}->{"$selected_ts"};
    &info_end("saved. ($selected_ts)");
}

sub save_stat()
{
    my @localtime = localtime;
    my $timestr = strftime("%Y-%m-%d %H:%M:%S",@localtime);
    my $input = shift;
    my $dir = sprintf("%s/%s", $percona_audit_basedir, strftime("%Y-%m-%d", @localtime));
    if (!-d $dir) {
	mkdir($dir, 0755);
    }
    my $fn = "";
    local *F;
    foreach my $hash_main (keys %{$input}) {
	$fn = $dir . "/" . $input->{$hash_main}->{'hostname'} . "_" . $input->{$hash_main}->{'ip'} . ".log";
	open(F, ">>$fn") or next;
	foreach my $hash_sub (sort {$input->{$hash_main}->{'connections'}->{$a}->{'db'} cmp $input->{$hash_main}->{'connections'}->{$b}->{'db'}} keys %{$input->{$hash_main}->{'connections'}}) {
	    print F sprintf("%s %s, %s > %s\n", $timestr, $input->{$hash_main}->{'hostname'}, $input->{$hash_main}->{'ip'}, encode_json($input->{$hash_main}->{'connections'}->{$hash_sub}));
	}
	print F sprintf("%s\n", "-"x300);
	close(F);
    }
}

sub doWorker()
{
    $stat->{'requests'}++;
    my $msg = shift || "";
    my @required = ( "user", "host", "ip", "db" );
    if ($msg =~ /^([^,]+),([^,]+),(.*)$/) {
	my ($hostname, $ip, $data) = ($1, $2, $3);
	my $r = decode_json_eval($data);
	return if (!$r);
	return if (!defined($r->{'audit_record'}->{'name'}));
	return if ($r->{'audit_record'}->{'name'} ne 'Connect');
	foreach my $reqname (@required) {
	    return if (!defined($r->{'audit_record'}->{"$reqname"}))
	}
	my $client_user = $r->{'audit_record'}->{'user'};
	my $client_host = $r->{'audit_record'}->{'host'};
	my $client_ip = $r->{'audit_record'}->{'ip'};
	my $client_db = $r->{'audit_record'}->{'db'};
	$flush_iterator++;
	&addConnection($hostname, $ip, $client_user, $client_host, $client_ip, $client_db);
	if ($flush_iterator == $aggregate_requests) {
	    my $now = [gettimeofday];
	    my $diff = tv_interval($aggregate_updated, $now);
	    if ($diff) {
		$request_per_second = $aggregate_requests / $diff;
	    }
	    $flush_iterator = 0;
	    $aggregate_updated = $now;
	    &gc();
	    &setProcTitle();
	}
    } elsif ($msg eq 'stop') {
	exit(0);
    }
}

sub daemonize()
{
    my $pid = fork();
    if ($pid > 0) {
	# parent
	exit(0);
    } elsif ($pid == 0) {
	# child
    } else {
	# error
	&error("fork() error");
    }
}

sub flush {
   my $h = select($_[0]); my $af=$|; $|=1; $|=$af; select($h);
}

sub lock()
{
    &info_start("Locking $lockfile ... ");
    my $rc = open($lockfh, ">$lockfile");
    if (!$rc) {
	&info_end("failed. ($!)");
	&error("Unable to open $lockfile for writing");
    }
    chmod(0777, $lockfile);
    $rc = flock($lockfh, LOCK_EX|LOCK_NB);
    if (!$rc) {
	&info_end("failed ($!)");
	&error("flock() failed.");
    }
    print $lockfh POSIX::getpid()."\n";
    &flush($lockfh);
    &info_end("done.");
}

sub unlock()
{
    return if (!defined($lockfh) || !$lockfh);
    close($lockfh);
    if (-w $lockfile) {
	unlink($lockfile);
    }
}

sub setProcTitle()
{
    if ($request_per_second) {
	$0 = sprintf("[aggregator::udp::%d] [rps=%d/s]", $listenPort, $request_per_second);
    } else {
	$0 = "[aggregator::udp::$listenPort]";
    }
}

sub send_shutdown_signal()
{
    &info_start("Sending kill signal to udp://127.0.0.1:$listenPort ... ");
    my $c = IO::Socket::INET->new(
	PeerAddr	=> "127.0.0.1",
	PeerPort	=> $listenPort,
	Proto		=> 'udp'
    );
    if (!$c) {
	&info_stop("failed. ($!)");
	&error("Connect failed to $listenPort on localhost.");
    }

    $c->send("stop");
    $c->close();
    &info_end("done.");
}

sub show_help()
{
    my $offset = length("usage: $0 ");
    printf("percona auditlog aggregator daemon\n");
    printf("usage: %s [-dkh]\n", $0);
    printf("%s -h: %s\n", " "x$offset, "show help");
    printf("%s -d: %s\n", " "x$offset, "silent mode. daemon.");
    printf("%s -k: %s\n", " "x$offset, "shutdown daemon");

}

sub main()
{
    getopts("dkh");
    if (defined($opt_h)) {
	&show_help();
	exit(0);
    }

    if (defined($opt_k)) {
	&send_shutdown_signal();
	exit(0);
    }
    if (defined($opt_d)) {
	$muted = 1;
	&daemonize();
	&setProcTitle();
    }
    &lock();
    &doUdpServer();
    &unlock();
}

&main();
