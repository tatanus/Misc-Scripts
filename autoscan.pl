#!/usr/bin/perl -w

use strict;
use Text::ParseWords;
use Getopt::Long qw(:config no_ignore_case bundling);


# version of this script
my $VERSION = "2.0";

################################################################################
# Subfunctions
################################################################################

# Print help and exit
sub usage {

    print STDERR "ERROR: @_\n" if @_;
    die <<EO_USAGE
usage: $0 [scan options] -i <filename> | -n <network> <mask>
	-i <filename>:
		read input from list of hosts specified in <filename>
	-n <network> <mask>:
		network	network address made up of four octets (12.34.56.78)
		mask	number of bits making up mask (0-32)

	additional options:
	-w	whois scan
	-p	ICMP and SYN ping sweeps
	-t	TCP scan  (implies -p for now)
	-a	Amap scan (implies -t)
	-A	means -wpta

	Note: either -i or -n must be specified but not both
EO_USAGE
}

# Append time information to log file
sub addTime {
    return "[" . scalar(localtime(time)) . "] @_";
}

# Takes a file to read and an xml tag respectively.  Then prints each host
# under the specified tag in report.xml
sub print_hosts {
    my ($file, $tag) = @_;
    my $num = 0;

    if (-e $file) {
	$num = `wc -l $file`;
	($num) = ($num =~ /(\d+)/);
    }
    print REPORT qq(\t\t<$tag total="$num">\n);
    open(IN, "< $file")
	or warn "couldn't open file $file for reading";
    while (<IN>) {
		chomp;
		print REPORT qq(\t\t\t<host ip="$_" />\n);
    }
    close IN;
    print REPORT qq(\t\t</$tag>\n);
}

################################################################################
# Whois queries
################################################################################
sub whois {
	my $net = $_[0];
	my %flags = %{$_[1]};

	if ($flags{infile}) {
		open (INFILE, "< $net") or die "Couldn't open $net for reading\n";
		foreach (<INFILE>) {
			chomp;
			my ($addr) = split('/',$_);
			my $nethandle = 0;
			print LOG addTime("whois $addr\n");
			open (SCAN, "whois -h whois.arin.net $addr | tee net-$net/data/whois-$net-$addr.txt |");
			while (<SCAN>) {
				if (/\((.*)\)/) {
					$nethandle = $1;
				}
			}
			print "Whois query against $addr";

			# If the first query only returned the nethandle, query against that nethandle
			if ($nethandle) {
				print LOG addTime("whois $nethandle\n");
				`whois -h whois.arin.net $nethandle > net-$net/data/whois-$nethandle-$addr.txt`;
				print " and $nethandle";
			}
			print "\n";
		}
	} else {
		my ($addr) = split('_', $net);

		print LOG addTime("whois $addr\n");
		my $nethandle = 0;
		open (SCAN, "whois -h whois.arin.net $addr | tee net-$net/data/whois-$net.txt |");
		while (<SCAN>) {
			if (/\((.*)\)/) {
				$nethandle = $1;
			}
		}
		print "Whois query against $addr";

		# If the first query only returned the nethandle, query against that nethandle
		if ($nethandle) {
			print LOG addTime("whois $nethandle\n");
			`whois -h whois.arin.net $nethandle > net-$net/data/whois-$nethandle.txt`;
			print " and $nethandle";
		}
		print "\n";
	}
}
################################################################################
# ICMP ping sweep
################################################################################
sub icmp_sweep {
	my $net = $_[0];
	my %flags = %{$_[1]};
	my ($addr, $bits) = split('_', $net);
	my $nmap_ending = $flags{infile} ? "-iL $net" : "$addr/$bits";
	my $v = $flags{verbose} ? " -v " : " ";

	print LOG addTime("ICMP ping sweep\n");
	my $result = "0 hosts";

	open (SCAN, "nmap$v-sP -PE -oA net-$net/data/nmap_ICMPping-$net $nmap_ending |");
	while (<SCAN>) {
		if ($flags{verbose}) { print $_; }
		if (/\((\d+ hosts*) up\)/) {
			$result = $1;
		}
	}
	print "ICMP ping sweep found $result\n";
}

################################################################################
# SYN sweep
################################################################################
sub syn_sweep {
	my $net = $_[0];
	my %flags = %{$_[1]};
	my ($addr, $bits) = split('_', $net);
	my $nmap_ending = $flags{infile} ? "-iL $net" : "$addr/$bits";
	my $v = $flags{verbose} ? " -v " : " ";

	# SYN pingsweeps in nmap can only handle 10 ports at a time.
	# Sweep 1/3: 21 (ftp), 22 (ssh), 23 (telnet), 25 (smtp), 53 (dns), 80 (http),
	#     110 (pop3), 119 (nntp), 143 (imap), 443 (https)
	print LOG addTime("SYN ping sweep 1/3\n");
	my $result = "0 hosts";
	open (SCAN, "nmap$v-sP -PS21,22,23,25,53,80,110,119,143,443 -T Aggressive -oA net-$net/data/nmap_SYNping1-$net $nmap_ending |");
	while (<SCAN>) {
		if ($flags{verbose}) { print $_; }
		if (/\((\d+ hosts*) up\)/) {
			$result = $1;
		}
	}
	print "SYN ping sweep 1/3 found $result\n";

	# SYN pingsweeps in nmap can only handle 10 ports at a time.
	# Sweep 2/3: 135 (ms-rpc), 139 (netbios), 445 (ms-ds), 593 (ms-http-rpc),
	#     1352 (lotus notes), 1433 (msql), 1498 (sybase), 1521 (oracle),
	#     3306 (mysql), 5432 (postgresql)
	print LOG addTime("SYN ping sweep 2/3\n");
	$result = "0 hosts";
	open (SCAN, "nmap$v-sP -PS135,139,445,593,1352,1433,1498,1521,3306,5432 -T Aggressive -oA net-$net/data/nmap_SYNping2-$net $nmap_ending |");
	while (<SCAN>) {
		if ($flags{verbose}) { print $_; }
		if (/\((\d+ hosts*) up\)/) {
			$result = $1;
		}
	}
	print "SYN ping sweep 2/3 found $result\n";

	# SYN pingsweeps in nmap can only handle 10 ports at a time.
	# Sweep 3/3: 389 (ldap), 1494 (citrix), 1723 (pptp), 2049 (nfs), 2598 (citrix),
	#     3389 (rdp), 5631 (pc anywhere), 5800 (vnc), 5900 (vnc), 6000 (x)
	print LOG addTime("SYN ping sweep 3/3\n");
	$result = "0 hosts";
	open (SCAN, "nmap$v-sP -PS389,1494,1723,2049,2598,3389,5631,5800,5900,6000 -T Aggressive -oA net-$net/data/nmap_SYNping3-$net $nmap_ending |");
	while (<SCAN>) {
		if ($flags{verbose}) { print $_; }
		if (/\((\d+ hosts*) up\)/) {
			$result = $1;
		}
	}
	print "SYN ping sweep 3/3 found $result\n";
}
################################################################################
# TCP Scan
################################################################################
sub tcp_scan {
	my $net = $_[0];
	my %flags = %{$_[1]};
	my $v = $flags{verbose} ? " -v " : " ";

	print LOG addTime("TCP port scan against found hosts\n");
	`nmap$v-sT -A -P0 -oA net-$net/data/nmap_TCPscan-$net -iL net-$net/data/hosts.txt`;
	print "TCP port scan completed\n";
}
################################################################################
# Application scan
################################################################################
sub amap_scan {
	my $net = $_[0];
	my %flags = %{$_[1]};

	print LOG addTime("Amap application scan against found hosts\n");
	`amap -1 -b -i net-$net/data/nmap_TCPscan-$net.gnmap -o net-$net/data/amap-$net.txt -m`;
	print "Amap application scan completed\n";
}

################################################################################
# Main
################################################################################

################################################################################
# Validate command line arguments
################################################################################
my ($addr,$bits,$net);

my %flags = (	verbose	=> 0,
				ping	=> 0,
				whois	=> 0,
				infile	=> 0,
				network	=> 0,
				tcp		=> 0,
				amap	=> 0,
				help	=> 0,
				all		=> 0
			);

GetOptions(	'v|verbose'	=> \$flags{verbose},
			'p|ping'	=> \$flags{ping},
			'w|whois'	=> \$flags{whois},
			'i|input'	=> \$flags{infile},
			'n|network'	=> \$flags{network},
			't|tcp'		=> \$flags{tcp},
			'a|amap'	=> \$flags{amap},
			'h|help'	=> \$flags{help},
			'A|all'		=> \$flags{all}
			);

usage if ($flags{infile} and $flags{network});
usage if ($flags{help} || @ARGV == 0);

if ($flags{all}) {
	$flags{whois} = $flags{ping} = $flags{tcp} = $flags{amap} = 1;
} elsif ($flags{amap} || $flags{tcp}) {
	$flags{ping} = $flags{tcp} = 1;
}

if ($flags{network}) {
	usage if (@ARGV != 2);

	$addr = $ARGV[0];
	if ($addr =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
		foreach ($1, $2, $3, $4) {
			if ($_ > 255) {
				usage "Invalid network address syntax";
			}
		}
	} else {
		usage "Invalid network address syntax";
	}

	$bits = $ARGV[1];
	unless ($bits =~ /(^\d{1,3}$)/ && $bits < 33) {
		usage "Invalid number of bits for mask";
	}

	$net = join('_', $addr, $bits);

} elsif ($flags{infile}) {
	usage if (@ARGV != 1);

	# $ARGV[0] is a filename
	$net = $ARGV[0];
}

################################################################################
# Check for whois, tee, nmap, amap, and DNS resolution
################################################################################
# only check for whois and amap command if their flags are set
if ($flags{whois}) {
	my $chk_whois = `whois --version 2>&1 | head -n1`;
	die "QUITTING: Could not find whois command\n"
    	unless $chk_whois =~ /^Version/;
}
if ($flags{amap}) {
	my $chk_amap = `amap | head -n1`;
	die "QUITTING: Could not find amap command\n"
		unless $chk_amap =~ /^amap v/;
}

# check for all these commands regardless
my $chk_tee = `tee --version | head -n1`;
my $chk_nmap = `nmap -V | tail -n1`;
my $chk_dns = `host www.google.com | grep 'has address'`;

die "QUITTING: Could not find tee command\n"
    unless $chk_tee =~ /\(GNU coreutils\)/;
die "QUITTING: Could not find nmap command\n"
    unless $chk_nmap =~ /^Nmap version/;
die "QUITTING: Could not resolve DNS names\n"
    unless $chk_dns;

################################################################################
# Create directory structure and log file
################################################################################
if (-e "net-$net") {
    die "QUITTING: Output directory net-$net already exists\n";
} else {
    mkdir "net-$net";
    mkdir "net-$net/data/";
}

open (LOG, ">net-$net/scanlog.txt")
    or die "QUITTING: Cannot open log file for writing\n";

# Determine IP information for logs
my $ip_addr = my $ip_mask = my $if = my $gateway = 0;
open (SCAN, "netstat -rn |");
while (<SCAN>) {
    if (/^0\.0\.0\.0/) {
        my @col = split;
        $gateway = $col[1];
        $if = $col[7];
    }
}
open (SCAN, "ifconfig $if |");
while (<SCAN>) {
    if (/inet addr:/) {
        my @col = split;
        $ip_addr = $col[1];
        $ip_mask = $col[3];

        $ip_addr =~ s/^.*://;
        $ip_mask =~ s/^.*://;
    }
}

my $start = time;
if (!$flags{infile}) {
	print LOG addTime("Monthly scan started against $addr/$bits\n");
} else {
	print LOG addTime("Monthly scan using hostfile $net\n");
}
print LOG addTime("Using IP $ip_addr/$ip_mask\n");
print LOG addTime("Using gateway $gateway\n");

# whois
if ($flags{whois}) { whois($net, \%flags); }

# ICMP and SYN sweeps
if ($flags{ping}) {
	icmp_sweep($net, \%flags);
	syn_sweep($net, \%flags);
}

################################################################################
# Create hosts file from sweeps
################################################################################
my %hosts;
open (SCAN, "grep -h Up net-$net/data/*.gnmap |");
while (<SCAN>) {
    my @col = split;
    $hosts{$col[1]} = pack('C4', split(/\./, $col[1]));
}

my $num_hosts = scalar(keys %hosts);
if ($num_hosts) {
    open (OUTPUT, ">net-$net/data/hosts.txt")
        or die "QUITTING: Cannot open hosts file for writing\n";
    foreach my $ip (sort { $hosts{$a} cmp $hosts{$b} } keys %hosts) {
        print OUTPUT "$ip\n";
    }

    my $result = ($num_hosts > 1) ? "hosts" : "host";
    print LOG addTime("Created hosts.txt file with $num_hosts $result\n");
    print "Continuing scan against $num_hosts unique $result...\n";
} else {
    die "QUITTING: No hosts found during discovery phase\n";
}

# Full TCP scan against found hosts
if ($flags{tcp}) { tcp_scan($net, \%flags); }

# Amap scan
if ($flags{amap}) { amap_scan($net, \%flags); }

################################################################################
# Print output
################################################################################
print LOG addTime("Compiling data\n");
print "Compiling data...\n";

### ICMP ping discovery ###
%hosts = ();
open (SCAN, "grep Up net-$net/data/nmap_ICMPping-$net.gnmap |");
while (<SCAN>) {
    my @col = split;
    $hosts{$col[1]} = pack('C4', split(/\./, $col[1]));
}

open (OUTPUT, ">net-$net/discovery-ICMP.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a} cmp $hosts{$b} } keys %hosts) {
    print OUTPUT "$ip\n";
}

### ICMP smurf discovery ###
%hosts = ();
open (SCAN, "grep Smurf net-$net/data/nmap_ICMPping-$net.gnmap |");
while (<SCAN>) {
    my @col = split;
    $hosts{$col[1]} = pack('C4', split(/\./, $col[1]));
}

open (OUTPUT, ">net-$net/discovery-Smurf.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a} cmp $hosts{$b} } keys %hosts) {
    print OUTPUT "$ip\n";
}

### SYN ping discovery ###
%hosts = ();
open (SCAN, "grep -h Up net-$net/data/nmap_SYNping*-$net.gnmap |");
while (<SCAN>) {
    my @col = split;
    $hosts{$col[1]} = pack('C4', split(/\./, $col[1]));
}

open (OUTPUT, ">net-$net/discovery-SYN.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a} cmp $hosts{$b} } keys %hosts) {
    print OUTPUT "$ip\n";
}

### Ports ###
%hosts = ();
if ($flags{tcp}) {
open (SCAN, "grep ^Host: net-$net/data/nmap_TCPscan-$net.gnmap |");
while (<SCAN>) {
    my @col = split('\t', $_);
    my (undef, $ip, undef) = split('\s', $_);

    foreach my $item (@col) {
        $hosts{$ip}{'cache'} = pack('C4', split(/\./, $ip));

        if ($item =~ /^Host:/) {
            if ($item =~ /\((.+)\)/) {
                $hosts{$ip}{'dns'} = $1;
            }
        } elsif ($item =~ /^Ports:/) {
            $item =~ s/^Ports: //;
            my @ports = split('/, ', $item);

            foreach my $port (@ports) {
                my @info = split('\/', $port);
                $hosts{$ip}{'ports'}{$info[0]}{'state'} = $info[1];
                $hosts{$ip}{'ports'}{$info[0]}{'service'} = $info[4];
                $hosts{$ip}{'ports'}{$info[0]}{'version'} = $info[6];
            }
        } elsif ($item =~ /^Ignored State:/) {
            print "DEBUG: $item\n";
        } elsif ($item =~ /^OS:/) {
            $item =~ s/^OS: //;
            $hosts{$ip}{'os'} = $item;
        }
    }
}

open (OUTPUT, ">net-$net/hosts-ports.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a}{'cache'} cmp $hosts{$b}{'cache'} } keys %hosts) {
    if (exists($hosts{$ip}{'ports'})) {
        my $ports = $hosts{$ip}{'ports'};
        foreach my $port (sort { $ports->{$a} <=> $ports->{$b} } keys %$ports) {
            print OUTPUT join("\t", $ip,
                                    "$port/tcp",
                                    $ports->{$port}{'state'},
                                    $ports->{$port}{'service'}) .
                         "\n";
        }
    }
}

### DNS entries ###
open (OUTPUT, ">net-$net/hosts-dns.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a}{'cache'} cmp $hosts{$b}{'cache'} } keys %hosts) {
    if (exists($hosts{$ip}{'dns'}) and defined($hosts{$ip}{'dns'})) {
        print OUTPUT "$ip\t$hosts{$ip}{'dns'}\n";
    }
}

### OS fingerprints ###
open (OUTPUT, ">net-$net/hosts-os.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a}{'cache'} cmp $hosts{$b}{'cache'} } keys %hosts) {
    if (exists($hosts{$ip}{'os'}) and defined($hosts{$ip}{'os'})) {
        print OUTPUT "$ip\t$hosts{$ip}{'os'}\n";
    }
}

### Version ###
open (OUTPUT, ">net-$net/hosts-version.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a}{'cache'} cmp $hosts{$b}{'cache'} } keys %hosts) {
    if (exists($hosts{$ip}{'ports'})) {
        my $ports = $hosts{$ip}{'ports'};
        foreach my $port (sort { $ports->{$a} <=> $ports->{$b} } keys %$ports) {
            if (exists($ports->{$port}{'version'}) and
                    defined($ports->{$port}{'version'}) and
                    $ports->{$port}{'state'} eq 'open') {
                print OUTPUT join("\t", $ip,
                                        "$port/tcp",
                                        $ports->{$port}{'version'},) .
                             "\n";
            }
        }
    }
}
} # if $flags{tcp}

### Banners ###
%hosts = ();
if ($flags{amap}) {
open (SCAN, "grep -v ^# net-$net/data/amap-$net.txt |");
while (<SCAN>) {
    # Grab IP address
    my $start = 0;
    my $stop = index($_, ':', $start);
    my $ip = substr($_, $start, $stop - $start);

    # Grab port number
    $start = $stop + 1;
    $stop = index($_, ':', $start);
    my $port = substr($_, $start, $stop - $start);

    # Skip protocol, status, and ssl
    $start = $stop + 1;
    $stop = index($_, ':', $start);
    $start = $stop + 1;
    $stop = index($_, ':', $start);
    $start = $stop + 1;
    $stop = index($_, ':', $start);

    # Grab identification
    $start = $stop + 1;
    $stop = index($_, ':', $start);
    my $id = substr($_, $start, $stop - $start);

    # Grab banner
    $start = $stop + 1;
    $stop = index($_, ':', $start);
    my $banner = substr($_, $start, $stop - $start);

    if ($banner) {
        $hosts{$ip}{'cache'} = pack('C4', split(/\./, $ip));
        $hosts{$ip}{'ports'}{$port}{'banner'} = $banner;
    }
}

open (OUTPUT, ">net-$net/hosts-banners.txt")
    or die "QUITTING: Cannot open file for writing\n";
foreach my $ip (sort { $hosts{$a}{'cache'} cmp $hosts{$b}{'cache'} } keys %hosts) {
    if (exists($hosts{$ip}{'ports'})) {
        my $ports = $hosts{$ip}{'ports'};
        foreach my $port (sort { $ports->{$a} <=> $ports->{$b} } keys %$ports) {
            if (exists($ports->{$port}{'banner'})) {
                print OUTPUT join("\t", $ip,
                                        "$port/tcp",
                                        $ports->{$port}{'banner'},) .
                             "\n";
            }
        }
    }
}
} # if $flags{amap}
################################################################################
# Cleanup
################################################################################
my $diff = time - $start;
print LOG addTime("Monthly scan completed in $diff seconds\n");
print "Monthly scan completed in $diff seconds\n";

###############################################################################
# Generate report file
###############################################################################
open(REPORT, ">net-$net/report.xml")
    or die "QUITTING: Cannot open report file for writing\n";

print REPORT qq(<?xml version="1.0" encoding="iso-8859-1"?>\n);
print REPORT qq(<report version="$VERSION">\n);

# get tool versions
($chk_nmap) = ($chk_nmap =~ /(\d\.\d+)/);
($chk_amap) = ($chk_amap =~ /v(\d.\d)/);

# get start and stop times from logfile
my $start_time = `head -n1 net-$net/scanlog.txt`;
my $stop_time = `tail -n1 net-$net/scanlog.txt`;
($start_time) = ($start_time =~ /^\[(.*)\]/);
($stop_time) = ($stop_time =~ /^\[(.*)\]/);

my $target;
if ($flags{infile}) {
	open (INFILE, "< $net") or die "Couldn't open $net for reading: $!";
	foreach (<INFILE>) {
			chomp;
			# if there is just an ip, then add an implied bit-mask of 32
			if ($_ =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
				$_ .= "/32";
			}
			$target .= "\n\t\t\t<network>$_</network>";
	}
} else {
	$target = "\n\t\t\t<network>$addr/$bits</network>";
}

print REPORT <<INFO
	<info>
	    <versions>
			<autoscan>1.0</autoscan>
			<nmap>$chk_nmap</nmap>
			<amap>$chk_amap</amap>
	    </versions>
	    <source>
			<ip>$ip_addr</ip>
			<netmask>$ip_mask</netmask>
			<gateway>$gateway</gateway>
	    </source>
	    <target>$target
		</target>
	    <date>
			<start>$start_time</start>
			<stop>$stop_time</stop>
	    </date>
	</info>
INFO
;

# Results Section
print REPORT qq(\t<results>\n);
# ICMP
print_hosts("net-$net/discovery-ICMP.txt", "icmp");

# SYN
print_hosts("net-$net/discovery-SYN.txt", "syn");

if ($flags{tcp}) {
# DNS
print_hosts("net-$net/hosts-dns.txt", "dns");

# Ports
open(PORTS, "< net-$net/hosts-ports.txt")
    or die "couldn't open file hosts-ports.txt for reading";
print REPORT qq(\t\t<ports>\n);


while (<PORTS>) {
    chomp;
    my @cols = split;
    my $ip = $cols[0];
    my $state = $cols[2];
    my ($port,$proto) = split('/', $cols[1]);
    my $service = $cols[3];
    print REPORT qq(\t\t\t<port proto="$proto" number="$port" service="$service">\n);
    print REPORT qq(\t\t\t\t<host ip="$ip">\n);
    print REPORT qq(\t\t\t\t\t<state>$state</state>\n);
    print REPORT qq(\t\t\t\t</host>\n);
    print REPORT qq(\t\t\t</port>\n);
}
close PORTS;
print REPORT qq(\t\t</ports>\n);

# OS
open(OS, "< net-$net/hosts-os.txt")
    or die "couldn't open file hosts-os.txt for reading";
print REPORT qq(\t\t<os>\n);
while (<OS>) {
    chomp;
    my @cols = split;
    my $ip = shift @cols;
    my $os = join(' ', @cols);
    print REPORT qq(\t\t\t<host ip="$ip">\n);
    print REPORT qq(\t\t\t\t<data>$os</data>\n);
    print REPORT qq(\t\t\t</host>\n);
}
close OS;
print REPORT qq(\t\t</os>\n);

# Version
open(VER, "< net-$net/hosts-version.txt")
    or die "couldn't open file hosts-version.txt for reading";
print REPORT qq(\t\t<version>\n);
while (<VER>) {
    chomp;
    my @cols = split;
    my $ip = shift @cols;
    my ($port, $proto) = split('/', shift(@cols));
    my $ver = join(' ', @cols);
    print REPORT qq(\t\t\t<port proto="$proto" number="$port">\n);
    print REPORT qq(\t\t\t\t<host ip="$ip">\n);
    print REPORT qq(\t\t\t\t\t<data>$ver</data>\n);
    print REPORT qq(\t\t\t\t</host>\n);
    print REPORT qq(\t\t\t</port>\n);
}
close VER;
print REPORT qq(\t\t</version>\n);
} # if $flags{tcp}

# Banners
print REPORT qq(\t\t<banners>\n);
if ($flags{amap}) {
open(BAN, "< net-$net/hosts-banners.txt")
    or die "couldn't open file hosts-banners.txt for reading";
while (<BAN>) {
    chomp;
    my @cols = split;
    my $ip = shift @cols;
    my ($port, $proto) = split('/', shift(@cols));
    my $ban = join(' ', @cols);
    print REPORT qq(\t\t\t<port proto="$proto" number="$port">\n");
    print REPORT qq(\t\t\t\t<host ip="$ip">\n);
    print REPORT qq(\t\t\t\t\t<data>$ban</data>\n);
    print REPORT qq(\t\t\t\t</host>\n);
    print REPORT qq(\t\t\t</port>\n);
}
close BAN;
} # if $flags{amap}
print REPORT qq(\t\t</banners>\n);


print REPORT qq(\t</results>\n);
print REPORT qq(</report>\n);

close REPORT;
