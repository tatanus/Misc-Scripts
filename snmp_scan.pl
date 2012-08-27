#!/usr/bin/perl

while(<STDIN>) {
	chomp;
	`snmpwalk -Cc -v1 -c public $_ system > SNMP/$_.snmp`;
	`snmpwalk -Cc -v1 -c public $_ 1.3.6.1.2.1.25.6.3.1.2 >> SNMP/$_.snmp`;
	`snmpwalk -Cc -v1 -c public $_ 1.3.6.1.4.1.77.1.2.25.1.1 >> SNMP/$_.snmp`;
}
