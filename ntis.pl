#!/usr/bin/perl

while (<STDIN>) {
	chomp;
	`./ntis.exe -n $_`;
}
