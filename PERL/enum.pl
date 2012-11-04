#!/usr/bin/perl

while (<STDIN>) {
	chomp;
	`./enum.exe -U -M -N -S -P -G -L -d $_ > $_.enum`;
}
