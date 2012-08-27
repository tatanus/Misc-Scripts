#!/usr/bin/perl

while(<STDIN>) {
	chomp;
	`smbclient -NL //$_ &> SMB/$_.smb`;
}
