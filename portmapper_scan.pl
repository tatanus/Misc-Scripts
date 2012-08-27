#!/usr/bin/perl

while(<STDIN>) {
	chomp;
	`rpcinfo -p $_ > RPCINFO/$_.rpcinfo`;
}
