#!/usr/bin/perl

while(<STDIN>) {
	chomp;
	`showmount -e $_ > SHOWMOUNT/$_.showmount`;
}
