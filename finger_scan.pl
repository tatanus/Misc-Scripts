#!/usr/bin/perl

while(<STDIN>) {
	chomp;
	$target = "@" . $_;
	print "$target\n";
	`finger .\$target > FINGER/$_.finger`;
	`finger 0$target >> FINGER/$_.finger`;
	`finger "0 1 2 3 4 5 6 7 8 9"$target >> FINGER/$_.finger`;
	`finger "a a a a a a a a"$target >> FINGER/$_.finger`;
	`finger "a b c d e f g h"$target >> FINGER/$_.finger`;
	`finger /etc/passwd$target >> FINGER/$_.finger`;
}
