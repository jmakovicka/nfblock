#!/usr/bin/perl

# Download from blocklistpro.com

use strict;

foreach my $arg (@ARGV) {
    my $url = "http://blocklistpro.com/download-center/start-download/ip-filters/" . $arg . ".html";
    my $path = "/var/lib/nfblock";
    my $url2 = "";
    my $outfile;

    if ($arg =~ /[0-9]+-(\S+)/) {
        $outfile = $1;
    } else {
        $outfile = $arg;
    }

    $outfile = $path . "/" . $outfile;

    open(PAGE, "wget -q -O- $url |");

    while (my $ln = <PAGE>) {
        if ($ln =~ /download limit has been reached/) {
            die "download limit reached"
        }
        if ($ln =~ /(http:\/\/\S+\?chk\=[0-9a-f]+\&no_html\=1)/) {
            $url2 = $1;
            last;
        }
    }

    if (length($url2) == 0) {
        die "cannot find the download url";
    }

    my $tmpfile = $outfile . ".tmp";

    if (system("wget -q -O $tmpfile \"$url2\"") == 0) {
        rename($tmpfile, $outfile);
    } else {
        unlink($tmpfile);
    }
}
