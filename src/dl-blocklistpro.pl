#!/usr/bin/perl

# Download from blocklistpro.com

use File::Temp qw/ tempfile tempdir /;

use strict;

my $ua = "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.5) Gecko/2008122406 Gentoo Firefox/3.0.5";
my @suff = ("", ".dat.gz", ".gz", ".zip");

foreach my $arg (@ARGV) {
    my $url_list = "http://blocklistpro.com/download-center/ip-filters/";
    my $url_detail;

    open(PAGE, "wget -q -U \"$ua\" -O- $url_list |");

  OUTER:
    while (my $ln = <PAGE>) {
        if ($ln =~ /download limit has been reached/) {
            die "download limit reached"
        }
        if ($ln =~ /href=\"(http:\/\/.+\/p2p-ip-filters\/[0-9]+-(\S+)\.html)\"/) {
            foreach my $s (@suff) {
                if ($2 eq $arg . $s) {
                    $url_detail = $1;
                    $arg = $2;
                    last OUTER;
                }
            }
        }
    }

    if (length($url_detail) == 0) {
        die "cannot find the detail url";
    }

    my $url = $url_detail;
    $url =~ s/view-details/start-download/;
    my $path = "/var/lib/nfblock";
    my $url2 = "";
    my $outfile;

    if ($arg =~ /[0-9]+-(\S+)/) {
        $outfile = $1;
    } else {
        $outfile = $arg;
    }

    $outfile = $path . "/" . $outfile;

    open(PAGE, "wget -q -U \"$ua\" -O- $url |");

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

    if (system("wget -q -U \"$ua\" -O $tmpfile \"$url2\"") == 0) {
        if ($outfile =~ /^(.*)\.zip$/) {
            my $tmpdir = tempdir();
            system("unzip $tmpfile -d $tmpdir");
            my @files = <$tmpdir/*>;
            if ($#files == -1) {
                print STDERR "no files in the zip file";
            } else {
                system("gzip -c9 $files[0] > $1.dat.gz");
                unlink(@files);
            }
            unlink($tmpdir);
            unlink($tmpfile);
        } else {
            rename($tmpfile, $outfile);
        }
    } else {
        unlink($tmpfile);
    }
}
