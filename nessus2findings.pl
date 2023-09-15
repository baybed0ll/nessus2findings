#!/usr/bin/env perl

use Text::CSV;
use Sort::Key::Multi qw(u5_skeysort);

sub uniq {
    my %seen; 
    grep !$seen{$_}++, @_ 
}

my $input = $ARGV[0] || die;
die "not a csv" unless ($input =~ /\.csv$/);

my %findings = ();

my %risks = qw(
    Critical    4
    High        3
    Medium      2
    Low         1
);

my $csv = Text::CSV->new ({ binary => 1, auto_diag => 1 });
open my $fh, "<:encoding(utf8)", $input or die "$input: $!";

while (my $row = $csv->getline($fh)) {
    my $risk = $row->[3];
    next if ($risk eq 'None' || $risk eq 'Risk');

    my $host  = $row->[4];
    my $proto = $row->[5];
    my $port  = $row->[6];
    my $vuln  = $row->[7];

    $findings{$vuln}{'risk'} = $risks{$risk};
    push @{$findings{$vuln}{'hosts'}}, $host . ":" . $port . "/" . uc($proto);
}

close($fh);

foreach my $vuln (sort { $findings{$b}{'risk'} <=> $findings{$a}{'risk'} } keys %findings) {
    print "$vuln\n";

    my @hosts = u5_skeysort { /^(\d+)\.(\d+)\.(\d+)\.(\d+):(\d+)\/(\w+)$/ } uniq(@{$findings{$vuln}{'hosts'}});

    for $host (@hosts) {
        print "    $host\n";
    }

    print "\n";
}
