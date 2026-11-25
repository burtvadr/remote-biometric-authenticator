#!/usr/bin/env perl
# Rebuild the normative RBA Display Text 1 repertoire from pinned UCD data.
use strict;
use warnings;
use Unicode::UCD qw(prop_invmap prop_invlist);
die "Unicode 15.0.0 data required\n" unless Unicode::UCD::UnicodeVersion() eq '15.0.0';
my ($age, $av) = prop_invmap('Age');
my ($cat, $cv) = prop_invmap('General_Category');
my @di = prop_invlist('Default_Ignorable_Code_Point');
my ($ai,$ci,$di_i,$start)=(0,0,0,undef);
print "# RBA Display Text 1: UCD 15.0.0, Age <= 10.0, L/M/N/P/S/Zs, not Default_Ignorable_Code_Point\n";
print "# Inclusive hexadecimal scalar ranges; normative, not runtime locale data.\n";
for my $cp (0..0x110000) {
    ++$ai while $ai+1<@$age && $age->[$ai+1] <= $cp;
    ++$ci while $ci+1<@$cat && $cat->[$ci+1] <= $cp;
    ++$di_i while $di_i<@di && $di[$di_i] <= $cp;
    my $ok=$cp<0x110000 && $av->[$ai] =~ /^\d+(?:\.\d+)?$/ && $av->[$ai]<=10 && $cv->[$ci]=~/^(?:[LMNPS].|Zs)$/ && !($di_i%2);
    if ($ok) { $start=$cp unless defined $start; }
    elsif (defined $start) { printf "%06X\t%06X\n",$start,$cp-1; undef $start; }
}
