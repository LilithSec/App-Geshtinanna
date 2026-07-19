#!/usr/bin/env perl

# Derive the batch-mode set prototypes from the online ones.
#
# The online prototypes under share/set_info_jsons/online/ are the source of
# truth for each set's feature schema and munger plan. A batch prototype shares
# that schema but swaps the streaming hyper-parameters (window_size /
# max_leaf_samples / growth) for the classic Isolation Forest knobs
# (sample_size / mode / extension_level / voting) and can use the richer batch
# `missing` policy (nan) that the online model lacks.
#
# This is a mechanical starting point, not a hand-tuned schema: the emitted
# params are defaults meant to be gone over per set. Re-run after editing an
# online prototype to keep its batch twin in sync.
#
#   perl maint/online2batch.pl            # write share/set_info_jsons/batch/*
#   perl maint/online2batch.pl --check    # diff only, non-zero exit if stale

use strict;
use warnings;
use FindBin;
use JSON::MaybeXS;
use File::Spec;

my $base    = File::Spec->catdir( $FindBin::Bin, '..', 'share', 'set_info_jsons' );
my $src_dir = File::Spec->catdir( $base, 'online' );
my $dst_dir = File::Spec->catdir( $base, 'batch' );
my $check   = grep { $_ eq '--check' } @ARGV;

# canonical, sorted output so the files are diff-stable
my $json = JSON::MaybeXS->new->utf8->canonical(1)->pretty(1)->indent_length(3);

mkdir $dst_dir unless -d $dst_dir;

opendir my $dh, $src_dir or die "open $src_dir: $!";
my @files = sort grep { /^Geshtinanna_Suricata_.*\.json$/ } readdir $dh;
closedir $dh;

my $stale = 0;
for my $file (@files) {
    my $proto = decode_json( slurp( File::Spec->catfile( $src_dir, $file ) ) );
    my $batch = to_batch($proto);
    my $text  = $json->encode($batch);

    my $out = File::Spec->catfile( $dst_dir, $file );
    if ($check) {
        my $have = -e $out ? slurp($out) : '';
        if ( $have ne $text ) { warn "stale: $file\n"; $stale = 1; }
        next;
    }
    open my $fh, '>', $out or die "write $out: $!";
    print {$fh} $text;
    close $fh;
    print "wrote batch/$file\n";
}

exit( $stale ? 1 : 0 );

sub to_batch {
    my ($proto) = @_;
    my %b = %$proto;

    $b{class} = 'batch';

    # a real batch model can route missing cells down both branches (nan)
    # instead of the online model's learn-as-zero.
    $b{schema} = { %{ $proto->{schema} } };
    $b{schema}{missing} = 'nan';

    # swap streaming knobs for the classic Isolation Forest ones. Values are
    # defaults to be tuned per set, mirroring the online prototypes' TODO.
    my $p = $proto->{params} || {};
    $b{params} = {
        n_trees         => $p->{n_trees}       // 100,
        sample_size     => 256,
        max_depth       => undef,          # undef => derive from sample_size
        seed            => $p->{seed}          // 42,
        mode            => 'axis',
        extension_level => 0,
        contamination   => $p->{contamination} // 0.01,
        voting          => 'soft',
    };

    $b{schema_version} = ( $proto->{schema_version} // '0' ) . '-batch';
    $b{schema_description}
        = '(batch) ' . ( $proto->{schema_description} // '' );

    return \%b;
}

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "read $path: $!";
    local $/;
    return <$fh>;
}
