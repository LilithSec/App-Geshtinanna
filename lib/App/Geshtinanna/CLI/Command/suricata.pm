package App::Geshtinanna::CLI::Command::suricata;

use 5.006;
use strict;
use warnings;
use App::Geshtinanna::CLI -command;
use App::Geshtinanna::Config;
use App::Geshtinanna::Suricata;
use App::Geshtinanna::SetInfo;
use File::Spec;

our $VERSION = '0.0.1';

=head1 NAME

App::Geshtinanna::CLI::Command::suricata - Follow Suricata EVE logs into Zorita.

=head1 SYNOPSIS

    geshtinanna suricata                     # tail every enabled flow, forever
    geshtinanna suricata --config ./g.toml   # use a specific config
    geshtinanna suricata --setup             # install Zorita sets, then run
    geshtinanna suricata --setup --no-run    # just install the sets and exit

=cut

sub abstract { 'follow Suricata EVE flow logs into Zorita sets' }

sub usage_desc { '%c suricata %o' }

sub opt_spec {
    return (
        [ 'config|c=s', 'config file (default: ' . App::Geshtinanna::Config->default_path . ')' ],
        [ 'setup',      'create the Zorita sets referenced by the config before running' ],
        [ 'force',      'with --setup, overwrite an existing set info.json' ],
        [ 'no-run',     'do not start the follow loop (useful with --setup)' ],
        [ 'share=s',    'set_info_jsons share dir (default: dist share dir)' ],
    );
}

sub execute {
    my ( $self, $opt, $args ) = @_;

    my $config = App::Geshtinanna::Config->load( $opt->{config} );
    my $sur    = $config->{suricata}
        or die "config has no [suricata] table\n";
    my $basedir = $config->{zorita}{basedir};

    if ( $opt->{setup} ) {
        my @created = App::Geshtinanna::SetInfo->install(
            basedir => $basedir,
            slug    => $sur->{slug} // 'suricata',
            flows   => $sur->{flows} || {},
            share   => $self->_share_dir( $opt->{share} ),
            force   => $opt->{force},
        );
        print @created
            ? "installed sets: " . join( ', ', @created ) . "\n"
            : "no new sets to install\n";
    }

    return if $opt->{no_run};

    my $engine = App::Geshtinanna::Suricata->new(
        suricata => $sur,
        basedir  => $basedir,
    );
    $engine->run;
    return;
}

# Locate the installed set_info_jsons share dir, falling back to the in-repo
# copy so the command works from a git checkout without installing.
sub _share_dir {
    my ( $self, $override ) = @_;
    return $override if $override;

    my $installed = eval {
        require File::ShareDir;
        File::Spec->catdir(
            File::ShareDir::dist_dir('App-Geshtinanna'), 'set_info_jsons' );
    };
    return $installed if $installed && -d $installed;

    # dev fallback: walk up from this file (.../lib/App/Geshtinanna/CLI/Command/
    # suricata.pm) five dirs to the repo root and use its in-tree share/.
    require Cwd;
    require File::Basename;
    my @dirs = File::Spec->splitdir(
        File::Basename::dirname( Cwd::abs_path(__FILE__) ) );
    splice @dirs, -5;   # drop Command, CLI, Geshtinanna, App, lib
    my $repo = File::Spec->catdir( @dirs, 'share', 'set_info_jsons' );
    return $repo if -d $repo;

    die "could not locate the set_info_jsons share dir (pass --share)\n";
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;
