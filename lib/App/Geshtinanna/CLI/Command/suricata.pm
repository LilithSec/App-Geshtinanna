package App::Geshtinanna::CLI::Command::suricata;

use 5.006;
use strict;
use warnings;
use App::Geshtinanna::CLI -command;
use App::Geshtinanna::Config;
use App::Geshtinanna::Suricata;
use App::Geshtinanna::SetInfo;

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
        [ 'setup',      'report which Zorita sets were installed (they are always ensured before running)' ],
        [ 'force',      'overwrite an existing set info.json from the shipped prototype' ],
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

    # Always make sure the Zorita sets the config references exist (and the
    # basedir with them); otherwise the follow loop dies on the first line for a
    # set with "no info.json". install() skips sets that already have one, so
    # this is a cheap idempotent step on every start. --setup just makes it
    # verbose; --force re-derives the info.json from the shipped prototype.
    my @created = App::Geshtinanna::SetInfo->install(
        basedir => $basedir,
        slug    => $sur->{slug} // 'suricata',
        flows   => $sur->{flows} || {},
        share   => $self->_share_dir( $opt->{share} ),
        force   => $opt->{force},
    );
    if ( $opt->{setup} || @created ) {
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

# Locate the installed set_info_jsons share dir (falls back to the in-repo copy
# so the command works from a git checkout without installing).
sub _share_dir {
    my ( $self, $override ) = @_;
    return App::Geshtinanna::SetInfo->share_dir($override);
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;
