package App::Geshtinanna::Config;

use 5.006;
use strict;
use warnings;
use Carp   qw(croak);
use TOML::Tiny qw(from_toml);

=head1 NAME

App::Geshtinanna::Config - Load the Geshtinanna TOML configuration.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Geshtinanna::Config;

    my $config = App::Geshtinanna::Config->load;              # default path
    my $config = App::Geshtinanna::Config->load($some_path);  # or an explicit one

    my $basedir = $config->{zorita}{basedir};
    my $flows   = $config->{suricata}{flows};

=head1 DESCRIPTION

Thin wrapper around L<TOML::Tiny> that reads the main Geshtinanna config file
and returns it as a plain hashref. The default location is
F</usr/local/etc/geshtinanna.toml> (see L</default_path>).

The config is intentionally just decoded TOML: each consumer
(L<App::Geshtinanna::Suricata>, a future LibreNMS ingester, ...) picks the sub
hash it cares about out of the top-level result. A rough shape:

    [zorita]
    basedir = "/var/db/zorita/"

    [suricata]
    slug = "suricata"

    [suricata.flows.flow]
    enable = true
    type   = "batch"      # batch | online
    path   = "/var/log/suricata/flows/current/flow.json"

=head1 METHODS

=head2 default_path

    my $path = App::Geshtinanna::Config->default_path;

The default config path, F</usr/local/etc/geshtinanna.toml>. Honors the
C<GESHTINANNA_CONFIG> environment variable as an override so the daemon can be
pointed at a test config without a command-line flag.

=cut

sub default_path {
    return $ENV{GESHTINANNA_CONFIG} || '/usr/local/etc/geshtinanna.toml';
}

=head2 load

    my $config = App::Geshtinanna::Config->load;
    my $config = App::Geshtinanna::Config->load($path);

Reads and decodes the config file, returning the top-level hashref. Croaks if
the file is missing, unreadable, or not valid TOML.

=cut

sub load {
    my ( $class, $path ) = @_;
    $path //= $class->default_path;

    open my $fh, '<:encoding(UTF-8)', $path
        or croak "could not open config '$path': $!";
    my $toml = do { local $/; <$fh> };
    close $fh;

    my ( $config, $err ) = from_toml($toml);
    croak "could not parse config '$path': $err" if $err;

    return $config;
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;
