#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

my @modules = qw(
    App::Geshtinanna
    App::Geshtinanna::Config
    App::Geshtinanna::Suricata
    App::Geshtinanna::SetInfo
    App::Geshtinanna::CLI
    App::Geshtinanna::CLI::Command::suricata
);

plan tests => scalar @modules;

use_ok($_) || BAIL_OUT("failed to load $_") for @modules;

diag( "Testing App::Geshtinanna $App::Geshtinanna::VERSION, Perl $], $^X" );
