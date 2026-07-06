#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'App::Geshtinanna' ) || print "Bail out!\n";
}

diag( "Testing App::Geshtinanna $App::Geshtinanna::VERSION, Perl $], $^X" );
