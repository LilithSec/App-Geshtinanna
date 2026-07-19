package App::Geshtinanna::CLI;

use 5.006;
use strict;
use warnings;
use App::Cmd::Setup -app;

=head1 NAME

App::Geshtinanna::CLI - Command dispatcher for the C<geshtinanna> program.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 DESCRIPTION

The L<App::Cmd> application behind the C<geshtinanna> binary. Commands live
under C<App::Geshtinanna::CLI::Command::>: C<suricata> (follow EVE logs into
Zorita) and C<config> (print a default configuration).

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;
