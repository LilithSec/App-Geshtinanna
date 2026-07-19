package App::Geshtinanna;

use 5.006;
use strict;
use warnings;

=head1 NAME

App::Geshtinanna - The great new App::Geshtinanna!

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';


=head1 SYNOPSIS

App::Geshtinanna ingests data from Suricata (and, planned, LibreNMS) into online
Isolation Forest models for anomaly detection, backed by
L<Algorithm::Classifier::IsolationForest::Zorita>.

This package is the distribution namespace and version anchor. The working parts
live in its submodules and the C<geshtinanna> command:

=over 4

=item * L<App::Geshtinanna::Config> - load F</usr/local/etc/geshtinanna.toml>.

=item * L<App::Geshtinanna::Suricata> - a L<POE> engine that tails Suricata EVE
flow logs and feeds each event into a Zorita set.

=item * L<App::Geshtinanna::SetInfo> - install the shipped set prototypes
(F<share/set_info_jsons/>) as Zorita sets.

=item * L<App::Geshtinanna::CLI> - the C<geshtinanna> command dispatcher.

=back

    use App::Geshtinanna::Config;
    use App::Geshtinanna::Suricata;

    my $config = App::Geshtinanna::Config->load;
    App::Geshtinanna::Suricata->new(
        suricata => $config->{suricata},
        basedir  => $config->{zorita}{basedir},
    )->run;

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-app-geshtinanna at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=App-Geshtinanna>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::Geshtinanna


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=App-Geshtinanna>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/App-Geshtinanna>

=item * Search CPAN

L<https://metacpan.org/release/App-Geshtinanna>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl


=cut

1; # End of App::Geshtinanna
