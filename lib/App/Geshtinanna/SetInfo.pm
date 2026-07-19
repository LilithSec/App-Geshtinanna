package App::Geshtinanna::SetInfo;

use 5.006;
use strict;
use warnings;
use Carp   qw(croak);
use JSON::MaybeXS ();
use File::Spec;
use Algorithm::Classifier::IsolationForest::Zorita ();

=head1 NAME

App::Geshtinanna::SetInfo - Install shipped set prototypes as Zorita sets.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Geshtinanna::SetInfo;

    # one-time: create the Zorita sets a config's flows reference
    App::Geshtinanna::SetInfo->install(
        basedir => '/var/db/zorita/',
        slug    => 'suricata',
        flows   => $config->{suricata}{flows},
        share   => '/usr/local/share/App-Geshtinanna/set_info_jsons',
    );

=head1 DESCRIPTION

The prototypes under F<share/set_info_jsons/{online,batch}/> are
L<Algorithm::Classifier::IsolationForest> B<prototype documents>
(C<schema.feature_names> + C<schema.mungers> + a C<params> block). A Zorita set
is described by an B<info.json> with a flatter shape (C<tags> + C<mungers> +
flat hyper-parameters). This module bridges the two: it reads a set's prototype
for the wanted mode and writes the equivalent Zorita C<info.json> via
C<write_info>, so L<App::Geshtinanna::Suricata>'s Writer / Online sinks have a
set to write to.

Run it once (or after changing a schema) per environment; it is a no-op-ish
setup step, not part of the hot path.

=head1 METHODS

=head2 prototype_to_info

    my $info = App::Geshtinanna::SetInfo->prototype_to_info(\%proto);

Pure conversion of a decoded prototype document into a Zorita C<info.json>
hashref: C<tags> from C<schema.feature_names>, C<mungers> from
C<schema.mungers>, the C<missing> policy, every key of C<params> flattened up,
and (for a batch prototype) a default C<days_back> of 7. An C<undef>
C<max_depth> is dropped so it defaults from C<sample_size>.

=cut

sub prototype_to_info {
    my ( $class, $proto ) = @_;
    ref $proto eq 'HASH' && $proto->{schema}
        or croak 'prototype_to_info: not a prototype document';

    my $schema = $proto->{schema};
    my %info = (
        tags => $schema->{feature_names},
        ( $schema->{mungers} ? ( mungers => $schema->{mungers} ) : () ),
        ( defined $schema->{missing} ? ( missing => $schema->{missing} ) : () ),
        %{ $proto->{params} || {} },
    );

    delete $info{max_depth} unless defined $info{max_depth};

    # batch sets train on a window read back from disk; online sets do not.
    $info{days_back} //= 7 if ( $proto->{class} // '' ) eq 'batch';

    return \%info;
}

=head2 prototype_path

    my $path = App::Geshtinanna::SetInfo->prototype_path($share, $type, $set);

Path to a set's shipped prototype: C<$share/$type/Geshtinanna_Suricata_$set.json>
where C<$type> is C<online> or C<batch>.

=cut

sub prototype_path {
    my ( $class, $share, $type, $set ) = @_;
    return File::Spec->catfile( $share, $type, "Geshtinanna_Suricata_$set.json" );
}

=head2 install

    my @created = App::Geshtinanna::SetInfo->install(
        basedir => ..., slug => ..., flows => \%flows, share => $dir,
        force   => 0,   # optional: overwrite an existing info.json
    );

For every enabled flow in C<%flows>, reads the prototype for its mode and
writes the derived C<info.json> into Zorita (a C<type =E<gt> 'online'> Zorita
object for online flows, a plain one for batch). Skips a set that already has an
C<info.json> unless C<force> is set. Returns the list of C<"set (type)">
strings actually written.

=cut

sub install {
    my ( $class, %args ) = @_;
    my $flows = $args{flows} or croak 'install: flows required';
    my $share = $args{share} or croak 'install: share dir required';
    my $slug  = $args{slug}  // 'suricata';

    my $json = JSON::MaybeXS->new->utf8;
    my %z;   # cache Zorita objects by mode

    my @created;
    for my $set ( sort keys %$flows ) {
        my $f = $flows->{$set};
        my $enable = exists $f->{enable} ? $f->{enable} : 1;
        next unless $enable;
        my $type = $f->{type} // 'batch';

        my $path = $class->prototype_path( $share, $type, $set );
        unless ( -f $path ) {
            warn "SetInfo: no $type prototype for '$set' at $path, skipping\n";
            next;
        }

        my $z = $z{$type} ||= Algorithm::Classifier::IsolationForest::Zorita->new(
            ( defined $args{basedir} ? ( basedir => $args{basedir} ) : () ),
            ( $type eq 'online' ? ( type => 'online' ) : () ),
        );

        if ( !$args{force} && $z->read_info( slug => $slug, set => $set ) ) {
            next;   # already installed
        }

        open my $fh, '<', $path or croak "SetInfo: read $path: $!";
        my $proto = $json->decode( do { local $/; <$fh> } );
        close $fh;

        my $info = $class->prototype_to_info($proto);
        $z->write_info( slug => $slug, set => $set, info => $info );
        push @created, "$set ($type)";
    }

    return @created;
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;
