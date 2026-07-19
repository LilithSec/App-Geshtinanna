package App::Geshtinanna::Suricata;

use 5.006;
use strict;
use warnings;
use Carp qw(croak);
use Sys::Hostname qw(hostname);
use Time::Local ();
use JSON::MaybeXS qw(decode_json);
use POE qw(Wheel::FollowTail);
use Algorithm::EventsPerSecond ();
use Algorithm::Classifier::IsolationForest::Zorita ();
use Algorithm::Classifier::IsolationForest::Zorita::Writer ();
use Algorithm::Classifier::IsolationForest::Zorita::Online::Client ();

=head1 NAME

App::Geshtinanna::Suricata - Tail Suricata EVE flow logs into Zorita Isolation Forest sets.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use App::Geshtinanna::Config;
    use App::Geshtinanna::Suricata;

    my $config = App::Geshtinanna::Config->load;

    my $engine = App::Geshtinanna::Suricata->new(
        suricata => $config->{suricata},        # the [suricata] table
        basedir  => $config->{zorita}{basedir}, # zorita basedir
    );

    $engine->run;   # POE loop: tail every enabled flow, feed Zorita, forever

=head1 DESCRIPTION

A L<POE> engine that follows one Suricata EVE JSON log per configured flow
type and feeds each event into the matching L<Zorita|Algorithm::Classifier::IsolationForest::Zorita>
set under a single slug (default C<suricata>).

Each configured flow is one Zorita set. For every appended line the engine
decodes the EVE record, turns it into a tagged row via a per-flow B<extractor>
(the raw source fields the set's munger plan expects, plus any writer-computed
stateful columns such as rates), and hands it to that set's B<sink>:

=over 4

=item * C<type = "batch"> — an L<Algorithm::Classifier::IsolationForest::Zorita::Writer>
appends the row to disk for a later scheduled C<rebuild_model>.

=item * C<type = "online"> — an L<Algorithm::Classifier::IsolationForest::Zorita::Online::Client>
streams the row (C<mode =E<gt> 'learn'>) to the set's already-running
C<zorita streamd> daemon.

=back

The extractors here mirror the feature tables in the top-level F<README.md> and
the writer input contract in F<share/set_info_jsons/online/README.md>. Only a
representative handful (C<flow>, C<http>, C<dns>, C<tls>) are implemented so
far; any other configured flow logs a one-time warning and is skipped. New
flows are added by writing one C<_extract_$flow> method and registering it in
L</%EXTRACTORS>.

=cut

# set name -> extractor method name. Adding a flow = add a _extract_$flow
# method and an entry here.
my %EXTRACTORS = (
    flow => '_extract_flow',
    http => '_extract_http',
    dns  => '_extract_dns',
    tls  => '_extract_tls',
);

# set name -> EVE event_type, when they differ from the set name. Used only as
# a sanity filter against a mislabelled line.
my %EVENT_TYPE = (
    # dns_with_time => 'dns', ...
);

=head1 METHODS

=head2 new

    my $engine = App::Geshtinanna::Suricata->new(
        suricata => \%suricata_table,
        basedir  => '/var/db/zorita/',   # optional; Zorita's own default otherwise
    );

Parses the C<suricata> config table. Under it, C<flows> is a hash keyed by set
name; each value is a table with:

=over 4

=item * C<enable> — whether to tail this flow (default true).

=item * C<type> — C<"batch"> or C<"online"> (default C<"batch">).

=item * C<path> — the EVE log to follow (required for an enabled flow).

=back

C<slug> defaults to C<suricata>; C<rate_window> (seconds, default 60) sizes the
per-entity rate meters. Croaks on an unknown C<type> or a missing C<path>.

=cut

sub new {
    my ( $class, %args ) = @_;

    my $sur = $args{suricata}
        or croak 'App::Geshtinanna::Suricata->new requires a suricata config hashref';
    ref $sur eq 'HASH'
        or croak 'suricata config must be a hashref';

    my $self = bless {
        slug        => $sur->{slug}        // 'suricata',
        basedir     => $args{basedir},
        rate_window => $sur->{rate_window} // 60,
        flows       => {},        # set => { type => ..., path => ... }
        sinks       => {},        # set => writer/client object (lazy)
        rates       => {},        # arbitrary rate-meter cache
        warned      => {},        # one-time-warning dedupe
        json        => JSON::MaybeXS->new->utf8,
    }, $class;

    my $flows = $sur->{flows} || {};
    ref $flows eq 'HASH'
        or croak 'suricata.flows must be a hashref';

    for my $set ( sort keys %$flows ) {
        my $f = $flows->{$set};
        my $enable = exists $f->{enable} ? $f->{enable} : 1;
        next unless $enable;

        my $type = $f->{type} // 'batch';
        $type eq 'batch' || $type eq 'online'
            or croak "suricata.flows.$set.type must be 'batch' or 'online', not '$type'";

        my $path = $f->{path}
            or croak "suricata.flows.$set.path is required when enabled";

        $self->{flows}{$set} = { type => $type, path => $path };
    }

    return $self;
}

=head2 run

    $engine->run;

Spawns the POE session (one L<POE::Wheel::FollowTail> per enabled flow) and
runs the kernel until the process is signalled. Returns when the loop exits.

=cut

sub run {
    my ($self) = @_;

    keys %{ $self->{flows} }
        or croak 'no enabled suricata flows to follow';

    POE::Session->create(
        object_states => [
            $self => {
                _start     => '_poe_start',
                flow_line  => '_poe_flow_line',
                flow_reset => '_poe_flow_reset',
                flow_error => '_poe_flow_error',
            },
        ],
    );

    POE::Kernel->run;
    return 1;
}

# --- POE states --------------------------------------------------------------

sub _poe_start {
    my ( $self, $heap ) = @_[ OBJECT, HEAP ];

    for my $set ( sort keys %{ $self->{flows} } ) {
        my $path  = $self->{flows}{$set}{path};
        my $wheel = POE::Wheel::FollowTail->new(
            Filename   => $path,
            InputEvent => 'flow_line',
            ResetEvent => 'flow_reset',
            ErrorEvent => 'flow_error',
        );
        $heap->{wheels}{ $wheel->ID } = $wheel;   # keep the wheel alive
        $heap->{wheel_set}{ $wheel->ID } = $set;
    }

    return;
}

sub _poe_flow_line {
    my ( $self, $heap, $line, $wheel_id ) = @_[ OBJECT, HEAP, ARG0, ARG1 ];

    my $set = $heap->{wheel_set}{$wheel_id} or return;

    my $rec = eval { $self->{json}->decode($line) };
    if ( !$rec || ref $rec ne 'HASH' ) {
        $self->_warn_once( "decode:$set", "$set: skipping undecodable line" );
        return;
    }

    my $want = $EVENT_TYPE{$set} // $set;
    return if defined $rec->{event_type} && $rec->{event_type} ne $want;

    my $method = $EXTRACTORS{$set};
    if ( !$method ) {
        $self->_warn_once( "noext:$set",
            "$set: no extractor implemented yet, skipping its events" );
        return;
    }

    my $row = eval { $self->$method($rec) };
    if ($@) {
        $self->_warn_once( "ext:$set", "$set: extractor error: $@" );
        return;
    }
    return unless $row;   # extractor may skip a row it can't use

    $self->_feed( $set, $row );
    return;
}

sub _poe_flow_reset {
    my ( $self, $heap, $wheel_id ) = @_[ OBJECT, HEAP, ARG0 ];
    # log rotation: FollowTail reopened the file. Nothing else to do.
    return;
}

sub _poe_flow_error {
    my ( $self, $heap, $op, $errnum, $errstr, $wheel_id )
        = @_[ OBJECT, HEAP, ARG0, ARG1, ARG2, ARG3 ];
    my $set = $heap->{wheel_set}{$wheel_id} // '?';
    warn "App::Geshtinanna::Suricata: $set follow $op error $errnum: $errstr\n";
    return;
}

# --- sinks -------------------------------------------------------------------

# Return (building on first use) the Zorita sink for a set: a Writer for batch,
# an Online::Client for online. A construction failure is warned once and the
# row dropped, so one misconfigured set does not take down the whole loop.
sub _sink {
    my ( $self, $set ) = @_;
    return $self->{sinks}{$set} if exists $self->{sinks}{$set};

    my $type = $self->{flows}{$set}{type};
    my $sink = eval {
        if ( $type eq 'online' ) {
            my $z = $self->_zorita('online');
            Algorithm::Classifier::IsolationForest::Zorita::Online::Client->new(
                zorita => $z, slug => $self->{slug}, set => $set );
        }
        else {
            my $z = $self->_zorita('batch');
            Algorithm::Classifier::IsolationForest::Zorita::Writer->new(
                zorita => $z,
                slug   => $self->{slug},
                set    => $set,
                writer => $self->_writer_name,
            );
        }
    };
    if ( !$sink ) {
        $self->_warn_once( "sink:$set", "$set: cannot build $type sink: $@" );
    }

    return $self->{sinks}{$set} = $sink;   # cache even undef, so we warn once
}

sub _zorita {
    my ( $self, $type ) = @_;
    my $key = "z_$type";
    return $self->{$key} ||= Algorithm::Classifier::IsolationForest::Zorita->new(
        ( defined $self->{basedir} ? ( basedir => $self->{basedir} ) : () ),
        ( $type eq 'online' ? ( type => 'online' ) : () ),
    );
}

# writer name for batch sets: the hostname, sanitized to Zorita's name regexp.
sub _writer_name {
    my ($self) = @_;
    return $self->{writer_name} ||= do {
        my $h = hostname();
        $h =~ s/[^A-Za-z0-9\-\_\@\=\+]/_/g;
        $h = 'writer' unless length $h;
        $h;
    };
}

sub _feed {
    my ( $self, $set, $row ) = @_;
    my $sink = $self->_sink($set) or return;

    my $ok = eval {
        if ( $self->{flows}{$set}{type} eq 'online' ) {
            $sink->row( $row, mode => 'learn' );
        }
        else {
            $sink->write_named($row);
        }
        1;
    };
    $self->_warn_once( "feed:$set", "$set: feed failed: $@" ) unless $ok;
    return;
}

# --- extractors --------------------------------------------------------------
#
# Each returns a hashref keyed for the set's tagged row: raw source fields the
# munger plan reads (by tag name, or by a munger's `from`), plus any columns
# the writer must compute itself (rates, ratios, derived times). Return undef
# to skip an event that lacks what the set needs.

sub _extract_flow {
    my ( $self, $rec ) = @_;
    my $f = $rec->{flow} or return;

    my $pkts_s  = $f->{pkts_toserver}  // 0;
    my $pkts_c  = $f->{pkts_toclient}  // 0;
    my $bytes_s = $f->{bytes_toserver} // 0;
    my $bytes_c = $f->{bytes_toclient} // 0;

    my $duration = 0;
    my $start = _epoch( $f->{start} );
    my $end   = _epoch( $f->{end} );
    $duration = $end - $start if defined $start && defined $end && $end > $start;

    return {
        pkts_toserver    => $pkts_s,
        pkts_toclient    => $pkts_c,
        bytes_toserver   => $bytes_s,
        bytes_toclient   => $bytes_c,
        duration         => $duration,
        proto            => $rec->{proto}     // 'unknown',
        app_proto        => $rec->{app_proto} // 'unknown',
        dest_port        => $rec->{dest_port} // 0,
        bytes_to_packets => ( $bytes_s + $bytes_c + 1 ) / ( $pkts_s + $pkts_c + 1 ),
        up_to_down       => ( $bytes_s + 1 ) / ( $bytes_c + 1 ),
    };
}

sub _extract_http {
    my ( $self, $rec ) = @_;
    my $h = $rec->{http} or return;

    # request rate per src/dst pair over the window
    my $pair = ( $rec->{src_ip} // '?' ) . '|' . ( $rec->{dest_ip} // '?' );
    my $meter = $self->_meter( "http:req:$pair" );
    $meter->mark;

    return {
        length       => $h->{length} // 0,
        status        => $h->{status} // 0,
        http_method   => $h->{http_method} // '',
        url           => $h->{url} // '',                 # -> url_* mungers
        user_agent    => $h->{http_user_agent} // '',     # -> ua_entropy
        src_request_rate => $meter->rate,
    };
}

sub _extract_dns {
    my ( $self, $rec ) = @_;
    my $d = $rec->{dns} or return;

    # per-event set: score DNS queries (and answered queries carrying rcode)
    my $domain = $d->{rrname} // return;

    # NXDOMAIN rate per client. Meter exists per client so rate() is always
    # callable; we only mark it when this event is an NXDOMAIN.
    my $client = $rec->{src_ip} // '?';
    my $meter  = $self->_meter( "dns:nx:$client" );
    my $rcode  = uc( $d->{rcode} // '' );
    $meter->mark if $rcode eq 'NXDOMAIN';

    return {
        domain        => $domain,             # -> entropy + domain_length + label_count
        rrtype        => $d->{rrtype} // '',
        nxdomain_rate => $meter->rate,
        ttl            => $d->{ttl} // 0,
        answer_count   => ref $d->{answers} eq 'ARRAY' ? scalar @{ $d->{answers} } : 0,
    };
}

sub _extract_tls {
    my ( $self, $rec ) = @_;
    my $t = $rec->{tls} or return;

    my $sni     = $t->{sni};
    my $subject = $t->{subject};
    my $issuer  = $t->{issuerdn};

    my $nb = _epoch( $t->{notbefore} );
    my $na = _epoch( $t->{notafter} );
    my ( $validity, $expiry ) = ( 0, 0 );
    if ( defined $nb && defined $na ) {
        $validity = ( $na - $nb ) / 86400;
        $expiry   = ( $na - time() ) / 86400;
    }

    return {
        ja3               => ref $t->{ja3}  eq 'HASH' ? ( $t->{ja3}{hash}  // '' ) : ( $t->{ja3}  // '' ),
        ja3s              => ref $t->{ja3s} eq 'HASH' ? ( $t->{ja3s}{hash} // '' ) : ( $t->{ja3s} // '' ),
        tls_version       => $t->{version} // '',
        sni               => $sni // '',           # -> sni_length + sni_entropy
        subject           => $subject // '',        # -> subject_entropy
        issuer            => $issuer // '',         # -> issuer_entropy
        sni_absent        => ( defined $sni && length $sni ) ? 0 : 1,
        cert_validity_days => $validity,
        days_until_expiry  => $expiry,
        self_signed        => ( defined $subject && defined $issuer && $subject eq $issuer ) ? 1 : 0,
    };
}

# --- helpers -----------------------------------------------------------------

# A per-key Algorithm::EventsPerSecond meter (created on first use).
sub _meter {
    my ( $self, $key ) = @_;
    return $self->{rates}{$key} ||= Algorithm::EventsPerSecond->new(
        window => $self->{rate_window} );
}

sub _warn_once {
    my ( $self, $key, $msg ) = @_;
    return if $self->{warned}{$key}++;
    warn "App::Geshtinanna::Suricata: $msg\n";
    return;
}

# Parse a Suricata EVE timestamp ("2026-07-03T12:00:31.121465+0000") to epoch
# seconds. Fractional seconds are dropped; the timezone offset is honored.
# Returns undef when it does not look like an EVE timestamp.
sub _epoch {
    my ($ts) = @_;
    return undef unless defined $ts && length $ts;
    my ( $y, $mo, $d, $h, $mi, $s ) =
        $ts =~ /^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)/ or return undef;

    my $e = eval { Time::Local::timegm( $s, $mi, $h, $d, $mo - 1, $y ) };
    return undef unless defined $e;

    if ( $ts =~ /([+-])(\d{2}):?(\d{2})$/ ) {
        my $mag = $2 * 3600 + $3 * 60;
        $e += ( $1 eq '+' ) ? -$mag : $mag;
    }
    return $e;
}

=head1 SEE ALSO

L<App::Geshtinanna::Config>,
L<Algorithm::Classifier::IsolationForest::Zorita>,
L<Algorithm::Classifier::IsolationForest::Zorita::Writer>,
L<Algorithm::Classifier::IsolationForest::Zorita::Online>.

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2026 by Zane C. Bowers-Hadley.

This program is released under the following license:

  agpl

=cut

1;
