package App::Geshtinanna::Suricata;

use 5.006;
use strict;
use warnings;
use Carp qw(croak);
use Sys::Hostname qw(hostname);
use Time::Local ();
use JSON::MaybeXS qw(decode_json);
use POE qw(Wheel::FollowTail);
use File::Path ();
use Algorithm::Classifier::IsolationForest::Zorita ();
use Algorithm::Classifier::IsolationForest::Zorita::Writer ();
use Algorithm::Classifier::IsolationForest::Zorita::Online::Client ();

=encoding UTF-8

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
the writer input contract in F<share/set_info_jsons/online/README.md>. Every
shipped set has an extractor; any flow without one logs a one-time warning and
is skipped. New flows are added by writing one C<_extract_$flow> method and
registering it in L</%EXTRACTORS>.

Extractors for the many L2-L7 protocols are necessarily best-effort against
Suricata's per-protocol EVE shape: fields are read defensively (a missing field
degrades to a neutral default rather than dying), and a few features that need
data Suricata does not carry in the event (e.g. a paired flow's byte totals) use
documented placeholders. Field names track current Suricata EVE output.

=cut

# set name -> extractor method name. Adding a flow = add a _extract_$flow
# method and an entry here.
my %EXTRACTORS = (
    flow           => '_extract_flow',
    http           => '_extract_http',
    dns            => '_extract_dns',
    dns_with_time  => '_extract_dns_with_time',
    tls            => '_extract_tls',
    smtp           => '_extract_smtp',
    ssh            => '_extract_ssh',
    ftp            => '_extract_ftp',
    ftp_data       => '_extract_ftp_data',
    files          => '_extract_files',
    dhcp           => '_extract_dhcp',
    arp            => '_extract_arp',
    krb5           => '_extract_krb5',
    smb            => '_extract_smb',
    nfs            => '_extract_nfs',
    dcerpc         => '_extract_dcerpc',
    snmp           => '_extract_snmp',
    sip            => '_extract_sip',
    rdp            => '_extract_rdp',
    rfb            => '_extract_rfb',
    mqtt           => '_extract_mqtt',
    quic           => '_extract_quic',
    ike            => '_extract_ike',
    pgsql          => '_extract_pgsql',
    tftp           => '_extract_tftp',
    modbus         => '_extract_modbus',
    dnp3           => '_extract_dnp3',
    enip           => '_extract_enip',
    'bittorrent-dht' => '_extract_bittorrent_dht',
);

# set name -> EVE event_type, when they differ from the set name. Used only as
# a sanity filter against a mislabelled line (hyphen/underscore differences are
# normalized away in _poe_flow_line, so only genuine remappings belong here).
my %EVENT_TYPE = (
    dns_with_time => 'dns',        # a second, time-aware view of the dns EVE log
    files         => 'fileinfo',   # the 'files' set is fed by EVE 'fileinfo' events
);

=head1 METHODS

=head2 implemented_flows

    my @sets = App::Geshtinanna::Suricata->implemented_flows;

Class method: the sorted list of flow/set names that have an extractor here (and
so can actually be fed into Zorita). Any other configured flow is tailed but its
events are skipped with a one-time warning. Used by C<geshtinanna config> to
decide which flows to enable by default.

=cut

sub implemented_flows {
    my ($class) = @_;
    my @flows = sort keys %EXTRACTORS;
    return @flows;
}

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
    if ( defined $rec->{event_type} ) {
        # Suricata is inconsistent about hyphen vs. underscore between the
        # app-layer name and the EVE event_type (e.g. bittorrent-dht); compare
        # with both normalized so a naming quirk does not drop every line.
        ( my $got = $rec->{event_type} ) =~ tr/-/_/;
        ( my $exp = $want )              =~ tr/-/_/;
        return if $got ne $exp;
    }

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
    return $self->{$key} if $self->{$key};

    # Zorita writes its slug/set tree under basedir but will not create the
    # basedir itself; make it (once) so a first run on a fresh host works.
    if ( defined $self->{basedir} && length $self->{basedir} && !-d $self->{basedir} ) {
        File::Path::make_path( $self->{basedir} );
    }

    return $self->{$key} = Algorithm::Classifier::IsolationForest::Zorita->new(
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

    # HTTP/2 control frames (SETTINGS, WINDOW_UPDATE, ...) are logged as http
    # events carrying only an `http2` frame block and no request line. There is
    # no method / URL / User-Agent to score against the request-shape model, so
    # skip them; a real request (h1 or h2) always has at least a method or URL.
    my $method = $h->{http_method};
    my $url    = $h->{url};
    return unless ( defined $method && length $method )
               || ( defined $url && length $url );

    # request rate per src/dst pair over the window
    my $pair = ( $rec->{src_ip} // '?' ) . '|' . ( $rec->{dest_ip} // '?' );

    return {
        length       => $h->{length} // 0,
        status        => $h->{status} // 0,
        http_method   => $method // '',
        url           => $url // '',                       # -> url_* mungers
        user_agent    => $h->{http_user_agent} // '',     # -> ua_entropy
        src_request_rate => $self->_rate( "http:req:$pair", 1 ),
    };
}

sub _extract_dns {
    my ( $self, $rec ) = @_;
    my $d = $rec->{dns} or return;

    # Suricata's DNS EVE shape changed across versions. Older logs put rrname /
    # rrtype / ttl flat on `dns`; v2/v3 (`dns.version`) nest the asked name
    # under `queries[]` (present on both request and response events) and the
    # returned records under `answers[]`. Read both so a query is scored no
    # matter which format the emitting Suricata uses.
    my $query = ( ref $d->{queries} eq 'ARRAY' && ref $d->{queries}[0] eq 'HASH' )
        ? $d->{queries}[0] : undef;
    my @answers = grep { ref $_ eq 'HASH' }
        ( ref $d->{answers} eq 'ARRAY' ? @{ $d->{answers} } : () );

    my $domain = $d->{rrname}
        // ( $query ? $query->{rrname} : undef )
        // ( @answers ? $answers[0]{rrname} : undef );
    defined $domain && length $domain or return;

    my $rrtype = $d->{rrtype}
        // ( $query ? $query->{rrtype} : undef )
        // ( @answers ? $answers[0]{rrtype} : undef )
        // '';

    # Answer TTL: the smallest across the returned answers (a very low TTL is
    # the suspicious case); a flat `dns.ttl` wins when Suricata supplies one.
    my $ttl = $d->{ttl};
    if ( !defined $ttl ) {
        my @ttls = sort { $a <=> $b } grep { defined } map { $_->{ttl} } @answers;
        $ttl = @ttls ? $ttls[0] : 0;
    }

    # NXDOMAIN rate per client. We read the per-client rate on every query but
    # only mark the meter when this particular event is an NXDOMAIN.
    my $client = $rec->{src_ip} // '?';
    my $rcode  = uc( $d->{rcode} // '' );
    my $nxdomain_rate = $self->_rate( "dns:nx:$client", $rcode eq 'NXDOMAIN' );

    return {
        domain        => $domain,             # -> entropy + domain_length + label_count
        rrtype        => $rrtype,
        nxdomain_rate => $nxdomain_rate,
        ttl           => $ttl,
        answer_count  => scalar @answers,
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

sub _extract_smtp {
    my ( $self, $rec ) = @_;
    my $s = $rec->{smtp} or return;
    my $email = ref $rec->{email} eq 'HASH' ? $rec->{email} : {};

    my $helo      = $s->{helo}      // '';
    my $mail_from = $s->{mail_from} // '';
    my @rcpts     = ref $s->{rcpt_to} eq 'ARRAY' ? @{ $s->{rcpt_to} } : ();

    # Skip a content-free SMTP event (a bare transaction with no HELO, sender,
    # recipients, or extracted email) — nothing for the envelope/header model to
    # score. A HELO-only probe is kept: the HELO string is itself a signal (a
    # spoofed "localhost" or a forged local domain is exactly what we score).
    return unless length $helo || length $mail_from || @rcpts || %$email;

    # distinct recipients per sender over the window (mass-mailing / spam).
    my $sender = length $mail_from ? lc $mail_from : ( $rec->{src_ip} // '?' );
    my $distinct_rcpt_rate =
        $self->_distinct_rate( "smtp:rcpt:$sender", map { lc } @rcpts );

    # header From (email.from) vs envelope MAIL FROM: a spoofing signal. Only
    # meaningful when email metadata was extracted; unknown -> not a mismatch.
    my $hdr_from = $email->{from};
    $hdr_from = $hdr_from->[0] if ref $hdr_from eq 'ARRAY';
    my $from_mismatch =
        ( length $mail_from && defined $hdr_from && length $hdr_from )
        ? ( _addr($hdr_from) ne _addr($mail_from) ? 1 : 0 )
        : 0;

    my @attach = ref $email->{attachment} eq 'ARRAY' ? @{ $email->{attachment} } : ();
    my @urls   = ref $email->{url}        eq 'ARRAY' ? @{ $email->{url} }        : ();

    return {
        helo               => $helo,               # -> helo_length + helo_entropy
        mail_from          => $mail_from,          # -> mail_from_entropy
        subject            => $email->{subject} // '',   # -> subject_entropy
        rcpt_count         => scalar @rcpts,
        distinct_rcpt_rate => $distinct_rcpt_rate,
        from_mismatch      => $from_mismatch,
        attachment_count   => scalar @attach,
        attachment_bytes   => 0,   # EVE carries no per-attachment sizes
        url_count          => scalar @urls,
    };
}

sub _extract_dns_with_time {
    my ( $self, $rec ) = @_;
    my $row = $self->_extract_dns($rec) or return;
    my ( $sin, $cos ) = _time_circle( $rec->{timestamp} );
    $row->{time_sin} = $sin;
    $row->{time_cos} = $cos;
    return $row;
}

sub _extract_ssh {
    my ( $self, $rec ) = @_;
    my $s = $rec->{ssh} or return;
    my $c = ref $s->{client} eq 'HASH' ? $s->{client} : {};
    my $v = ref $s->{server} eq 'HASH' ? $s->{server} : {};
    my $src = $rec->{src_ip} // '?';

    return {
        hassh           => ref $c->{hassh} eq 'HASH' ? ( $c->{hassh}{hash} // '' ) : ( $c->{hassh} // '' ),
        hassh_server    => ref $v->{hassh} eq 'HASH' ? ( $v->{hassh}{hash} // '' ) : ( $v->{hassh} // '' ),
        client_software => $c->{software_version} // '',
        server_software => $v->{software_version} // '',
        # a flow-timeout event may carry only the server banner (client never
        # sent one); fall back to the server's proto so the row still records
        # the SSH version rather than an unknown.
        proto_version   => $c->{proto_version} // $v->{proto_version} // '',
        conn_rate       => $self->_rate( "ssh:conn:$src", 1 ),
    };
}

sub _extract_ftp {
    my ( $self, $rec ) = @_;
    my $f = $rec->{ftp} or return;
    my $src = $rec->{src_ip} // '?';

    my $command = uc( $f->{command} // '' );
    my $code = ref $f->{completion_code} eq 'ARRAY'
        ? ( $f->{completion_code}[0] // '' )
        : ( $f->{completion_code} // '' );

    # USER <name> carries the login; keep it for the username_entropy munger.
    my $username = ( $command eq 'USER' ) ? ( $f->{command_data} // '' ) : '';

    return {
        ftp_command       => $command,
        reply_code        => _num($code) // -1,        # -> ftp_enum (numeric status)
        username          => $username,          # -> username_entropy
        login_fail_rate   => $self->_rate( "ftp:fail:$src", $code eq '530' ),
        command_rate      => $self->_rate( "ftp:cmd:$src", 1 ),
        distinct_commands => $self->_distinct_count( "ftp:dc:$src", $command ),
        passive_mode      => ( $command eq 'PASV' || $command eq 'EPSV' || $f->{dynamic_port} ) ? 1 : 0,
    };
}

sub _extract_ftp_data {
    my ( $self, $rec ) = @_;
    my $d = $rec->{ftp_data} or return;
    my $src = $rec->{src_ip} // '?';

    my $command  = uc( $d->{command} // '' );
    my $filename = $d->{filename} // '';

    return {
        transfer_command       => $command,
        transfer_bytes         => 0,   # paired-flow byte total is not in this event
        direction              => ( $command eq 'STOR' ) ? 1 : 0,
        filename               => $filename,   # -> filename_length + filename_entropy
        files_per_session_rate => $self->_rate( "ftpd:files:$src", 1 ),
    };
}

sub _extract_files {
    my ( $self, $rec ) = @_;
    my $fi = $rec->{fileinfo} or return;
    my $src = $rec->{src_ip} // '?';

    my $filename = $fi->{filename} // '';
    my $ext      = _ext($filename);
    my $magic    = $fi->{magic} // '';
    my $hash     = $fi->{sha256} // $fi->{md5} // $filename;

    return {
        file_size         => $fi->{size} // 0,
        filename          => $filename,     # -> length + entropy + non_ascii
        extension         => $ext,          # -> hash-encoded
        double_extension  => ( $filename =~ /\.[A-Za-z0-9]{1,6}\.[A-Za-z0-9]{1,6}$/ ) ? 1 : 0,
        magic_ext_mismatch => _magic_mismatch( $magic, $ext ),
        truncated         => ( ( $fi->{state} // '' ) ne 'CLOSED' || $fi->{gaps} ) ? 1 : 0,
        direction         => ( ( $fi->{direction} // '' ) =~ /to_?client|inbound/i ) ? 1 : 0,
        hash_first_seen   => $self->_first_seen("files:hash:$hash"),
        hash_prevalence   => $self->_freq( 'files:hash', $hash ),
    };
}

sub _extract_dhcp {
    my ( $self, $rec ) = @_;
    my $d = $rec->{dhcp} or return;

    my $mac    = $d->{client_mac} // '?';
    my $req_ip = $d->{requested_ip} // '';
    my $asn_ip = $d->{assigned_ip} // '';
    my $subnet = _subnet( length $asn_ip ? $asn_ip : ( $d->{client_ip} // '' ) );
    my $is_reply = ( $d->{type} // '' ) eq 'reply';

    return {
        dhcp_type                   => $d->{dhcp_type} // '',
        hostname                    => $d->{hostname} // '',   # -> length + entropy
        vendor_class                => $d->{vendor_class} // $d->{vendor_class_identifier} // '',
        mac_request_rate            => $self->_rate( "dhcp:mac:$mac", 1 ),
        new_mac                     => $self->_first_seen("dhcp:newmac:$mac"),
        requested_assigned_mismatch => ( length $req_ip && length $asn_ip && $req_ip ne $asn_ip ) ? 1 : 0,
        # a lease-time mismatch needs offer<->request correlation across two
        # messages, which we do not track; left neutral.
        lease_mismatch    => 0,
        subnet_server_count => $self->_distinct_count( "dhcp:srv:$subnet", $is_reply ? ( $rec->{src_ip} // '?' ) : () ),
        subnet_mac_count    => $self->_distinct_count( "dhcp:macs:$subnet", $mac ),
    };
}

sub _extract_arp {
    my ( $self, $rec ) = @_;
    my $a = $rec->{arp} or return;

    my $opcode = $a->{opcode} // '';
    my $mac    = $a->{src_mac} // '?';
    my $ip     = $a->{src_ip}  // '?';
    my $is_reply = ( $opcode =~ /reply/i ) ? 1 : 0;

    return {
        arp_opcode       => $opcode,
        reply_rate       => $self->_rate( "arp:reply:$mac", $is_reply ),
        request_rate     => $self->_rate( "arp:req:$mac", !$is_reply ),
        macs_per_ip      => $self->_distinct_count( "arp:mip:$ip",  $mac ),
        ips_per_mac      => $self->_distinct_count( "arp:ipm:$mac", $ip ),
        new_mac_ip       => $self->_first_seen("arp:pair:$mac|$ip"),
        # gratuitous / unsolicited: a reply announcing its own binding
        # (sender IP == target IP) rather than answering a request.
        unsolicited_flag => ( $is_reply && ( $a->{src_ip} // '' ) eq ( $a->{dest_ip} // '' ) ) ? 1 : 0,
    };
}

sub _extract_krb5 {
    my ( $self, $rec ) = @_;
    my $k = $rec->{krb5} or return;
    my $src = $rec->{src_ip} // '?';

    my $msg   = $k->{msg_type} // '';
    my $cname = $k->{cname} // '';
    my $sname = $k->{sname} // '';

    return {
        msg_type            => $msg,
        enc_type            => $k->{encryption} // $k->{ticket_encryption} // '',
        error_code          => $k->{error_code} // '',
        cname               => $cname,   # -> cname_entropy
        sname               => $sname,   # -> sname_entropy
        weak_encryption     => $k->{weak_encryption} ? 1 : 0,
        ticket_request_rate => $self->_rate( "krb5:tgs:$cname", $msg =~ /TGS_REQ/i ),
        fail_rate           => $self->_rate( "krb5:fail:$src", $msg =~ /ERROR/i || defined $k->{error_code} ),
        distinct_snames     => $self->_distinct_count( "krb5:sname:$cname", length $sname ? $sname : () ),
    };
}

sub _extract_smb {
    my ( $self, $rec ) = @_;
    my $s = $rec->{smb} or return;
    my $src = $rec->{src_ip} // '?';

    my $command  = $s->{command} // '';
    my $status   = $s->{status} // '';
    my $share    = $s->{share} // '';
    my $filename = $s->{filename} // '';
    my $ntlm     = ref $s->{ntlmssp} eq 'HASH' ? $s->{ntlmssp} : {};

    return {
        smb_command      => $command,
        dialect          => $s->{dialect} // '',
        named_pipe       => $s->{named_pipe} // '',
        filename         => $filename,               # -> filename_entropy
        ntlm_host        => $ntlm->{host} // '',      # -> ntlm_host_entropy
        status_fail      => ( length $status && $status !~ /SUCCESS/i ) ? 1 : 0,
        admin_share      => ( $share =~ /\$$/ ) ? 1 : 0,
        distinct_shares  => $self->_distinct_count( "smb:share:$src", length $share ? $share : () ),
        distinct_files   => $self->_distinct_count( "smb:file:$src", length $filename ? $filename : () ),
        write_delete_rate => $self->_rate( "smb:wd:$src", $command =~ /WRITE|RENAME|DELETE|SET_INFO/i ),
    };
}

sub _extract_nfs {
    my ( $self, $rec ) = @_;
    my $n = $rec->{nfs} or return;
    my $src = $rec->{src_ip} // '?';

    my $proc     = $n->{procedure} // '';
    my $status   = $n->{status} // '';
    my $filename = $n->{filename} // '';

    return {
        nfs_procedure     => $proc,
        nfs_version       => $n->{version} // 0,
        filename          => $filename,     # -> filename_entropy
        auth_uid          => defined $n->{uid} ? $n->{uid} : ( ref $n->{rpc} eq 'HASH' ? ( $n->{rpc}{creds}{uid} // '' ) : '' ),
        status_fail       => ( length $status && $status ne 'OK' ) ? 1 : 0,
        distinct_files    => $self->_distinct_count( "nfs:file:$src", length $filename ? $filename : () ),
        write_delete_rate => $self->_rate( "nfs:wd:$src", $proc =~ /WRITE|REMOVE|RENAME/i ),
        readdir_rate      => $self->_rate( "nfs:rd:$src", $proc =~ /READDIR/i ),
    };
}

sub _extract_dcerpc {
    my ( $self, $rec ) = @_;
    my $d = $rec->{dcerpc} or return;
    my $src = $rec->{src_ip} // '?';

    my $ifaces = $d->{interfaces};
    my $uuid   = ref $ifaces eq 'ARRAY' && ref $ifaces->[0] eq 'HASH'
        ? ( $ifaces->[0]{uuid} // '' )
        : ( $d->{interface_uuid} // '' );
    my $opnum   = $d->{opnum};
    my $request = $d->{request} // '';
    my $is_bind  = ( $request =~ /BIND/i ) ? 1 : 0;
    my $is_fault = ( ( $d->{response} // '' ) =~ /FAULT/i ) ? 1 : 0;

    return {
        interface_uuid      => $uuid,
        opnum               => defined $opnum ? $opnum : -1,
        request_rate        => $self->_rate( "dcerpc:req:$src", $request =~ /REQUEST/i || defined $opnum ),
        bind_rate           => $self->_rate( "dcerpc:bind:$src", $is_bind ),
        fault_rate          => $self->_rate( "dcerpc:fault:$src", $is_fault ),
        distinct_opnums     => $self->_distinct_count( "dcerpc:op:$src", defined $opnum ? $opnum : () ),
        distinct_interfaces => $self->_distinct_count( "dcerpc:if:$src", length $uuid ? $uuid : () ),
    };
}

sub _extract_snmp {
    my ( $self, $rec ) = @_;
    my $s = $rec->{snmp} or return;
    my $src = $rec->{src_ip} // '?';

    my $pdu  = $s->{pdu_type} // '';
    my @oids = ref $s->{vars} eq 'ARRAY' ? @{ $s->{vars} } : ();

    return {
        snmp_version   => $s->{version} // 0,
        pdu_type       => $pdu,
        community      => $s->{community} // '',   # -> present + entropy
        request_rate   => $self->_rate( "snmp:req:$src", 1 ),
        set_rate       => $self->_rate( "snmp:set:$src", $pdu =~ /set/i ),
        error_rate     => $self->_rate( "snmp:err:$src", $s->{error} ? 1 : 0 ),
        distinct_oids  => $self->_distinct_count( "snmp:oid:$src", @oids ),
    };
}

sub _extract_sip {
    my ( $self, $rec ) = @_;
    my $s = $rec->{sip} or return;
    my $src = $rec->{src_ip} // '?';

    my $method = uc( $s->{method} // '' );
    my $code   = $s->{code} // '';
    my $uri    = $s->{uri} // '';
    my ($uri_user) = $uri =~ m{^sips?:([^@;]+)@};
    $uri_user //= '';

    return {
        sip_method     => $method,
        response_code  => _num($code) // -1,   # -> sip_enum (numeric status)
        uri_user       => $uri_user,   # -> uri_user_length + uri_user_entropy
        user_agent     => $s->{user_agent} // '',
        request_rate   => $self->_rate( "sip:req:$src", length $method ? 1 : 0 ),
        auth_fail_rate => $self->_rate( "sip:authf:$src", $code =~ /^(?:401|403|407)$/ ),
        distinct_uris  => $self->_distinct_count( "sip:uri:$src", length $uri ? $uri : () ),
    };
}

sub _extract_rdp {
    my ( $self, $rec ) = @_;
    my $r = $rec->{rdp} or return;
    my $src = $rec->{src_ip} // '?';
    my $c = ref $r->{client} eq 'HASH' ? $r->{client} : {};

    my $event = $r->{event_type} // '';

    return {
        rdp_event           => $event,
        cookie              => $r->{cookie} // '',            # -> present + entropy
        keyboard_layout     => $c->{keyboard_layout} // '',
        client_build        => $c->{build} // '',
        client_name         => $c->{client_name} // '',       # -> client_name_entropy
        channel_count       => ref $r->{channels} eq 'ARRAY' ? scalar @{ $r->{channels} } : 0,
        conn_rate           => $self->_rate( "rdp:conn:$src", $event eq 'initial_request' ),
        # cannot tell a self-signed RDP cert from the EVE event alone.
        self_signed_cert    => 0,
    };
}

sub _extract_rfb {
    my ( $self, $rec ) = @_;
    my $r = $rec->{rfb} or return;
    my $src = $rec->{src_ip} // '?';

    my $sv   = ref $r->{server_protocol_version} eq 'HASH' ? $r->{server_protocol_version} : {};
    my $ver  = defined $sv->{major} ? "$sv->{major}.$sv->{minor}" : ( $r->{server_protocol_version} // '' );
    my $auth = ref $r->{authentication} eq 'HASH' ? $r->{authentication} : {};
    my $srv  = ref $r->{server} eq 'HASH' ? $r->{server} : {};
    my $area = ( $srv->{width} // 0 ) * ( $srv->{height} // 0 );

    return {
        rfb_version         => $ver,
        security_type       => $auth->{security_type} // 0,
        desktop_name        => $srv->{name} // '',   # -> desktop_name_entropy
        screen_area         => $area,
        shared_flag         => $r->{screen_shared} ? 1 : 0,
        conn_rate           => $self->_rate( "rfb:conn:$src", 1 ),
        # EVE does not flag a failed VNC auth on its own; left as a live meter
        # that never marks rather than a fabricated signal.
        auth_fail_rate      => $self->_rate( "rfb:fail:$src", 0 ),
    };
}

sub _extract_mqtt {
    my ( $self, $rec ) = @_;
    my $q = $rec->{mqtt} or return;

    # the control-packet type is whichever sub-object is present.
    my $mtype = '';
    for my $t (qw(connect connack publish puback pubrec pubrel pubcomp
                  subscribe suback unsubscribe unsuback pingreq pingresp
                  disconnect auth)) {
        if ( ref $q->{$t} eq 'HASH' ) { $mtype = uc $t; last; }
    }

    my $conn    = ref $q->{connect} eq 'HASH' ? $q->{connect} : {};
    my $pub     = ref $q->{publish} eq 'HASH' ? $q->{publish} : {};
    my $sub     = ref $q->{subscribe} eq 'HASH' ? $q->{subscribe} : {};
    my $connack = ref $q->{connack} eq 'HASH' ? $q->{connack} : {};

    # only CONNECT carries a client_id; publishes / pings / acks do not, so key
    # the per-client meters on the client_id when present, else the source IP.
    my $cid    = $conn->{client_id} // '';
    my $client = length $cid ? $cid : ( $rec->{src_ip} // '?' );

    # topic from a PUBLISH, else the first SUBSCRIBE topic.
    my $topic = $pub->{topic};
    if ( !defined $topic && ref $sub->{topics} eq 'ARRAY' && ref $sub->{topics}[0] eq 'HASH' ) {
        $topic = $sub->{topics}[0]{topic};
    }
    $topic //= '';

    my $rc = $connack->{return_code} // $connack->{reason_code};
    my $connack_fail = ( defined $rc && $rc ne '0' && lc "$rc" ne 'success' ) ? 1 : 0;

    return {
        mqtt_type        => $mtype,
        topic            => $topic,     # -> length + depth + entropy
        client_id        => $cid,       # -> client_id_entropy
        payload_size     => length( $pub->{message} // '' ),
        wildcard_sub     => ( $topic =~ /[#+]/ ) ? 1 : 0,
        msg_rate         => $self->_rate( "mqtt:msg:$client", 1 ),
        distinct_topics  => $self->_distinct_count( "mqtt:topic:$client", length $topic ? $topic : () ),
        # newness only applies to an actual client_id (a CONNECT); the many
        # id-less packet types are not "a new client".
        new_client_id    => length $cid ? $self->_first_seen("mqtt:cid:$cid") : 0,
        connack_fails    => $self->_rate( "mqtt:connack:$client", $connack_fail ),
    };
}

sub _extract_quic {
    my ( $self, $rec ) = @_;
    my $u = $rec->{quic} or return;
    my $src = $rec->{src_ip} // '?';

    my $sni = $u->{sni} // '';
    my $ja3 = ref $u->{ja3} eq 'HASH' ? ( $u->{ja3}{hash} // '' ) : ( $u->{ja3} // '' );
    my $ja4 = $u->{ja4} // '';
    my $cyu = ref $u->{cyu} eq 'ARRAY'
        ? ( ref $u->{cyu}[0] eq 'HASH' ? ( $u->{cyu}[0]{hash} // '' ) : ( $u->{cyu}[0] // '' ) )
        : ( $u->{cyu} // '' );

    # Only the QUIC ClientHello carries the client identity this set models —
    # SNI + JA3/JA4/CYU. Bare version packets, version negotiation, and
    # ServerHello (ja3s only) events have none of it, so skip them rather than
    # flood the set with near-empty rows (one connection emits many such events).
    return unless length $sni || length $ja3 || length $ja4 || length $cyu;

    return {
        quic_version   => $u->{version} // '',
        ja4            => length $ja4 ? $ja4 : $ja3,   # prefer JA4, fall back to JA3
        cyu            => $cyu,
        sni            => $sni,           # -> sni_length + sni_entropy
        sni_absent     => length $sni ? 0 : 1,
        dest_fanout    => $self->_distinct_count( "quic:dest:$src", $rec->{dest_ip} // () ),
        # up_to_down / duration / quic_tcp_ratio need the paired flow record,
        # which is not part of a quic EVE event; use neutral placeholders.
        up_to_down     => 1,
        duration       => 0,
        quic_tcp_ratio => 1,
    };
}

sub _extract_ike {
    my ( $self, $rec ) = @_;
    my $i = _obj( $rec, 'ike', 'ikev2' ) or return;
    my $src = $rec->{src_ip} // '?';

    my $enc  = $i->{alg_enc} // '';
    my $dh   = $i->{alg_dh}  // '';
    my $dh_group = _digits($dh);
    my @vids = ref $i->{vendor_ids} eq 'ARRAY' ? @{ $i->{vendor_ids} } : ();
    my $weak = ( $enc =~ /\b(?:DES|3DES|NULL)\b/i || ( $dh_group && $dh_group < 2048 ) ) ? 1 : 0;

    return {
        ike_version     => _num( $i->{version_major} // $i->{version} ) // -1,
        exchange_type   => _num( $i->{exchange_type} ) // -1,
        enc_alg         => $enc,
        dh_group        => $dh_group,
        auth_method     => $i->{alg_auth} // '',
        vendor_id       => $vids[0] // ( $i->{vendor_id} // '' ),
        weak_proposal   => $weak,
        init_rate       => $self->_rate( "ike:init:$src", ( $i->{message_id} // 0 ) == 0 ),
        notify_fail_rate => $self->_rate( "ike:notify:$src", $i->{notify} ? 1 : 0 ),
    };
}

sub _extract_pgsql {
    my ( $self, $rec ) = @_;
    my $p = $rec->{pgsql} or return;
    my $src = $rec->{src_ip} // '?';

    my $req    = ref $p->{request} eq 'HASH' ? $p->{request} : {};
    my $resp   = ref $p->{response} eq 'HASH' ? $p->{response} : {};
    my $params = ref $req->{startup_parameters} eq 'HASH' ? $req->{startup_parameters} : {};
    my $query  = $req->{simple_query} // '';
    my $err    = ref $resp->{error_response} eq 'HASH' ? $resp->{error_response}
               : ( ref $resp->{error} eq 'HASH' ? $resp->{error} : undef );
    my $errcode = $err ? ( $err->{code} // $err->{severity} // 'error' ) : undef;
    my $is_authfail = ( $errcode && $errcode =~ /^28/ ) ? 1 : 0;   # SQLSTATE class 28

    # database is nested in startup_parameters.optional_parameters[] as a
    # {database => ...} entry, not directly under startup_parameters.
    my $database = $params->{database};
    if ( !defined $database && ref $params->{optional_parameters} eq 'ARRAY' ) {
        for my $kv ( @{ $params->{optional_parameters} } ) {
            next unless ref $kv eq 'HASH' && defined $kv->{database};
            $database = $kv->{database};
            last;
        }
    }

    # A coarse message type: many PostgreSQL EVE events carry no literal
    # `.message`, so classify by request shape (Query is the one that matters
    # most for injection detection) rather than leaving it blank.
    my $msg_type =
          length $query                                   ? 'query'
        : defined $req->{message}                         ? $req->{message}
        : ( %$params || defined $req->{protocol_version} ) ? 'startup'
        : $req->{password_redacted}                       ? 'password'
        : defined $resp->{message}                        ? $resp->{message}
        :                                                   '';

    return {
        msg_type        => $msg_type,
        user            => $params->{user} // '',       # -> user_entropy
        database        => $database // '',
        query_length    => length $query,
        query_rate      => $self->_rate( "pgsql:q:$src", length $query ? 1 : 0 ),
        auth_fail_rate  => $self->_rate( "pgsql:authf:$src", $is_authfail ),
        error_rate      => $self->_rate( "pgsql:err:$src", defined $errcode ),
        distinct_errors => $self->_distinct_count( "pgsql:derr:$src", defined $errcode ? $errcode : () ),
    };
}

sub _extract_tftp {
    my ( $self, $rec ) = @_;
    my $t = $rec->{tftp} or return;
    my $src = $rec->{src_ip} // '?';

    my $opcode = $t->{packet} // '';

    return {
        tftp_opcode  => $opcode,
        mode         => $t->{mode} // '',
        filename     => $t->{file} // '',   # -> filename_length + filename_entropy
        write_flag   => ( $opcode =~ /write/i ) ? 1 : 0,
        request_rate => $self->_rate( "tftp:req:$src", 1 ),
        error_rate   => $self->_rate( "tftp:err:$src", $opcode =~ /error/i ),
    };
}

sub _extract_modbus {
    my ( $self, $rec ) = @_;
    my $m = $rec->{modbus} or return;
    my $src = $rec->{src_ip} // '?';

    my $func   = ref $m->{function} eq 'HASH' ? $m->{function} : {};
    my $access = ref $m->{access}   eq 'HASH' ? $m->{access}   : {};
    my $fname  = $func->{name} // '';
    my $fcode  = $func->{code};
    my $unit   = $m->{unit_id} // '';
    my $is_write = ( $fname =~ /write/i
        || ( defined $fcode && grep { $fcode == $_ } 5, 6, 15, 16 ) ) ? 1 : 0;

    return {
        function_code    => _num($fcode) // -1,   # numeric function code
        unit_id          => $unit,
        register_address => $access->{base} // $m->{address} // 0,
        quantity         => $access->{quantity} // $m->{quantity} // 0,
        write_flag       => $is_write,
        command_rate     => $self->_rate( "modbus:cmd:$src", 1 ),
        exception_rate   => $self->_rate( "modbus:exc:$src", ( defined $m->{exception} || ( $m->{reply} // '' ) =~ /exception/i ) ? 1 : 0 ),
        new_master       => $self->_first_seen("modbus:pair:$src|$unit"),
    };
}

sub _extract_dnp3 {
    my ( $self, $rec ) = @_;
    my $d = $rec->{dnp3} or return;
    my $src = $rec->{src_ip} // '?';

    my $app   = ref $d->{application} eq 'HASH' ? $d->{application} : {};
    my $fname = $app->{function} // '';            # name, for flag classification
    my $iin   = ref $d->{iin} eq 'HASH' && ref $d->{iin}{indicators} eq 'ARRAY'
        ? scalar @{ $d->{iin}{indicators} } : 0;
    my $link_src = $d->{src} // '';
    my $link_dst = $d->{dst} // '';

    return {
        function_code => _num( $app->{function_code} ) // -1,   # set expects a number
        dnp3_src      => "$link_src",
        dnp3_dst      => "$link_dst",
        iin_flags     => $iin,
        control_flag  => ( $fname =~ /OPERATE|SELECT/i ) ? 1 : 0,
        restart_flag  => ( $fname =~ /RESTART|DISABLE_UNSOLICITED/i ) ? 1 : 0,
        command_rate  => $self->_rate( "dnp3:cmd:$src", 1 ),
        new_pairing   => $self->_first_seen("dnp3:pair:$link_src|$link_dst"),
    };
}

sub _extract_enip {
    my ( $self, $rec ) = @_;
    my $e = $rec->{enip} or return;
    my $src = $rec->{src_ip} // '?';
    my $dst = $rec->{dest_ip} // '?';

    my $cip     = ref $e->{cip} eq 'HASH' ? $e->{cip} : {};
    my $command = $e->{command} // $e->{enip_command} // '';
    my $service = $cip->{service} // $e->{cip_service} // '';
    my $status  = $cip->{status} // $e->{status};
    my $path    = $cip->{path};
    if ( !defined $path && ( defined $cip->{class} || defined $cip->{instance} ) ) {
        $path = ( $cip->{class} // '' ) . '/' . ( $cip->{instance} // '' );
    }
    $path //= '';

    return {
        enip_command       => _num($command) // -1,   # numeric command
        cip_service        => _num($service) // -1,    # numeric service
        target_path        => "$path",
        write_flag         => ( "$service" =~ /write|set/i ) ? 1 : 0,
        status_fail        => ( defined $status && "$status" !~ /^(?:0|success)$/i ) ? 1 : 0,
        command_rate       => $self->_rate( "enip:cmd:$src", 1 ),
        list_identity_rate => $self->_rate( "enip:li:$src", "$command" =~ /list_?identity/i ),
        new_source         => $self->_first_seen("enip:pair:$src|$dst"),
    };
}

sub _extract_bittorrent_dht {
    my ( $self, $rec ) = @_;
    my $b = _obj( $rec, 'bittorrent_dht', 'bittorrent-dht' ) or return;
    my $src = $rec->{src_ip} // '?';

    my $request   = ref $b->{request} eq 'HASH' ? $b->{request} : {};
    my $response  = ref $b->{response} eq 'HASH' ? $b->{response} : {};
    my $req_type  = $b->{request_type} // '';
    my $node_id   = $request->{id} // $response->{id} // '';
    my $info_hash = $request->{info_hash} // '';

    return {
        request_type         => $req_type,
        client_version       => $b->{client_version} // '',
        node_id              => $node_id,   # -> node_id_entropy
        announce_flag        => ( $req_type =~ /announce/i ) ? 1 : 0,
        request_rate         => $self->_rate( "bt:req:$src", 1 ),
        distinct_peers       => $self->_distinct_count( "bt:peer:$src", $rec->{dest_ip} // () ),
        distinct_info_hashes => $self->_distinct_count( "bt:ih:$src", length $info_hash ? $info_hash : () ),
    };
}

# --- helpers -----------------------------------------------------------------

# A minimal per-key sliding-window events-per-second meter, replacing the
# external Algorithm::EventsPerSecond dependency: record "now" when $do_mark is
# true, prune anything older than rate_window, and return the events per second
# over that window. State lives in $self->{rates}{$key} as an arrayref of epochs.
sub _rate {
    my ( $self, $key, $do_mark ) = @_;
    my $window = $self->{rate_window} || 1;
    my $now    = time();
    my $buf    = $self->{rates}{$key} ||= [];
    push @$buf, $now if $do_mark;
    shift @$buf while @$buf && $buf->[0] <= $now - $window;
    return scalar(@$buf) / $window;
}

# Number of *distinct* values seen for $key within the window (each value's
# timestamp refreshed on every sighting, stale ones pruned). Marking with an
# empty @values just prunes and reports the current distinct count, so a meter
# can be read on every event and only fed on the events that matter.
sub _distinct_count {
    my ( $self, $key, @values ) = @_;
    my $window = $self->{rate_window} || 1;
    my $now    = time();
    my $seen   = $self->{distinct}{$key} ||= {};
    $seen->{$_} = $now for @values;
    delete $seen->{$_} for grep { $seen->{$_} <= $now - $window } keys %$seen;
    return scalar keys %$seen;
}

# _distinct_count expressed as a per-second rate (distinct SMTP recipients, ...).
sub _distinct_rate {
    my ( $self, $key, @values ) = @_;
    return $self->_distinct_count( $key, @values ) / ( $self->{rate_window} || 1 );
}

# 1 the first time $key is ever seen this process, 0 afterwards. Backs the
# various "new_*" / "first_seen" boolean features.
sub _first_seen {
    my ( $self, $key ) = @_;
    return $self->{seen}{$key}++ ? 0 : 1;
}

# Running count of how many times $val has been seen in namespace $ns (the count
# after recording this sighting). Backs frequency-prevalence features that have
# no munger of their own.
sub _freq {
    my ( $self, $ns, $val ) = @_;
    return ++$self->{freq}{$ns}{$val};
}

# Fetch the first EVE sub-object present under one of @keys (protocols whose
# app-layer name and EVE key disagree, e.g. bittorrent_dht / ikev2).
sub _obj {
    my ( $rec, @keys ) = @_;
    for my $key (@keys) {
        return $rec->{$key} if ref $rec->{$key} eq 'HASH';
    }
    return undef;
}

# The /24 (IPv4) or /64-ish prefix of an address, for per-subnet grouping. Falls
# back to the whole address for anything that is not dotted-quad.
sub _subnet {
    my ($ip) = @_;
    return '' unless defined $ip && length $ip;
    return "$1.0/24" if $ip =~ /^(\d+\.\d+\.\d+)\.\d+$/;
    return $ip;
}

# Lower-cased final filename extension (no dot), or '' when there is none.
sub _ext {
    my ($filename) = @_;
    return '' unless defined $filename && $filename =~ /\.([A-Za-z0-9]{1,8})$/;
    return lc $1;
}

# Leading run of digits in a string as a number (MODP_1024 -> 1024), else 0.
sub _digits {
    my ($v) = @_;
    return ( defined $v && $v =~ /(\d+)/ ) ? $1 : 0;
}

# A value as a plain number, or undef when it is absent / not numeric. Several
# prototypes carry an "encoded" categorical (dnp3 function_code, enip command,
# ike version, ...) with NO enum munger, so the set expects it already numeric.
# The Zorita Writer wants every tag present and clean, so callers pair this with
# a numeric "unknown" sentinel (`_num($x) // -1`) rather than passing a bare
# string or undef, both of which the writer rejects.
sub _num {
    my ($v) = @_;
    return ( defined $v && $v =~ /^-?\d+(?:\.\d+)?$/ ) ? $v + 0 : undef;
}

# Best-effort libmagic-type vs. extension disagreement, over a small table of
# common types. Returns 0 (no evidence of mismatch) unless the extension is one
# we know a signature keyword for and that keyword is absent from the magic.
sub _magic_mismatch {
    my ( $magic, $ext ) = @_;
    return 0 unless defined $magic && length $magic && defined $ext && length $ext;
    my %keyword = (
        pdf  => 'PDF',      zip  => 'Zip',     gz   => 'gzip',
        png  => 'PNG',      gif  => 'GIF',     jpg  => 'JPEG',
        jpeg => 'JPEG',     exe  => 'executable', dll => 'executable',
        elf  => 'ELF',      doc  => 'Composite', xls => 'Composite',
    );
    my $want = $keyword{$ext} or return 0;
    return ( index( lc $magic, lc $want ) >= 0 ) ? 0 : 1;
}

# Map an EVE timestamp's time-of-day onto the unit circle (sin, cos over 24h),
# so "3am" is near "3am" regardless of day. (0, 0) for an unparseable stamp.
sub _time_circle {
    my ($ts) = @_;
    my $epoch = _epoch($ts);
    return ( 0, 0 ) unless defined $epoch;
    my $angle = 2 * 3.14159265358979 * ( $epoch % 86400 ) / 86400;
    return ( sin($angle), cos($angle) );
}

# Reduce an address header ('"Name" <foo@bar>', '<foo@bar>', 'foo@bar') to the
# bare, lowercased addr-spec for envelope-vs-header comparison.
sub _addr {
    my ($v) = @_;
    return '' unless defined $v;
    $v = $1 if $v =~ /<([^>]*)>/;
    $v =~ s/^\s+|\s+$//g;
    return lc $v;
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
