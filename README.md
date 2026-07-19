# App-Geshtinanna

Ingests data from Suricata/LibreNMS into online Isolation Forest models for
anomaly detection.

## How the pieces fit together

- **[Algorithm::Classifier::IsolationForest::Online]** is the streaming
  Isolation Forest each set trains. There is no batch `fit()`: events are
  `learn`ed as they arrive and, once the stream exceeds the model's
  `window_size`, the oldest retained event is forgotten for each new one, so
  the model always reflects the most recent window of the stream.
  - A `slug` is a top-level namespace grouping related sets; everything here
    lives under the slug `suricata` (sensor telemetry goes under its own
    `sensor` slug).
  - A `set` is one feature table === one online Isolation Forest model. Each
    set declares an ordered list of columns (its `feature_names`) plus the
    hyper-parameters handed to the forest (`n_trees`, `window_size`,
    `max_leaf_samples`, `contamination`, `missing`, …). Column order is
    significant and is honored by the writer, so the tables below are written
    in the order the columns should be emitted.
  - Each set ships as an **online prototype** JSON under
    `share/set_info_jsons/` (`Geshtinanna_Suricata_<set>.json`); load one with
    `Algorithm::Classifier::IsolationForest->load_prototype($file)` to get a
    fresh, unfitted model with that schema and knobs already stamped in. See
    that directory's README for the file format and conventions.
- `Algorithm::Time::ToNumber` converts a Suricata `.timestamp` into a
  cyclic sin/cos pair. Use `suricata_to_circle_both` for the desired time field:
  it encodes day-of-week and time-of-day as a single position on a
  604800-second (7-day) circle, returning `($sin, $cos)`. Those become the
  `time_sin` / `time_cos` columns wherever a set is time-aware.
- A small internal sliding-window meter in `App::Geshtinanna::Suricata` backs
  every rate / per-second column — no external dependency. State is kept per
  entity under a string key: e.g. 4xx errors for a `src_ip` live under a key
  like `"http:4xx:$src_ip"`, marked on each hit and read as events-per-second
  over the configured `rate_window` (default 60s) — see `_rate`. Distinct-count
  columns (fanout, distinct topics/OIDs/shares, …) use the same window via a
  companion `_distinct_count` meter, and `_first_seen` / `_freq` back the
  "new"/prevalence booleans.

## Design rules (why the columns look the way they do)

These apply to every set below; the per-set notes only call out exceptions.

- **Isolation Forest wants numbers.** Every column is a count, size, duration,
  rate, entropy, ratio, boolean (0/1), or an encoding of a low-cardinality
  category. No raw strings.
- **Never feed raw identifiers.** IPs, MACs, hashes, and full domains are not
  columns. Derive from them instead: fanout (distinct destinations per source),
  first-time-seen booleans, prevalence/frequency, entropy.
- **Encode low-cardinality categoricals.** `proto`, `rrtype`, `http_method`,
  etc. are frequency-encoded (or bucketed) so a rare value scores as unusual on
  its own axis.
- **Log-transform heavy tails.** Bytes, durations, and counts are extremely
  skewed; a forest splits them poorly raw. Anything marked "log" below is
  `log`-transformed (`log(v+1)`) before it is learned.
- **One event type per set.** Feature spaces differ too much between DNS and
  TLS to share a model — a combined model just dilutes signal. Hence a set (and
  a forest) per event type, and sometimes more than one per event type.
- **Two altitudes.** Per-event sets catch loud single events; a planned
  host-level set aggregated per `(src_ip, window)` catches slow / distributed
  behavior that no single event reveals. See [Host-level model](#host-level-model-planned).
- **Missing cells learn as zero.** The online model's `missing` policy is only
  `die` or `zero` (it has no batch `nan` / `impute`), so every set uses `zero`:
  an absent cell is learned as `0.0`. Where a real `0` would be misleading —
  the sparse cert / fingerprint / extended-logging columns the per-set caveats
  call out — prefer a munger sentinel (an `enum` `default: -1`) over leaning on
  the missing policy. The caveats below say "ride `missing => zero`" for the
  columns where a zero is harmless enough.

## LibreNMS

Each set represents a host.

## Suricata

Reads a flows dir, e.g. `/var/log/suricata/flows/current/`, where each EVE flow
type is its own log. Sets are added under the slug `suricata`.

`netflow` is intentionally not given its own set: it is the unidirectional
counterpart to `flow` with the same fields, so it is handled by the `flow` set's
logic. All columns below obey the [design
rules](#design-rules-why-the-columns-look-the-way-they-do) — numeric / encoded /
entropy / rate columns only.

### flow

One set. Per-flow volume, shape, and timing — the workhorse for anomaly
detection because nearly every field is already numeric.

set **flow**

| column | description |
|-|-|
| flow.pkts_toserver | raw packet count client→server |
| flow.pkts_toclient | raw packet count server→client |
| flow.bytes_toserver | raw byte count client→server |
| flow.bytes_toclient | raw byte count server→client |
| duration | seconds, derived from `flow.end` - `flow.start` |
| proto | encoded transport proto (tcp/udp/icmp/…) |
| app_proto | encoded application proto (http/tls/dns/…) |
| dest_port | encoded: well-known vs. registered vs. ephemeral |
| bytes_to_packets | avg packet size, `(bytes+1)/(packets+1)` |
| up_to_down | upload/download ratio, `(bytes_toserver+1)/(bytes_toclient+1)` |

**Why:**

The four raw volume counters — `flow.pkts_toserver`, `flow.pkts_toclient`,
`flow.bytes_toserver`, `flow.bytes_toclient` — are the base signal: how much was
sent in each direction. On their own a tree can only split "big vs. small," but
paired with duration and the two ratios they describe the *shape* of the
conversation, which is what separates a file download from a beacon from a scan.

`duration` (from `flow.end` − `flow.start`) is what lets the forest see a flow
held open far longer than its byte count justifies. A three-bytes-per-second
connection kept alive for an hour is a classic C2 keep-alive; the same three
bytes as a one-shot is nothing. Without duration those two look identical.

`proto` and `app_proto` are encoded because a tree can't read "tls", but *rare
combinations* of transport, application protocol, and port are exactly where
tunneling and evasion hide — DNS on a non-53 port, TLS on 8080, an
`app_proto` that failed to parse on 443. Encoding turns the categorical into a
rarity axis the forest can split on. `dest_port` is deliberately bucketed into
well-known / registered / ephemeral rather than fed raw: the literal number is
meaningless to a threshold split (443 is not "less than" 444 in any useful
sense), but "a server answering on an ephemeral port" or "a client reaching a
high random port" is a real anomaly the class captures.

`bytes_to_packets` is mean packet size, and it cheaply proxies the *kind* of
conversation: bulk transfers ride full-MTU packets, interactive shells and
beacons dribble tiny ones, and some tunnels emit suspiciously uniform sizes.
`up_to_down` is the exfiltration axis — browsing and downloads pull far more
than they push (ratio ≪ 1), so a host pushing more than it pulls (ratio ≫ 1)
is the staging/exfil pattern. Both ratios add 1 to numerator and denominator so
one-way and failed flows — scans, RSTs, unanswered UDP where `bytes_toclient` or
`packets` is 0 — stay finite instead of dividing by zero or going infinite.

**Candidates to add:** `flow.state` / `flow.reason` (encoded — new vs.
established, timeout vs. shutdown), `tcp.tcp_flags` and the syn/ack/rst/fin
booleans (flag combinations catch scans), and packets-per-second via
the internal rate meter. Held back for now to keep the first set small.

### dns

Two sets that share the same content features and differ only in whether time
is included. Train both and ablate: per-event DNS gets most of its power from
entropy / NXDOMAIN / rrtype, so the time-aware variant is there to test whether
diurnal context (a novel-domain burst at 3AM) adds anything on this network.

Set `dns_with_time`...

| column | description |
|-|-|
| time_sin | `suricata_to_circle_both` sin of `.timestamp` |
| time_cos | `suricata_to_circle_both` cos of `.timestamp` |
| domain | Shannon entropy of the queried domain (DGA detection) |
| domain_length | length of the queried name |
| label_count | number of labels (dots + 1) in the query |
| rrtype | encoded rrtype (TXT/NULL/ANY are rare and interesting) |
| nxdomain_rate | NXDOMAIN (rcode) rate per client over the window |
| ttl | TTL of the response (very low TTL is suspicious) |
| answer_count | number of answers returned |

Set `dns`...

| column | description |
|-|-|
| domain | Shannon entropy of the queried domain (DGA detection) |
| domain_length | length of the queried name |
| label_count | number of labels (dots + 1) in the query |
| rrtype | encoded rrtype (TXT/NULL/ANY are rare and interesting) |
| nxdomain_rate | NXDOMAIN (rcode) rate per client over the window |
| ttl | TTL of the response (very low TTL is suspicious) |
| answer_count | number of answers returned |

**Why:**

`domain` is the single strongest per-event DNS feature. It is the Shannon
entropy of the queried name, and it works because both DGA malware and
DNS-tunneling generate names that don't look like human language — a
hand-registered `google` has low per-character entropy, `x7f3q9zk2v` has high.
`domain_length` and `label_count` corroborate it cheaply and independently:
tunneling stuffs payload into the query, so the name grows long and gains labels
(`data.chunk1.chunk2.evil.com`). The three together separate a legitimate long
CDN hostname (long, but low-entropy and few labels) from an actual tunnel — no
single one does that alone.

`rrtype` is encoded because normal traffic is overwhelmingly A / AAAA / PTR /
HTTPS, while TXT, NULL, and ANY are the record types tunneling and exfil tools
reach for precisely because they carry arbitrary data. Encoding makes those rare
types score high on their own axis instead of being lost in the A-record noise.

`nxdomain_rate` is stored as a rate per client per window rather than a
per-event code because the signal is behavioral, not momentary. One NXDOMAIN is
a typo; a client emitting a steady stream of them is either walking a DGA's
candidate-domain list hunting for the one that resolves, or running a beacon
against dead infrastructure. The rate turns "this client's relationship with
resolution failure over time" into a number a forest can rank.

`ttl` matters because attacker infrastructure runs very low TTLs so it can
fast-flux — rotate IPs faster than blocklists can keep up — so an unusually low
TTL is a proxy for disposable hosting. `answer_count` catches the same family
from another angle: fast-flux and manipulated responses return abnormally many
(or, on a NOERROR, zero) records.

On the `dns_with_time` variant, `time_sin` / `time_cos` encode the timestamp as
a position on the weekly circle (via `suricata_to_circle_both`) so the forest
can learn a host's normal diurnal rhythm and flag the 3AM novel-domain burst
that beaconing produces regardless of office hours. It lives in a *separate* set
because, per-event, time is only a marginal add on top of the content
features — the ablation the set intro calls for is exactly to measure whether it
earns its place here or only in the host-level model.

**Candidate to add:** ratio of distinct subdomains per registered domain (DNS
tunneling), likely as a per-window derived feature rather than per-event.

### http

One set. HTTP request/response shape.

Set `http`.

| column | description |
|-|-|
| length | body size (log-transformed) |
| status | encoded / bucketed 2xx·3xx·4xx·5xx |
| http_method | encoded method (rare methods PUT/DELETE/TRACE stand out) |
| url_length | length of the request URI |
| url_path_depth | path depth (count of `/` segments) |
| url_non_alnum | fraction of non-alphanumeric characters in the URI |
| ua_entropy | Shannon entropy of the User-Agent string |
| src_request_rate | request rate per src/dst pair over the window |

**Why:**

The URL triplet — `url_length`, `url_path_depth`, `url_non_alnum` — is the
injection detector. Exploit payloads (SQLi, path traversal, encoded shellcode,
template injection) are long and dense with punctuation and percent-encoding.
`url_length` catches the raw bloat, `url_path_depth` catches traversal
(`../../../`) and unusually deep paths, and `url_non_alnum` — deliberately a
*fraction* of non-alphanumeric characters, not a count, so it stays independent
of length — catches the encoding/punctuation density (`%`, `'`, `<`, `;`) that
plain content lacks. The fraction is what separates a long-but-benign signed CDN
link (mostly alphanumeric) from a compact injection string (mostly not).

`http_method` is encoded because the web is ~99% GET and POST; PUT, DELETE,
TRACE, PATCH, CONNECT, and the WebDAV verbs are rare and disproportionately tied
to misconfiguration abuse, webshell upload, and proxy abuse, so encoding lifts
them onto their own axis. `status` is bucketed into 2xx / 3xx / 4xx / 5xx to keep
cardinality low while preserving the error signal: a client generating a burst
of 4xx is fuzzing or enumerating, and a server suddenly emitting 5xx is being
broken by malformed input. `length` (response/body size, log-transformed because
it spans many orders of magnitude) catches exfil over POST and oversized
webshell responses.

`ua_entropy` works because real browsers and apps send stable, low-entropy,
heavily-repeated User-Agent strings, whereas malware and scanners either omit
the UA, forge a rare one, or emit something random and garbled (high entropy).
Entropy is a cheap proxy for "not a normal client string." `src_request_rate` is
the beaconing axis: C2 checks in on a timer, producing a steady, low-variance
cadence to one destination that looks nothing like bursty human browsing. It is
computed per src/dst pair per window so the rate reflects a single conversation
rather than the host's total traffic.

**Candidates to add:** `http_content_type` vs. file-extension mismatch boolean,
UA length, and frequency-encoding of the UA string (rare UAs).

### tls

One set. Handshake fingerprint, SNI shape, and certificate hygiene. Almost none
of TLS is human-readable to a tree, so every column is either an encoded
fingerprint, an entropy, a length, a duration, or a boolean.

set **tls**

| column | description |
|-|-|
| ja3 | frequency-encoded JA3 client fingerprint (rare = interesting) |
| ja3s | frequency-encoded JA3S server fingerprint |
| tls_version | encoded version (SSLv3 / 1.0 / 1.1 are anomalous) |
| sni_length | length of the SNI, 0 when absent |
| sni_entropy | Shannon entropy of the SNI (randomized / DGA SNIs) |
| sni_absent | boolean: 1 when no SNI (raw-IP TLS / evasion) |
| cert_validity_days | `notAfter` − `notBefore`, in days |
| days_until_expiry | days from observation to `notAfter` (≤0 = expired) |
| self_signed | boolean: issuer == subject |
| subject_entropy | Shannon entropy of the certificate subject string |
| issuer_entropy | Shannon entropy of the certificate issuer string |

**Why:**

`ja3` hashes the client's ClientHello — its cipher suites, extensions, and
curves — into a fingerprint of the TLS *implementation*, and `ja3s` does the
same for the server's chosen response. Because the fingerprint reflects the TLS
library and its configuration rather than the destination, malware built on a
custom or unusual stack carries a rare JA3 even when it is talking to a
legitimate-looking host with a clean SNI and a valid cert. Both are
frequency-encoded so commonness is the score: the handful of fingerprints every
mainstream browser and OS produces dominate the baseline, and anything rare
rises on its own. `tls_version` sits alongside them because modern clients
negotiate 1.2/1.3 — seeing SSLv3/1.0/1.1 means either ancient software or a
deliberate downgrade to reach a weak-crypto flaw.

The SNI trio attacks the destination name. `sni_entropy` and `sni_length` catch
randomized or DGA-style SNIs exactly as the DNS `domain` features do — malware
that generates its rendezvous names produces high-entropy SNIs. `sni_absent` is
kept as its own boolean rather than folded into length because it is a distinct
signal: a browser *always* sends SNI, so TLS to a raw IP with none is unusual —
routine for some internal infrastructure and health checks, but a recurring
tell for C2 that skips naming its endpoint.

The five certificate columns together describe the throwaway-cert profile.
Operators spin up disposable certs, and those cluster on measurable traits:
`cert_validity_days` is short (auto-issued certs often live ≤90 days, abuse certs
shorter), `days_until_expiry` at or below zero means an expired cert is being
reused, `self_signed` skips a CA altogether, and `subject_entropy` /
`issuer_entropy` run high because the identity fields are auto-generated gibberish
rather than a real organization name. No single one is damning — plenty of
legitimate internal services are self-signed — so the forest keys on them
*co-occurring*, which is what a throwaway cert actually looks like.

> **Missing-cert caveat:** resumed sessions and handshakes where Suricata never
> logs a certificate leave all five cert columns empty. Under the online
> `missing => zero` policy an empty cell learns as `0`, which fakes a "zero-day
> validity, self-signed" cert on every resumption — so give these columns
> munger sentinels the forest can tell apart from a real cert (e.g. a negative
> `cert_validity_days` / `days_until_expiry` fill and `self_signed` left
> unset-as-0 only where 0 genuinely means "not self-signed") rather than
> relying on the missing policy to stay neutral.

**Candidates to add:** JA4/JA4S (newer, GREASE-robust fingerprints — same
frequency-encoding), SAN count, certificate-chain length, and a
`notBefore`-in-the-future boolean.

### ssh

One set. SSH is banner-and-fingerprint plus volume — Suricata stops inspecting
after the key exchange and never logs auth results, so per-event signal is the
handshake, and brute-force signal is the connection rate.

set **ssh**

| column | description |
|-|-|
| hassh | frequency-encoded client HASSH fingerprint (rare = interesting) |
| hassh_server | frequency-encoded server HASSH fingerprint |
| client_software | frequency-encoded client `software_version` banner |
| server_software | frequency-encoded server `software_version` banner |
| proto_version | encoded protocol version (2.0 normal; 1.x is anomalous) |
| conn_rate | SSH connections per source IP over the window (brute-force = volume) |

**Why:**

`hassh` and `hassh_server` are the SSH analog of JA3: HASSH hashes the
algorithms a client (and server) offer during key exchange — the kex, cipher,
MAC, and compression lists — into a fingerprint of the SSH *implementation*.
Automation and attack tooling each offer a distinctive algorithm set, so
paramiko, libssh, Go's `x/crypto/ssh`, Metasploit, and custom scanners carry a
HASSH that stands apart from the OpenSSH fingerprints dominating a normal
network, even when the login itself is routine. Both are frequency-encoded so
rarity is the score.

`client_software` and `server_software` are the version banner (`OpenSSH_8.9`
and so on) — a second, coarser fingerprint of the same implementation, since
tooling and old or unusual builds announce themselves there. They are kept
alongside HASSH deliberately: a banner is trivial to forge while HASSH is much
harder to spoof, so the two can disagree, and a rare HASSH under a
normal-looking banner (or vice versa) is itself a signal. `proto_version` is
encoded because everything modern speaks SSH 2.0; SSH 1.x is long-broken and
effectively only appears from ancient gear or deliberate downgrade probing.

`conn_rate` carries the attack that the per-event fields cannot see. Suricata
stops inspecting after the key exchange and never records whether authentication
succeeded, so brute-force and credential-stuffing leave no per-event trace — the
only tell is volume. A source opening many SSH connections per window is the
credential-attack signature, so `conn_rate` (per source, via the internal
rate meter) is the axis that captures it.

> **HASSH-disabled caveat:** HASSH requires `hassh: enabled` in `suricata.yaml`.
> With it off, `hassh` / `hassh_server` are always empty. Under `missing =>
> zero` they collapse to a single constant (0) the whole time, so the model
> effectively degrades to banner + rate features — acceptable while these
> columns are placeholder `hash` mungers, but decide the empty-fingerprint fill
> deliberately once they move to `frozen_freq_map`.

**Candidates to add:** client `software_version` length/entropy (randomized
banners), distinct servers contacted per source (spread / scanning), and
offered kex/cipher/MAC algorithm counts.

### files / fileinfo

One set. `fileinfo` fires per file carried over HTTP/SMTP/FTP/NFS/SMB, and it is
one of the most productive event types because so much of it is already
numeric — size, and a pile of name/type/transfer features.

set **files**

| column | description |
|-|-|
| file_size | `fileinfo.size` in bytes, log-transformed |
| filename_length | length of the filename |
| filename_entropy | Shannon entropy of the filename |
| filename_non_ascii | count of non-ASCII characters in the filename |
| extension | frequency-encoded file extension |
| double_extension | boolean: two extensions (`invoice.pdf.exe`) |
| magic_ext_mismatch | boolean: `fileinfo.magic` type disagrees with the extension |
| truncated | boolean: `state` != CLOSED or gaps present (incomplete transfer) |
| direction | boolean: 1 = inbound to the monitored net, 0 = outbound |
| hash_first_seen | boolean: first time this file hash is seen in the environment |
| hash_prevalence | frequency-encoded hash prevalence across the environment (rare = interesting) |

**Why:**

The masquerade axis is the headline. `magic_ext_mismatch` compares what the file
*is* (libmagic's read of the actual bytes) against what it *claims to be* (the
extension), so an executable dressed as a `.jpg` or a script wearing `.pdf`
lights up — a disagreement `file_size` alone can never see. `double_extension`
catches the companion trick, the `invoice.pdf.exe` that relies on a UI hiding the
final extension. Together they are the strongest single indicator here because
legitimate files almost never trip either.

The name-shape columns describe *how the file is named*, which betrays tooling.
Malware droppers and staging tools generate names algorithmically, so
`filename_entropy` (randomness of the characters), `filename_length` (generated
names run long), and `filename_non_ascii` (homoglyph and padding tricks) all
rise together on machine-made names and stay low on human-chosen ones.
`file_size` is log-transformed because file sizes span bytes to gigabytes, and
the extreme skew would otherwise dominate every split. `extension` is
frequency-encoded so rare or dangerous extensions score on their own axis rather
than being lost among the `.jpg`/`.docx` bulk.

`truncated` flags transfers that ended incomplete — `state != CLOSED` or gaps in
the reassembled stream — which often accompanies a killed download or an evasion
attempt that splits a payload to defeat inspection. `direction` supplies risk
context the raw file features lack: an inbound executable arriving over HTTP is a
delivery event, the same file leaving is potential exfil, and the forest should
treat those asymmetrically.

The two hash columns exist so the file's *novelty* becomes a feature without ever
feeding the hash itself (a hash is a high-cardinality identifier, forbidden by
the design rules). `hash_first_seen` catches the never-before-observed dropper —
the thing no signature knows yet — and `hash_prevalence` scores rare binaries as
unusual while ubiquitous ones (OS updates, shared libraries) settle into the
baseline. A rare-or-brand-new binary is exactly the file worth a second look.

> **Derived-state caveat:** `hash_first_seen` and `hash_prevalence` are not in
> any single EVE record — they require a running store of hashes seen across the
> environment (the same way the rate columns require the internal rate meter's
> state). And both depend on file hashing being enabled in `suricata.yaml`
> (`filestore` / md5 / sha256); with hashing off they are always empty and
> should ride the set's `missing => zero` policy.

**Candidates to add:** `app_proto` encoded (which protocol carried the file),
files-per-host-per-window, same-hash-to-many-destinations (staging / exfil), and
the `fileinfo.stored` boolean.

### dhcp

One set. DHCP is chatty, repetitive, and mostly benign, so — unlike the
protocols above — almost none of the signal is in a single record's field
*contents*. It is in rarity and volume: who is new, who is flooding, and who is
answering that shouldn't be. Most columns here are therefore aggregate / stateful.

set **dhcp**

| column | description |
|-|-|
| dhcp_type | encoded message type (discover/offer/request/ack/nak/decline/inform/release) |
| mac_request_rate | DHCP messages per client MAC over the window (starvation / exhaustion) |
| new_mac | boolean: first time this client MAC is seen |
| hostname_length | length of `dhcp.hostname` |
| hostname_entropy | Shannon entropy of `dhcp.hostname` (randomized tooling names) |
| requested_assigned_mismatch | boolean: `requested_ip` != `assigned_ip` |
| lease_mismatch | boolean: requested lease time != offered lease time |
| vendor_class | frequency-encoded vendor class identifier (option 60) |
| subnet_server_count | distinct DHCP servers answering in this subnet over the window |
| subnet_mac_count | distinct client MACs in this subnet over the window (spoofing floods) |

**Why:**

`dhcp_type` is encoded to catch abnormal *message mixes*. A healthy network is
almost all DISCOVER→OFFER→REQUEST→ACK (DORA); a rash of NAKs, DECLINEs, INFORMs,
or half-finished handshakes is what starvation, misconfiguration, and address
conflicts look like, and encoding lets the forest treat those rare types as
off-baseline.

`mac_request_rate` and `subnet_mac_count` are the two exhaustion axes, viewed
from different keys. DHCP starvation drains a scope by requesting leases under
many spoofed MAC addresses, so a single attacking host drives `mac_request_rate`
up (lots of messages per MAC as it hammers) while the subnet as a whole shows
`subnet_mac_count` spiking (far more distinct MACs than there are real devices).
Watching both catches the attack whether it comes from one loud MAC or a spray
of quiet ones. `new_mac` is the novelty companion — a first-ever MAC on the
segment is how a rogue device or a spoofing tool announces itself.

`subnet_server_count` is the highest-value column in the set: it counts distinct
DHCP servers answering on a subnet, and anything above one is almost always a
rogue server — an attacker handing out a malicious gateway or DNS to man-in-the-
middle the whole segment. `hostname_length` and `hostname_entropy` catch the
randomized hostnames that tooling and malware supply instead of a real device
name, and `vendor_class` (option 60) is frequency-encoded so an unusual client
implementation stands out. The two mismatch booleans —
`requested_assigned_mismatch` and `lease_mismatch` — flag clients that don't
behave like the offer they were given, which is a marker of a hand-rolled or
misbehaving DHCP client rather than a normal OS stack.

> **Derived-state + extended-logging caveat:** `mac_request_rate`, `new_mac`,
> `subnet_server_count`, and `subnet_mac_count` are not in any single EVE record —
> they need the pipeline's per-MAC / per-subnet state (rates via the internal
> rate meter, "seen" sets for the rest). And `hostname`,
> `requested_ip`, lease time, and vendor class only appear when DHCP extended
> logging is on (`dhcp: extended: yes` in `suricata.yaml`); without it those
> columns are empty and ride the set's `missing => zero` policy.

> **Rule-vs-model note:** the crispest DHCP wins — a new server IP answering a
> subnet, a rogue server — are better handled as a simple alerting rule than
> left to an anomaly score. This set exists to fold the volume / entropy
> features into a host-level picture, not to replace that rule.

**Candidates to add:** the option-55 parameter-request-list frequency-encoded
(fingerprints the client OS / tooling), distinct `requested_ip` per MAC, and
release / decline rate per client.

### mqtt

One set. IoT traffic is metronomic — a device does the same handful of things
forever — so here the *variance itself* is the feature and per-device baselining
matters more than anywhere else.

set **mqtt**

| column | description |
|-|-|
| mqtt_type | encoded control-packet type (CONNECT/PUBLISH/SUBSCRIBE/…) |
| msg_rate | MQTT messages per client over the window |
| payload_size | PUBLISH payload size, log-transformed |
| topic_length | length of the topic string |
| topic_depth | topic hierarchy depth (count of `/` levels) |
| topic_entropy | Shannon entropy of the topic |
| wildcard_sub | boolean: subscription topic contains `#` or `+` |
| distinct_topics | distinct topics per client over the window (enumeration) |
| client_id_entropy | Shannon entropy of `connect.client_id` |
| new_client_id | boolean: first time this `client_id` is seen |
| connack_fails | CONNACK reason codes != 0 per client over the window (auth failures) |

**Why:**

`mqtt_type` is the behavioral-change detector. An IoT device has a fixed role —
a sensor only ever PUBLISHes, an actuator only SUBSCRIBEs — so the *mix* of
control-packet types per client is nearly constant. A device that has published
temperature readings for months suddenly issuing SUBSCRIBE is not doing its job;
it has been taken over and is now reconnoitering the broker. `wildcard_sub` is
the sharpest version of that: subscribing to `#` or `+` asks the broker for
*every* topic, which is exactly what an attacker does to map the bus and what a
normal device never does.

`msg_rate` and `payload_size` catch drift off the tiny-and-constant norm. IoT
payloads are small and regular, so the *variance itself* is the feature — a
device whose message rate climbs or whose payloads balloon (log-transformed,
since a data-exfil PUBLISH dwarfs a sensor reading) has changed behavior even if
each individual message is well-formed. The topic columns describe the
*addressing*: `topic_length`, `topic_depth`, and `topic_entropy` flag randomized
or unusually deep topic strings (tooling and dynamic C2 topics look nothing like
a hand-designed `home/livingroom/temp` hierarchy), and `distinct_topics` per
client catches enumeration — a client touching far more topics than its role
needs.

`client_id_entropy` and `new_client_id` cover identity: brokers key clients by
`client_id`, so a high-entropy (generated) id or a never-before-seen one is how a
spoofed or rotating client shows up. `connack_fails` counts non-zero CONNACK
reason codes per client, which is the brute-force and misconfiguration axis — a
client failing to connect repeatedly is either guessing credentials or a broken
integration, and either is worth surfacing.

> **Per-device-baseline note:** a camera and a thermostat have completely
> different "normal," so one global forest washes the signal out. Prefer one set
> per device class (or heavy per-client aggregation) over a single MQTT model.

> **Sparse-by-packet-type caveat:** each control packet populates only its own
> columns — topic fields exist only on PUBLISH/SUBSCRIBE, `client_id` only on
> CONNECT — so any single event leaves the rest empty. `mqtt_type` says which
> columns are meaningful for a row; the others ride `missing => zero`. As with
> the other sets, `msg_rate` / `distinct_topics` / `new_client_id` /
> `connack_fails` come from per-client pipeline state, not one record.

**Candidates to add:** CONNECT rate per client (reconnect storms), QoS-level
distribution shift, retain-flag usage rate, and protocol version encoded.

### quic

One set. QUIC's payload is encrypted, so the packet-level columns are just the
handshake; the exfil / C2 signal is flow-level, joined from the paired `flow`
record on `flow_id`.

set **quic**

| column | description |
|-|-|
| quic_version | encoded QUIC version (rare / forced-downgrade) |
| ja4 | frequency-encoded JA4/JA3 QUIC fingerprint (rare = interesting) |
| cyu | frequency-encoded CYU (Chrome QUIC) fingerprint |
| sni_length | length of the SNI, 0 when absent |
| sni_entropy | Shannon entropy of the SNI |
| sni_absent | boolean: 1 when no SNI (ECH / evasion) |
| up_to_down | upload/download byte ratio from the paired flow, `(toserver+1)/(toclient+1)` |
| duration | connection duration from the paired flow, seconds |
| dest_fanout | distinct QUIC destinations per source over the window |
| quic_tcp_ratio | QUIC vs. TLS-over-TCP byte ratio per host over the window |

**Why:**

The crypto columns mirror the `tls` set, because a QUIC handshake carries the
same TLS material. `quic_version` is encoded so rare or forced-downgrade
versions stand out. `ja4` and `cyu` fingerprint the client stack — JA4 is the
modern TLS/QUIC fingerprint, CYU is the Chrome-QUIC-specific one — so non-browser
tooling and custom C2 clients carry a rare value even when the destination looks
ordinary; both are frequency-encoded so commonness is the score. The SNI trio
works exactly as in `tls`: `sni_entropy` and `sni_length` catch randomized names,
and `sni_absent` catches a connection that names no endpoint at all (ECH or
deliberate evasion), which a real browser session never does.

Everything else is joined from the paired `flow` record, because QUIC's payload
is encrypted and the packet-level view ends at the handshake — the actual
behavior lives in the volumes and timing. `up_to_down` and `duration` together
are the tunneling signature: a QUIC connection to 443 that stays open a long time
while pushing far more than it pulls is what an exfil channel or a C2 tunnel
looks like, and neither column alone says that — it's the *combination* the
forest keys on. `up_to_down` reuses the flow set's `(x+1)/(y+1)` zero-guard so
one-way connections stay finite. `dest_fanout` (distinct QUIC destinations per
source) catches scanning and spread, and `quic_tcp_ratio` catches a host
abruptly shifting its traffic from TLS-over-TCP to QUIC — attractive to C2
precisely because middleboxes can't inspect QUIC, so a sudden QUIC-heavy profile
is a deliberate evasion tell.

> **Flow-join caveat:** `up_to_down`, `duration`, and the ratio/fanout columns
> are not in the `quic` event — the pipeline must correlate to the paired `flow`
> record (and hold per-source/per-host state) to build them. Rows where the flow
> record isn't yet available ride `missing => zero`.

**Candidates to add:** the highest-value QUIC adds are beacon features —
inter-arrival-time variance and byte-size consistency across connections to the
same destination — plus a long-lived-connection count per host.

### smtp

One set. Envelope and header shape; the attachments themselves arrive as
`fileinfo` and are scored by the `files` set, so this set is about who is being
mailed, how, and how much — not file content.

set **smtp**

| column | description |
|-|-|
| helo_length | length of the HELO/EHLO string |
| helo_entropy | Shannon entropy of the HELO string (randomized botnet HELOs) |
| rcpt_count | number of RCPT TO recipients on the message |
| distinct_rcpt_rate | distinct recipients per sender over the window (blast / spam) |
| mail_from_entropy | Shannon entropy of the MAIL FROM localpart |
| from_mismatch | boolean: envelope MAIL FROM != header `From` (spoofing) |
| subject_entropy | Shannon entropy of the subject |
| attachment_count | number of attachments on the message |
| attachment_bytes | total attachment size, log-transformed |
| url_count | count of URLs in the body (phishing) |

**Why:**

Spam and blast campaigns are a volume story. `rcpt_count` catches the single
message addressed to a large recipient list, and `distinct_rcpt_rate` catches
the slower version — one sender fanning out to many distinct recipients over the
window — which a normal user's mail never does. Together they separate a person
sending a few targeted emails from a compromised host or open relay pumping out
a campaign.

Phishing and spoofing are a header-and-body story. `from_mismatch` is the
strongest of these: when the envelope MAIL FROM disagrees with the header
`From`, someone is forging the visible sender, which is the mechanical basis of
most phishing and BEC. `url_count` catches the payload delivery vector —
phishing bodies are dense with links — and `helo_entropy` / `helo_length` catch
the randomized HELO strings that botnet MTAs generate instead of a real
hostname. `subject_entropy` and `mail_from_entropy` round this out by flagging
the auto-generated, high-entropy subjects and sender localparts that mass-mailing
tools produce.

Malware delivery is an attachment story, but only half of it lives here.
`attachment_count` and `attachment_bytes` (log-transformed) describe *that*
files were attached and roughly how large — an unusual count or size is the smtp-
side signal — while the actual masquerade, extension, and hash checks happen in
the `files` set on the same `flow_id`. This set deliberately stays on the
envelope so the two don't duplicate each other.

> **Extraction + handoff caveat:** header fields (`From`, subject, URLs) require
> Suricata's MIME / email extraction enabled in `suricata.yaml`; without it those
> columns are empty and ride `missing => zero`. Attachment *content* is not here —
> correlate to the `files` set on `flow_id`. `distinct_rcpt_rate` is per-sender
> pipeline state.

**Candidates to add:** auth-failure rate per source (587/465 brute force),
recipients-per-message vs. body-size ratio, and X-Mailer frequency-encoded.

### smb

One set. SMB is lateral-movement rich and almost entirely categorical +
volumetric, which suits an encoded/rate feature table well.

set **smb**

| column | description |
|-|-|
| smb_command | encoded SMB command (Create/Read/Write/Rename/Delete/TreeConnect/…) |
| dialect | encoded negotiated dialect (SMBv1 is anomalous) |
| status_fail | boolean: response status is an error (access-denied probing) |
| named_pipe | frequency-encoded named pipe (`svcctl`/`samr`/`lsarpc`/`atsvc` = tooling) |
| admin_share | boolean: access to an admin share (`ADMIN$`, `C$`, `IPC$`) |
| distinct_shares | distinct shares accessed per host over the window |
| distinct_files | distinct files touched per host over the window |
| write_delete_rate | write + rename + delete ops per host over the window (ransomware) |
| filename_entropy | Shannon entropy of the filename |
| ntlm_host_entropy | Shannon entropy of the NTLMSSP hostname (random tooling hostnames) |

**Why:**

`smb_command` and `dialect` set the baseline. The command mix is fairly stable
for a given host's role (a workstation reads files, it doesn't create services),
so encoding `smb_command` lets unusual verbs surface. `dialect` is called out
separately because SMBv1 is a red flag on its own — it is EternalBlue-era,
disabled on healthy modern networks, and its reappearance usually means either
ancient gear or an exploit reaching for the old protocol.

The lateral-movement columns are where SMB earns its place. `named_pipe` is
frequency-encoded because the pipe name *is* the technique: `svcctl` is remote
service creation (PsExec), `atsvc`/`tsch` is scheduled-task execution, `samr` is
account enumeration, and `lsarpc`/`drsuapi` underpin DCSync — all rare on normal
traffic, so a rare pipe scores high. `admin_share` is the companion primitive:
touching `ADMIN$`, `C$`, or `IPC$` is how remote code execution and file
staging land on a target. `status_fail` catches the reconnaissance that precedes
all of this — a host generating many access-denied responses is walking shares
and permissions looking for a way in.

The ransomware signature is behavioral and volumetric. `distinct_shares` and
`distinct_files` spike as an infected host reaches across the network to
everything it can reach, and `write_delete_rate` spikes as it encrypts —
write-then-rename-then-delete in a tight loop, at a rate no human workflow
produces. `filename_entropy` catches the randomized names ransomware and tooling
leave behind, and `ntlm_host_entropy` catches the spoofed, random NTLMSSP
hostnames that automated tools present instead of a real machine name.

> **Derived-state caveat:** `distinct_shares`, `distinct_files`, and
> `write_delete_rate` come from per-host window state, not one record. DCERPC
> carried over SMB may also surface as separate `dcerpc` events — don't
> double-count.

**Candidates to add:** NTLM domain/user frequency-encoded, session-setup
failure rate (auth spray), and signed-vs-unsigned session boolean.

### ftp

One set. The FTP *control* channel — commands and auth. Cleartext, so the
command stream is fully visible; the transfer volume lives in `ftp_data`.

set **ftp**

| column | description |
|-|-|
| ftp_command | encoded command (USER/PASS/RETR/STOR/LIST/DELE/SITE/…) |
| reply_code | bucketed completion code (2xx / 4xx / 5xx) |
| login_fail_rate | authentication-failed (530) replies per source over the window |
| command_rate | commands per source over the window |
| distinct_commands | distinct commands per session (recon) |
| username_entropy | Shannon entropy of the USER argument |
| passive_mode | boolean: PASV/EPSV used (dynamic data port negotiated) |

**Why:**

Brute force is the primary target and it reads across two columns.
`login_fail_rate` counts authentication-failed (530) replies per source, which
is the direct signal, and `command_rate` corroborates it — a source hammering
USER/PASS pairs generates a command volume no interactive session matches. Kept
together because a slow, low-fail spray and a fast, high-fail hammer are both
attacks, and the pair spans them. `username_entropy` adds the credential-
spraying angle: tools that cycle generated usernames produce high-entropy USER
arguments, unlike the handful of real accounts a legitimate client uses.

`distinct_commands` is the recon and automation axis — a scripted client or a
scanner exercises a wider, more mechanical command vocabulary in one session
than a human transferring a file, so an unusually high distinct-command count
per session stands out. `ftp_command` is encoded so the dangerous and unusual
verbs — `DELE`, `RNFR`, `SITE EXEC` and friends — surface on their own axis
rather than drowning in the RETR/STOR/LIST bulk. `reply_code`, bucketed into
2xx/4xx/5xx, gives the forest a compact view of error-heavy sessions, which
accompany both probing and misconfiguration. `passive_mode` notes whether the
session negotiated PASV/EPSV, which determines where the data channel opens and
so is context for correlating the `ftp_data` transfer.

> **Split-channel caveat:** actual bytes moved are *not* here — they are in
> `ftp_data` (below), correlated via the negotiated data port / `flow_id`.
> `login_fail_rate` and `command_rate` are per-source pipeline state.

**Candidates to add:** anonymous-login boolean, bounce-attack indicator
(PORT to a third-party IP), and command-argument length.

### ftp_data

One set. The FTP *data* channel — one record per transfer. Thin on its own, so
most columns are joined from the paired `flow` record; file content is scored by
the `files` set.

set **ftp_data**

| column | description |
|-|-|
| transfer_command | encoded STOR (upload) vs. RETR (download) |
| transfer_bytes | bytes moved on the data channel, log-transformed (paired flow) |
| direction | boolean: 1 = inbound STOR to server, 0 = outbound RETR |
| filename_length | length of the transferred filename |
| filename_entropy | Shannon entropy of the filename |
| files_per_session_rate | files transferred per host over the window |

**Why:**

`transfer_command` and `direction` establish which way data is moving, and that
is most of the risk. A STOR (upload to the server) inbound to a monitored host is
a drop or a staging action; a RETR (download) outbound is potential exfil. The
forest should treat those asymmetrically, so the direction is encoded two ways —
the STOR/RETR verb and the inbound/outbound boolean — rather than left implicit.

`transfer_bytes` (log-transformed, joined from the paired flow) is the volume
that turns a routine transfer into a staging or exfil event when it is large,
and `files_per_session_rate` catches the other shape of bulk movement — many
files pushed through one session, the pattern of someone sweeping a directory out
rather than grabbing a single file. `filename_length` and `filename_entropy`
carry the same tooling signal they do in the `files` set: randomized, generated
names betray automation. This set stays intentionally thin because the file's
*content* — magic, extension, hash — is scored once, in `files`, on the same
transfer; here we only describe the envelope so the two don't overlap.

> **Flow-join + overlap caveat:** `transfer_bytes` and `direction` come from the
> paired `flow`, not the `ftp_data` event — correlate on `flow_id`. This set is
> the transfer *envelope*; magic / extension / hash of the file itself belong to
> the `files` set, so don't duplicate them here.

**Candidates to add:** transfer duration and throughput (bytes/sec) from the
paired flow, and aborted-transfer boolean.

### krb5

One set. Kerberos is highly categorical and Suricata even pre-computes a
`weak_encryption` flag, so the kerberoasting / spraying signals map almost
directly onto columns.

set **krb5**

| column | description |
|-|-|
| msg_type | encoded message type (AS-REQ/AS-REP/TGS-REQ/TGS-REP/ERROR) |
| enc_type | encoded ticket encryption type (etype) |
| weak_encryption | boolean: Suricata's `weak_encryption` flag (RC4/DES) |
| ticket_request_rate | TGS-REQ per principal over the window (kerberoasting) |
| distinct_snames | distinct service names requested per principal over the window (SPN enumeration) |
| fail_rate | KRB-ERROR / failed requests per source over the window (spraying) |
| error_code | encoded error code (PREAUTH_FAILED, principal-unknown) |
| cname_entropy | Shannon entropy of the client principal name |
| sname_entropy | Shannon entropy of the service principal name |

**Why:**

Kerberoasting is the headline attack and it lights up three columns at once. The
attacker requests service tickets for many Service Principal Names and asks for
RC4 encryption because those tickets are crackable offline, so
`ticket_request_rate` (many TGS-REQ from one principal), `distinct_snames` (for
*different* services, i.e. SPN enumeration), and `weak_encryption` all rise
together. Any one of them alone is weak; the co-occurrence is the signature, and
Suricata pre-computing `weak_encryption` as a boolean means that high-value axis
needs no derivation on our side. `enc_type` is the finer-grained companion —
encoding the exact etype catches AS-REP roasting and downgrade, where the tell
is a weak encryption type appearing on an AS-REP.

`msg_type` frames the exchange (AS-REQ/AS-REP/TGS-REQ/TGS-REP/ERROR) so the
forest can tell a ticket-granting flow from an authentication flow. Password
spraying reads through `fail_rate` and `error_code` together: a source producing
KRB-ERRORs with `error_code` = PREAUTH_FAILED across many accounts is guessing
passwords, and the encoded error code distinguishes that from benign
principal-unknown noise. `cname_entropy` and `sname_entropy` catch the randomized
or tooling-generated principal and service names that automated Kerberos attacks
produce, unlike the stable, human-readable names of a real domain.

> **Derived-state caveat:** `ticket_request_rate`, `distinct_snames`, and
> `fail_rate` are per-principal / per-source window state, not single records.

**Candidates to add:** ticket lifetime (renew-till − start), no-preauth (AS-REQ
without pre-auth) boolean for AS-REP roasting, and realm frequency-encoded.

### rdp

One set. RDP negotiation, client fingerprint, and connection volume. After the
handshake RDP wraps in TLS, so cert/JA3 signal is scored by the `tls` set on the
paired flow — this set is the RDP-specific negotiation.

set **rdp**

| column | description |
|-|-|
| rdp_event | encoded event type (initial_request/connect_response/tls_handshake/…) |
| conn_rate | RDP connections per source over the window (brute force) |
| cookie_present | boolean: mstshash cookie present |
| cookie_entropy | Shannon entropy of the cookie (the attempted username) |
| keyboard_layout | frequency-encoded client keyboard layout (foreign locale = interesting) |
| client_build | frequency-encoded client build / product id (rare / old / tooling) |
| client_name_entropy | Shannon entropy of the client machine name |
| channel_count | number of requested virtual channels |
| self_signed_cert | boolean: RDP-over-TLS cert is self-signed (default RDP cert) |

**Why:**

`conn_rate` is the brute-force axis and, for internet-facing RDP, the single
busiest attack surface there is — automated tools hammer 3389 constantly, so
many connections from one source over the window is the direct signal.
`rdp_event` encodes where in the negotiation each record sits, which lets the
forest tell a completed connection from a flood of half-open initial requests
that never progress (the shape of a scanner or a failed brute-force).

The `cookie` columns read the login attempt itself. RDP's mstshash cookie
carries the username the client is trying, so `cookie_present` notes whether one
was offered at all and `cookie_entropy` flags the generated, high-entropy names
that spraying tools cycle through — a stark contrast to the small set of real
usernames a legitimate client presents.

The client-fingerprint columns are the external-compromise tells. `keyboard_
layout` and `client_build` are frequency-encoded because a foreign keyboard
layout or a rare/old client build reaching an internal host is exactly what an
attacker connecting from elsewhere looks like — their machine isn't configured
like the local fleet. `client_name_entropy` catches the random hostnames tooling
presents instead of a real workstation name, and `channel_count` catches unusual
feature negotiation (headless or scripted clients request a different set of
virtual channels than a real mstsc session). `self_signed_cert` notes the
default self-signed RDP certificate, which is normal but, combined with an
external source and a rare client build, adds weight.

> **TLS-handoff caveat:** NLA / CredSSP moves auth into TLS, so the `cookie`
> columns are often absent (ride `missing => zero`) and the real cert / JA3
> fingerprint lives in the paired `tls` event — score it there, don't duplicate.
> `conn_rate` is per-source pipeline state.

**Candidates to add:** requested desktop width/height (odd resolutions =
headless tooling), and connection-hint frequency-encoded.

### sip

One set. VoIP signaling — method, target, and volume. Request and response are
separate events, so any one row fills the columns for its half.

set **sip**

| column | description |
|-|-|
| sip_method | encoded method (INVITE/REGISTER/OPTIONS/BYE/…) |
| request_rate | SIP requests per source over the window (INVITE / REGISTER floods) |
| response_code | bucketed response code (2xx / 4xx / 5xx) |
| auth_fail_rate | 401/403/407 responses per source over the window (registration brute force) |
| uri_user_length | length of the URI user part |
| uri_user_entropy | Shannon entropy of the URI user part |
| distinct_uris | distinct target URIs per source over the window (extension scanning) |
| user_agent | frequency-encoded User-Agent (sipvicious / friendly-scanner = tooling) |

**Why:**

`sip_method` and `request_rate` together frame the two big VoIP abuses. Toll
fraud and INVITE floods are a rate story with a method skew — a source driving
`request_rate` up with an INVITE-heavy mix is placing calls it shouldn't, while
a REGISTER-heavy flood is account hijacking. Encoding the method lets the forest
see the mix, not just the volume, and the two columns together separate a busy-
but-normal PBX from an attack.

Registration brute force reads through `auth_fail_rate` — a storm of 401/403/407
responses to one source is password guessing against SIP accounts. Extension
enumeration, the recon that precedes it, reads through `distinct_uris` and
`uri_user_entropy`: a scanner walks many target URIs (`distinct_uris`) probing
for valid extensions, and the generated or sequential user parts it tries push
`uri_user_entropy` and `uri_user_length` off the profile of the handful of real
extensions a normal endpoint contacts.

`user_agent` is frequency-encoded because SIP attack tooling is famously
self-identifying — `sipvicious`, `friendly-scanner`, and similar leave a
distinctive UA — so a rare or known-bad value scores high on its own. And
`response_code`, bucketed into 2xx/3xx/4xx/5xx, gives a compact error-rate view
that rises during both enumeration and malformed-request probing.

> **Request/response split + rule caveat:** `response_code` / `auth_fail_rate`
> come from responses, `sip_method` / URI fields from requests, so a single event
> populates a subset — the rest ride `missing => zero`. The rate/distinct columns
> are per-source window state. Known scanner UAs (`friendly-scanner`) are also
> trivially a rule.

**Candidates to add:** Call-ID entropy, `Contact` vs. `Via` host mismatch
(spoofing), and codec / SDP media-count from INVITE bodies.

### snmp

One set. SNMP is small and categorical, and its weaknesses are structural
(cleartext v1/v2c), so version + PDU + rate features carry most of the signal.

set **snmp**

| column | description |
|-|-|
| snmp_version | encoded version (v1 / v2c = cleartext community; v3 = auth) |
| pdu_type | encoded PDU (get / getnext / getbulk / set / trap / response) |
| request_rate | SNMP requests per source over the window (walk / enumeration) |
| community_present | boolean: community string present (v1 / v2c) |
| community_entropy | Shannon entropy of the community string (guessing past public/private) |
| set_rate | SET requests per source over the window (config tampering) |
| distinct_oids | distinct OIDs queried per source over the window (full-tree walk) |
| error_rate | SNMP error responses per source over the window (noAccess / authFail probing) |

**Why:**

`snmp_version` is first because SNMP's weakness is structural: v1 and v2c
authenticate with a cleartext community string, so simply *seeing* them tells the
forest this traffic is guessable and worth watching, whereas v3 (which
authenticates and can encrypt) is a different risk class. The community columns
build on that — `community_present` notes whether a community string was offered,
and `community_entropy` flags guessing that has moved past the default
`public`/`private` into generated strings, which is what a community-string
brute-forcer produces.

Enumeration is the main attack and it reads across three columns. An SNMP walk
scrapes a device by requesting its whole MIB tree, so `request_rate` climbs, the
`pdu_type` skews toward `getnext`/`getbulk` (the verbs used to iterate), and
`distinct_oids` climbs as the attacker touches object after object. Together they
describe "someone is systematically reading everything," which no monitoring
poll of a fixed OID set does.

`set_rate` is the tampering axis and the most dangerous column: SET requests
*change* device configuration, and on read-only monitoring infrastructure they
should be near zero, so any rate of them is a strong signal. `error_rate` catches
authentication-failure probing.

> **Secret + derived-state caveat:** the community string is a secret — feed
> `community_present` and `community_entropy`, never the raw string (same rule as
> hashes). `request_rate`, `set_rate`, `distinct_oids`, and `error_rate` are
> per-source window state. SNMPv3 moves auth into USM, so the community columns
> are empty there and ride `missing => zero`.

**Candidates to add:** USM username frequency-encoded (v3), and OID-prefix
frequency-encoding (which MIB subtree is being hit).

### ike

One set. IKE / ISAKMP VPN negotiation. Highly categorical — versions, exchange
types, and proposed algorithms — plus a negotiation rate.

set **ike**

| column | description |
|-|-|
| ike_version | encoded IKE version (v1 vs v2) |
| exchange_type | encoded exchange (main / aggressive / IKE_SA_INIT / …) |
| enc_alg | encoded proposed encryption algorithm (DES / 3DES = weak) |
| dh_group | encoded Diffie-Hellman group (low groups = weak / downgrade) |
| auth_method | encoded authentication method (PSK vs. certificate) |
| weak_proposal | boolean: any proposed algorithm is weak / deprecated |
| init_rate | SA-init / main-mode starts per source over the window (brute force / DoS) |
| vendor_id | frequency-encoded vendor ID (fingerprints the VPN implementation) |
| notify_fail_rate | error / notify (AUTHENTICATION_FAILED, NO_PROPOSAL_CHOSEN) per source over the window |

**Why:**

`ike_version` and `exchange_type` frame the negotiation, and one combination is a
known weakness on its own: IKEv1 in aggressive mode transmits a hash of the
pre-shared key in the clear, so an attacker can capture and crack it offline.
Encoding the exchange type makes aggressive-mode negotiations separable from the
main-mode and IKE_SA_INIT norm.

The proposal columns describe the *crypto being offered*, which is where
downgrade and legacy-config risk lives. `enc_alg` and `dh_group` are encoded so
weak choices (DES/3DES, low DH groups) surface, and `weak_proposal` is a single
boolean summarizing "anything in the offered set is deprecated" — useful because
proposals are lists and the forest wants one clean axis for "this endpoint is
negotiating weak crypto." `auth_method` (PSK vs. certificate) adds context, since
PSK is the mode vulnerable to the aggressive-mode leak above.

`init_rate` is the volume axis: a source starting many SA negotiations per window
is either brute-forcing PSKs or flooding the responder to exhaust it (a known IKE
DoS). `vendor_id` frequency-encodes the vendor-ID payloads that fingerprint the
VPN implementation, so a rare or unexpected client stack reaching the gateway
stands out. `notify_fail_rate` closes the loop by counting error/notify messages
(AUTHENTICATION_FAILED, NO_PROPOSAL_CHOSEN) per source — the response side of PSK
guessing and proposal-mismatch probing.

> **Derived-state caveat:** proposals are lists — encode the negotiated/first
> and set `weak_proposal` across all. `init_rate` / `notify_fail_rate` are
> per-source window state; IKEv1 and v2 expose different fields.

### rfb

One set. VNC (Remote Framebuffer) handshake and connection volume.

set **rfb**

| column | description |
|-|-|
| rfb_version | encoded protocol version (3.3 = weak-auth only) |
| security_type | encoded security type (None / VNC-auth / Tight / …) |
| auth_fail_rate | authentication failures per source over the window (password brute force) |
| conn_rate | VNC connections per source over the window |
| shared_flag | boolean: session requested shared (multiple viewers) |
| desktop_name_entropy | Shannon entropy of the server desktop name |
| screen_area | framebuffer width × height, log-transformed (odd sizes = headless) |

**Why:**

`security_type` is the headline column: a value of None means an open,
unauthenticated VNC server that anyone reaching it can drive — a critical
exposure, and the reason this set exists at all. `rfb_version` reinforces it,
because RFB 3.3 only supports the weak DES-based VNC authentication, so an old
protocol version is a proxy for "even if auth is on, it's breakable."

`auth_fail_rate` and `conn_rate` are the brute-force pair. VNC's weak auth makes
it a heavy target, so a source generating authentication failures
(`auth_fail_rate`) and/or many connection attempts (`conn_rate`) over the window
is the password-guessing signature — the two together span the slow and fast
variants the same way they do in the SSH and RDP sets.

`desktop_name_entropy` and `screen_area` profile the *target*: a random,
high-entropy desktop name or an odd framebuffer geometry (log-transformed) is
what headless and automated VNC endpoints look like, versus a named human
desktop at a standard resolution. `shared_flag` notes a session requesting
shared access — multiple simultaneous viewers — which is unusual and consistent
with session hijacking or shoulder-surfing.

> **Rule-vs-model note:** an open VNC (`security_type` None) is also trivially an
> alerting rule. `auth_fail_rate` / `conn_rate` are per-source window state.

### dcerpc

One set. MS RPC — the interface UUID plus operation number is where lateral
movement and domain attacks show up.

set **dcerpc**

| column | description |
|-|-|
| interface_uuid | frequency-encoded interface UUID (drsuapi / svcctl / atsvc / samr = tooling) |
| opnum | encoded operation number within the interface |
| distinct_opnums | distinct operations per host over the window (recon / lateral) |
| distinct_interfaces | distinct interfaces bound per host over the window |
| request_rate | DCERPC requests per source over the window |
| bind_rate | interface bind attempts per source over the window (interface scanning) |
| fault_rate | fault / error responses per source over the window (access-denied probing) |

**Why:**

`interface_uuid` is the crown jewel of this set because the interface *is* the
capability. Each UUID maps to a service, and a handful of those services are the
building blocks of Windows attacks: `drsuapi` (with `opnum` 3, GetNCChanges) is
DCSync, the technique for stealing password hashes from a domain controller;
`svcctl` is remote service creation, the core of PsExec-style lateral movement;
`atsvc`/`tsch` is remote scheduled-task execution; `samr` is account
enumeration. Frequency-encoding the UUID plus encoding the specific `opnum` lets
the forest score these rare, high-value operations on their own axes while the
routine RPC bulk stays baseline.

The remaining columns catch the surrounding behavior. `distinct_interfaces` and
`distinct_opnums` per host rise during reconnaissance and lateral movement, when
an attacker binds to many interfaces and exercises many operations rather than
the one or two a normal client uses; `request_rate` scales that with volume.
`bind_rate` isolates the binding step — a source binding interface after
interface is scanning for what's exposed — and `fault_rate` catches the
access-denied responses that accompany probing for operations the caller isn't
authorized to run.

> **Overlap + mapping caveat:** DCERPC frequently rides over SMB (see the `smb`
> set) — correlate, don't double-count. The value depends on a maintained
> UUID→service / opnum→operation mapping table. Rates are per-source window state.

### nfs

One set. NFS file operations; AUTH_SYS makes the asserted uid itself a feature.

set **nfs**

| column | description |
|-|-|
| nfs_procedure | encoded procedure (READ/WRITE/CREATE/REMOVE/RENAME/READDIR/…) |
| nfs_version | encoded NFS version (v2 / v3 = weaker auth) |
| status_fail | boolean: response status is an error (permission probing) |
| distinct_files | distinct files accessed per host over the window |
| write_delete_rate | WRITE + REMOVE + RENAME ops per host over the window (ransomware / tampering) |
| readdir_rate | READDIR / READDIRPLUS per host over the window (directory enumeration) |
| filename_entropy | Shannon entropy of the filename |
| auth_uid | frequency-encoded RPC AUTH_SYS uid (unexpected uid = spoofed creds) |

**Why:**

`auth_uid` is the column that makes NFS interesting, and it works because of a
protocol weakness: under AUTH_SYS the client simply *asserts* its uid and gid,
and the server trusts them. That means an attacker can claim to be uid 0 or any
account they like. Frequency-encoding the asserted uid surfaces a client
presenting a rare or unexpected identity — trivial privilege spoofing that no
authentication step ever challenged.

The file-operation columns describe what's being done with that (possibly
spoofed) access. `write_delete_rate` spikes during ransomware or tampering on an
export — the same write-rename-delete burst as the SMB set, at machine speed —
while `readdir_rate` and `distinct_files` together are the scraping and
enumeration signature, a client listing directories and touching far more files
than a normal workflow. `status_fail` catches the permission probing that
precedes it (errors as the attacker maps what they can and can't reach), and
`filename_entropy` catches the randomized names tooling leaves behind.
`nfs_procedure` encodes the operation so unusual verbs separate out, and
`nfs_version` flags the legacy v2/v3 versions whose weaker auth makes the
`auth_uid` spoof easiest.

> **Derived-state caveat:** the rate/distinct columns are per-host window state.
> The `auth_uid` signal exists *because* AUTH_SYS uid is asserted, not
> authenticated.

### modbus

One set. ICS: Modbus has no authentication at all, so every feature is
behavioral, and the environment is metronomic — deviation from the polling
baseline is itself the signal.

set **modbus**

| column | description |
|-|-|
| function_code | encoded function (read/write coils / registers, diagnostics) |
| write_flag | boolean: a write function (write single/multiple coil/register) |
| command_rate | requests per master over the window (baseline vs. flood) |
| unit_id | frequency-encoded unit / slave id (unexpected target device) |
| register_address | target register / coil address (writes to control ranges) |
| quantity | number of registers / coils touched (bulk write) |
| exception_rate | exception responses per master over the window (illegal-function probing) |
| new_master | boolean: first time this source addresses this slave |

**Why:**

The tampering axes — `write_flag`, `register_address`, `quantity` — are the whole
point. Modbus writes change physical process state: opening a valve, changing a
setpoint, tripping a relay. `write_flag` isolates the write functions from the
far more common reads, `register_address` says *which* coil or register is being
written (writes into control ranges are the dangerous ones), and `quantity`
catches a bulk write touching many points at once. An unauthorized write to a
control register is the Stuxnet-class event this set exists to surface, and the
three columns together describe it precisely rather than just flagging "a write
happened."

Everything else keys on the fact that ICS traffic is metronomic — a master polls
the same slaves for the same registers on a fixed cycle. `command_rate` therefore
makes deviation from that baseline (a flood, or a sudden burst of new commands)
visible, and `new_master` flags a source addressing a slave it never has before,
which is exactly what a rogue engineering station or a compromised host looks
like on a network where the pairings are supposed to be fixed. `unit_id` is
frequency-encoded so an unexpected target device stands out, and `exception_rate`
catches function-code scanning — an attacker probing for supported functions
generates illegal-function exceptions a normal master never triggers.

> **Behavioral-only caveat:** per-master / per-slave window state and a
> first-seen pairing store back most columns; Modbus offers nothing to
> authenticate on. Writes to control registers are usually also a hard ICS rule.

### dnp3

One set. ICS / SCADA. Same closed-and-predictable logic as `modbus`; control
functions actuate physical equipment.

set **dnp3**

| column | description |
|-|-|
| function_code | encoded application function (READ/WRITE/OPERATE/SELECT/RESTART/…) |
| control_flag | boolean: a control function (OPERATE / DIRECT_OPERATE / SELECT) |
| restart_flag | boolean: a restart / disable function (COLD_RESTART / DISABLE_UNSOLICITED) |
| command_rate | requests per master over the window (baseline vs. flood) |
| dnp3_src | frequency-encoded DNP3 source (link) address |
| dnp3_dst | frequency-encoded DNP3 destination (link) address |
| iin_flags | encoded internal-indication flags (device-restart / parameter-error bits) |
| new_pairing | boolean: first time this src ↔ dst pair is seen |

**Why:**

`control_flag` is the crown-jewel column: OPERATE, DIRECT_OPERATE, and SELECT are
the DNP3 functions that actuate physical equipment — trip a breaker, move a
setpoint — so an unauthorized control command is the highest-consequence attack on
the protocol. `function_code` encodes the full verb set behind it so unusual
functions surface individually, and `restart_flag` isolates the other dangerous
class: COLD_RESTART and DISABLE_UNSOLICITED don't change the process but blind the
operator or knock the outstation offline, a denial-of-view/DoS the forest should
weight as heavily as a write.

The rest is the same closed-environment logic as `modbus`. `command_rate` makes
deviation from the fixed polling baseline visible, and `new_pairing` flags a
source↔destination link never seen before — a rogue master inserting itself.
`dnp3_src` and `dnp3_dst` are frequency-encoded (they are DNP3 link addresses,
not IPs) so unexpected endpoints stand out, and `iin_flags` encodes the internal-
indication bits the outstation returns, which surface the device restarts and
parameter errors that often accompany an attack or a misconfiguration.

> **Behavioral-only caveat:** src/dst are DNP3 link addresses, not IPs; per-master
> state backs the rates. DNP3 Secure Authentication is rarely deployed, so treat
> links as unauthenticated.

### enip

One set. ICS: EtherNet/IP + CIP. Discovery scans and tag writes are the events
that matter.

set **enip**

| column | description |
|-|-|
| enip_command | encoded ENIP command (register_session / list_identity / send_rr_data / …) |
| cip_service | encoded CIP service (read tag / write tag / forward-open / reset) |
| write_flag | boolean: a CIP write / set service (tag write, attribute set) |
| command_rate | ENIP / CIP requests per source over the window (baseline vs. flood) |
| list_identity_rate | ListIdentity requests per source over the window (device discovery) |
| target_path | frequency-encoded CIP class / instance path (unexpected object target) |
| status_fail | boolean: non-success ENIP / CIP status (probing) |
| new_source | boolean: first time this source talks to this device |

**Why:**

`list_identity_rate` is the discovery detector. ListIdentity is the standard way
to ask an EtherNet/IP device to describe itself, so it's the first thing a plant-
mapping scanner does at scale — a rate of it from one source is reconnaissance,
plainly. `enip_command` encodes the surrounding ENIP verbs so unusual session or
data commands separate from the norm.

The tampering axis is `write_flag`, `cip_service`, and `target_path` together.
CIP is where the actual control happens: `cip_service` encodes the operation
(read tag, write tag, forward-open, reset), `write_flag` isolates the write and
set services that change device state, and `target_path` frequency-encodes the
CIP class/instance being addressed so a write to an unexpected object stands out.
Writing a tag or resetting a controller is the consequential attack, and these
three describe it the way `write_flag`/`register_address`/`quantity` do for
Modbus.

`command_rate` and `new_source` carry the same behavioral logic as the other ICS
sets — deviation from the fixed baseline, and a source talking to a device it
never has before (a rogue engineering workstation). `status_fail` catches the
object- and service-enumeration probing that returns non-success statuses as an
attacker maps what the device exposes.

> **Behavioral-only caveat:** per-source window state and CIP parse depth are
> required; same closed-environment reasoning as `modbus` / `dnp3`.

### tftp

One set. TFTP is unauthenticated and typically only used for device configs and
PXE, so its presence and write direction carry most of the signal.

set **tftp**

| column | description |
|-|-|
| tftp_opcode | encoded operation (RRQ read / WRQ write / ERROR) |
| write_flag | boolean: WRQ (upload to server) |
| mode | encoded transfer mode (octet / netascii) |
| filename_length | length of the requested filename |
| filename_entropy | Shannon entropy of the filename |
| request_rate | TFTP requests per source over the window |
| error_rate | TFTP error packets per source over the window (file-not-found scanning) |

**Why:**

`write_flag` isolates the dangerous half of TFTP. The protocol is unauthenticated
and mostly carries router/switch configs and PXE boot images, so a read (RRQ) is
routine but a write (WRQ) — overwriting a network device's config or a boot
image — is a high-impact action anyone on-path can perform. `tftp_opcode` encodes
the full operation set (RRQ/WRQ/ERROR) so the write, and error responses, sit on
their own axis.

`request_rate` and `error_rate` are the scanning pair: an attacker who doesn't
know the exact config filename guesses, producing many requests and a stream of
file-not-found errors that a legitimate client — which asks for one known file —
never generates. `filename_length` and `filename_entropy` catch the other shape
of that probing, path traversal (`../`) and randomized or generated target names.
`mode` (octet vs. netascii) is encoded as minor context. Underlying all of it:
TFTP appearing between hosts that have no reason to speak it is itself the signal,
which is why even the low-information columns here are worth carrying.

> **Rule + handoff caveat:** TFTP anywhere unexpected is often just a rule.
> Transferred file content pairs with the `files` set if Suricata extracts it;
> rates are per-source window state.

### bittorrent-dht

One set. On a monitored network BitTorrent DHT usually should not exist, so
presence and fanout are the headline — and DHT is also abused as resilient C2.

set **bittorrent-dht**

| column | description |
|-|-|
| request_type | encoded DHT query (ping / find_node / get_peers / announce_peer) |
| request_rate | DHT messages per source over the window |
| distinct_peers | distinct DHT peers contacted per source over the window (fanout) |
| distinct_info_hashes | distinct info_hashes queried / announced per source over the window |
| announce_flag | boolean: announce_peer (this host is sharing content) |
| client_version | frequency-encoded client version string |
| node_id_entropy | Shannon entropy of the node id |

**Why:**

The starting premise is that BitTorrent DHT usually should not exist on a
monitored corporate or server network at all, so `request_rate` and
`distinct_peers` carry the first-order signal: a host exchanging DHT messages
with many distinct peers is doing peer-to-peer, whether that's policy-violating
file sharing or something using the DHT as transport. `request_type` encodes the
query mix (ping / find_node / get_peers / announce_peer) so the *kind* of DHT
activity is visible, not just its volume.

The second-order and more interesting angle is C2. DHT is abused as a resilient,
hard-to-block rendezvous: malware treats info_hashes as dead-drops, announcing or
querying them to find its controller without any fixed domain or IP to blocklist.
`distinct_info_hashes` catches a host touching many info_hashes (unusual for a
normal client settled on a few torrents), and `announce_flag` flags announce_peer
messages — the host advertising that it is *serving* content or a rendezvous
point. `client_version` is frequency-encoded to separate real torrent clients
(which report recognizable version strings) from the custom stacks malware ships,
and `node_id_entropy` catches non-standard or rapidly-rotating node IDs that
don't follow the conventions a genuine client uses.

> **Rule-vs-model note:** simple presence is also a rule; the C2-over-DHT angle
> is the reason to model rather than just block. Rates / distinct counts are
> per-source window state.

### pgsql

One set. PostgreSQL wire protocol (Suricata 7+). Auth failures, error storms,
and query shape.

set **pgsql**

| column | description |
|-|-|
| msg_type | encoded message type (Startup / Query / Auth / Error / …) |
| query_rate | queries per source over the window |
| auth_fail_rate | authentication-failure responses per source over the window (brute force) |
| error_rate | ErrorResponse messages per source over the window (SQLi probing / bad syntax) |
| distinct_errors | distinct SQLSTATE codes per source over the window (injection fuzzing) |
| user_entropy | Shannon entropy of the startup user name |
| database | frequency-encoded target database name |
| query_length | simple-query string length, log-transformed |

**Why:**

Database brute force reads through `auth_fail_rate` — a source drawing repeated
authentication-failure responses is guessing credentials — and `user_entropy`
adds the spraying angle, since tools cycling generated usernames produce high-
entropy startup user names unlike the few real roles an application connects as.

SQL-injection fuzzing is the other main attack, and it shows in the error
behavior. As an attacker probes, malformed and type-mismatched queries throw
errors, so `error_rate` (volume of ErrorResponse messages) rises and
`distinct_errors` (distinct SQLSTATE codes) widens — a legitimate application
hits a small, stable set of errors, while a fuzzer trips many different ones.
`query_length` (log-transformed) corroborates it because injection payloads and
UNION-based extraction produce unusually long query strings.

`database` is frequency-encoded so a connection to a database this source
normally never touches stands out — lateral movement or credential misuse often
shows as access to an unexpected schema. `query_rate` sets the baseline that
makes the rest legible: steady application traffic has a characteristic rate, and
both interactive tooling and automated attacks deviate from it. `msg_type`
encodes the protocol phase (Startup / Query / Auth / Error) so the forest can
tell an auth flood from a query flood.

> **TLS caveat:** `sslmode=require` wraps Postgres in TLS, hiding everything past
> the startup packet — those sessions surface only in the `tls` set. Rates /
> distinct counts are per-source window state.

### arp

One set. ARP has no payload, so it is entirely behavioral — MAC↔IP bindings and
reply volume. Spoofing / poisoning is the target.

set **arp**

| column | description |
|-|-|
| arp_opcode | encoded opcode (request vs. reply) |
| reply_rate | ARP replies per source MAC over the window (gratuitous-reply flood) |
| unsolicited_flag | boolean: reply with no preceding request (gratuitous ARP) |
| macs_per_ip | distinct MACs claiming one IP over the window (spoofing / poisoning) |
| ips_per_mac | distinct IPs claimed by one MAC over the window (impersonation / scan) |
| request_rate | ARP requests per source over the window (address scanning) |
| new_mac_ip | boolean: first time this MAC ↔ IP binding is seen |

**Why:**

`macs_per_ip` is the column that matters most, because it is the direct signature
of ARP poisoning. In a healthy network one IP maps to exactly one MAC; when two
or more MACs claim the same IP — especially the gateway's — someone is
advertising themselves as a host they are not, which is how an attacker inserts
themselves into the middle of a conversation. Anything above one on this column
is the attack, plainly. `ips_per_mac` is its mirror image and catches the other
direction: a single MAC claiming many IPs is one host impersonating many, or
sweeping the segment.

The rate and flag columns catch *how* the poisoning is delivered. Attackers keep
a spoofed mapping alive by continuously broadcasting it, so `reply_rate` climbs
and `unsolicited_flag` fires — a gratuitous reply is an ARP answer nobody asked
for, which is the mechanism of the attack and rare in normal traffic where
replies follow requests. `request_rate` covers reconnaissance rather than
spoofing: a host ARPing across the subnet is doing address-discovery host
scanning. `new_mac_ip` flags a never-before-seen binding, which is how a rogue
device first appears. `arp_opcode` simply separates requests from replies so the
forest can weight the two behaviors differently.

Because ARP carries no payload, every one of these is derived from per-MAC /
per-IP window state and a first-seen binding store — there is nothing else to go
on, which is exactly why the behavioral view is the whole model here.

> **Rule-vs-model note:** all columns are per-MAC / per-IP window state plus a
> first-seen binding store — ARP spoofing (`macs_per_ip` > 1) is usually a hard
> rule too. This set folds the volume features into the host-level picture rather
> than replacing that rule.

## alert, anomaly & drop — host-level feature sources

These three are **not** per-event forests. An `alert` is already a signature
decision (the *known*), so training an unsupervised model on it is circular and
its `signature_id` is a high-cardinality identifier the [design
rules](#design-rules-why-the-columns-look-the-way-they-do) forbid feeding.
`anomaly` and `drop` are individually common and noisy. All three instead
contribute **columns to the host-level model** (below), aggregated per
`(src_ip, window)` — and `alert` additionally serves as the weak label that
lets the whole system be tuned and triaged.

### alert

Contributes these columns to the host-level model:

| column | description |
|-|-|
| alert_count | alerts for this host over the window (rate via the internal rate meter) |
| distinct_sids | distinct signatures tripped (many *different* sigs ≫ one sig ×1000) |
| max_severity | highest severity seen (Suricata severity 1 = worst) |
| high_sev_ratio | high-severity alerts / total |
| category_counts | encoded per-category counts (Trojan / Attempted-Admin / Policy / …) |
| new_sid | boolean: a signature this host has never tripped before |

`distinct_sids` and `new_sid` are the sharp ones — a host that is
individually-normal on every protocol set but is quietly accumulating a *spread*
of signatures is exactly the slow behavior per-event models miss.

**As a weak label.** Because the forests are unsupervised there is no ground
truth; alerts supply one, for free, to validate scores (do high anomaly scores
co-occur with alerts?) and to tune the score cutoff / `contamination`. The
payoff is the anomaly-score × alert cross-product:

|  | **alert** | **no alert** |
|-|-|-|
| **anomalous** | high-confidence — triage first | **the novel bucket** — why this system exists |
| **normal** | signature handles it (or FP) | baseline |

Signatures already own the bottom-left. The top-right — **anomalous but
unsignatured** — is the entire reason to add anomaly detection on top of
Suricata, and alerts are what separate that cell from noise.

> **Join, don't re-ingest:** an alert record embeds the whole flow + app-layer
> context. The `flow` / `http` / `tls` sets already process that, so use the
> alert record only for its alert-specific fields (`signature_id`, `category`,
> `severity`, `action`) joined on `flow_id` — otherwise the flow is counted
> twice. `alert_count` uses per-host rate-meter state; `new_sid` uses a
> per-host seen-`sid` set.

### anomaly

Suricata's own protocol-violation events — `anomaly.type` is `decode`, `stream`,
or `applayer` (malformed packets, out-of-spec TCP, app-layer parser confusion).
Individually common, so aggregated per host/window:

| column | description |
|-|-|
| anomaly_count | anomaly events for this host over the window |
| distinct_anomaly_events | distinct `anomaly.event` codes seen |
| type_counts | encoded counts per `anomaly.type` (decode / stream / applayer) |
| applayer_ratio | app-layer anomalies / total |

`applayer_ratio` is the security-relevant one: deliberately malformed app-layer
traffic is a classic IDS-evasion / parser-confusion technique, so a host driving
app-layer anomalies up is more interesting than one throwing decode errors from
a flaky NIC.

### drop

IPS-mode only — packets the engine actively blocked. Closely tied to `alert`
(`alert.action == blocked` is the alert-side view of the same event):

| column | description |
|-|-|
| drop_count | packets dropped for this host over the window |
| drop_reason_counts | encoded counts per `drop.reason` |

A host generating a sustained stream of drops is being actively blocked —
compromised, scanning, or misconfigured.

> **No double-count + IDS caveat:** pick one source for the "blocked" signal —
> `drop_count` here *or* `blocked_count` from `alert.action`, not both. In IDS
> (non-inline) mode there are no `drop` events at all, so this column is simply
> absent and rides `missing => zero`.

## stats — sensor-health model & data-quality guard

`stats` is different from everything above: it is **per-sensor telemetry, not
per-host security** — `capture.kernel_drops`, `decoder.invalid`,
`flow.memcap`, `tcp.reassembly_gaps`, and so on. It has two roles.

**1. Its own ops-health set** (a separate slug, e.g. `sensor`, keyed per sensor
per window — not under `suricata`):

set **sensor/stats**

| column | description |
|-|-|
| kernel_drop_rate | `capture.kernel_drops` / `capture.kernel_packets` over the window |
| decoder_invalid_rate | decoder invalid events per packet |
| memcap_pressure | flow / stream / app-layer memcap hits over the window |
| reassembly_gap_rate | TCP reassembly gaps per flow |
| flow_table_pressure | active flows vs. flow-table capacity |

This catches sensor degradation — a NIC dropping packets, memcap exhaustion,
a sensor falling behind line rate.

**2. A data-quality guard for every other set — the more important role.**
Rising `kernel_drop_rate` means Suricata is *seeing less traffic*, so every
security set that window is under-fed. Missing events look like "quiet," which
can both mask a real attack and manufacture false anomalies. So `stats` should
gate confidence: when the drop rate spikes in a window, the security scores from
that same window are flagged low-confidence rather than trusted at face value.

---

## Suricata Host-level model (planned)

A second altitude, aggregated per `(src_ip, window)` rather than per event, to
catch slow and distributed behavior no single event reveals. It joins
protocol-derived aggregates with the `alert` / `anomaly` / `drop` columns
defined above into one row per host per window:

| column | description |
|-|-|
| dest_fanout | distinct destinations contacted (scanning / spread) |
| new_dest_rate | new-destination rate vs. this host's history |
| port_fanout | distinct destination ports (service scanning) |
| bytes_up / bytes_down | total volume each direction, log-transformed |
| upload_ratio | aggregate `(up+1)/(down+1)` (slow exfil) |
| nxdomain_spike | NXDOMAIN count from `dns` (DGA / beaconing) |
| distinct_domains | distinct domains queried |
| proto_entropy | entropy of the app_proto mix (a host's protocol profile shifting) |
| time_sin / time_cos | window position via `suricata_to_circle_both` (see [DNS tradeoffs](#dns)) |
| *alert / anomaly / drop columns* | as defined in their sections above |

The internal rate meter supplies the rate columns; time earns its place
here — "host X's activity in this window vs. its baseline" is exactly where
diurnal context pays off, unlike the per-event sets. MQTT and DHCP especially
benefit from entity-level aggregation (per device / MAC) at this altitude.

## Open questions / TODO

- Confirm the exact `n_trees` / `window_size` / `max_leaf_samples` /
  `contamination` per set; the prototype defaults (100 / 4096 / 32 / 0.01) are a
  starting point, and `window_size` especially wants tuning against each set's
  real event volume.
- Decide the rate-window length for `rcode`, `src_request_rate`, and the ssh /
  dhcp / mqtt volume columns.
- Cyclic time is included in `dns_with_time` on the expectation that it earns
  its place mainly in the host-level model; ablate before committing it to the
  per-event sets.
- fill out LibreNMS bits

[Algorithm::Classifier::IsolationForest::Online]: https://metacpan.org/pod/Algorithm::Classifier::IsolationForest::Online
[Algorithm::Time::ToNumber]: https://metacpan.org/pod/Algorithm::Time::ToNumber
