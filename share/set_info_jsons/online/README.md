# Suricata set prototype JSONs

One file per per-event Suricata set from the top-level README, each an
**online Isolation Forest prototype** for
`Algorithm::Classifier::IsolationForest`. Load one with

```perl
my $model = Algorithm::Classifier::IsolationForest->load_prototype(
    'Geshtinanna_Suricata_dns.json',
    seed => 42,               # optional per-run overrides
);
```

which returns a fresh, unfitted
`Algorithm::Classifier::IsolationForest::Online` model with the set's
feature schema and tuning knobs already stamped in. File names are
`Geshtinanna_Suricata_<set>.json`; the set name is the part after the
prefix.

Every file is `class: "online"` — this pipeline streams events and never
does a batch `fit()`. `new_from_prototype` / `load_prototype` refuse to
build a batch model from an online prototype and vice versa.

`alert`, `anomaly`, `drop`, and `stats` have no file here on purpose: they
are not per-event sets — the first three contribute columns to the planned
host-level model, and `stats` belongs under its own `sensor` slug.

## Prototype layout

Each file is a prototype document (see PROTOTYPES in
`Algorithm::Classifier::IsolationForest`):

- `format` / `version` / `class` — always
  `Algorithm::Classifier::IsolationForest::Prototype`, `1`, `online`.
- `schema_version` / `schema_description` — an opaque revision string and a
  one-line human description, both stamped into any model built from the
  file so it explains itself later.
- `schema` — the variable schema: `feature_names` (column order, honored by
  the writer), `feature_descriptions` (per-column notes drawn from the
  top-level README tables), the `mungers` plan, and the `missing` policy.
- `params` — the online tuning knobs.

## Hyper-parameters

Every file carries the same starting `params`: `n_trees` 100,
`window_size` 4096, `max_leaf_samples` 32, `growth` `adaptive`,
`contamination` 0.01, `seed` 42. Per the top-level README's TODO these are
a starting point, to be tuned per set — the online knobs replace the batch
`sample_size` / `mode` / `voting` / `extension_level` of the earlier draft
(only `n_trees`, `window_size`, `max_leaf_samples`, `growth`, `subsample`,
`contamination`, and `seed` are accepted for an online prototype).

`window_size` is how many of the most recent events the model reflects
before it starts forgetting the oldest; `max_leaf_samples` is the split
threshold (eta). Both want tuning against each set's real event volume: a
low-rate set (arp, ike) sees far fewer events per unit time than a
high-rate one (flow), so a single window length is only a first cut.

## Missing values

`missing` is `zero` on every file. The online model accepts only `die` or
`zero` (unlike the batch model's `nan` / `impute`), so the sparse sets
whose caveats lean on a missing policy — tls certs, ssh hassh, dhcp
extended logging, mqtt per-packet-type sparsity, … — ride `zero` here: an
absent cell learns as `0.0` rather than croaking. This is weaker than the
batch `nan` routing the top-level README describes (a real `0` is a value,
not a "route this point down both branches" signal), so where a sparse
column's zero would be misleading, prefer supplying a sentinel the munger
maps out of the way (e.g. an `enum` `default: -1`) over relying on the
missing policy alone.

## Munger conventions

- **Per-value transforms are mungers**, so the writer hands over raw values:
  entropy / length / `char` / `count` columns read a shared raw source field
  via `from` (e.g. the `dns` set's `domain`, `domain_length`, and
  `label_count` all read the one raw `domain` field the writer supplies);
  heavy-tailed sizes use `log` with `offset` 1; reply codes use the
  `http_enum` / `ftp_enum` / `sip_enum` class mungers; `dest_port` uses
  `bucket` with bounds `[1024, 49152]`.
- **Low-cardinality categoricals with well-known values** use `enum` maps with
  `default: -1`, so an unmapped value lands on its own "rare" point instead of
  croaking the writer.
- **Frequency-encoded columns** (JA3/JA3S/JA4/CYU, HASSH, banners, named
  pipes, vendor classes, interface UUIDs, …) currently use the `hash` munger
  as a placeholder. The intended end state is `frozen_freq_map` with
  per-environment count tables (`unseen => 'rare'`) once baseline counts have
  been collected; `hash` keeps the column numeric and categorical-splittable
  until then.
- **Stateful / derived columns are raw**: rates (`*_rate`, via
  `Algorithm::EventsPerSecond` objects per entity), distinct-counts, first-seen
  booleans, mismatch booleans, flow-join columns (`quic`/`ftp_data`
  duration/bytes), and `time_sin`/`time_cos` (via
  `Algorithm::Time::ToNumber::suricata_to_circle_both`) are computed by the
  writer and passed through unchanged.

## Writer input contract

Where a munged column reads a source field (`from`), the writer must supply
that raw field in the named row it hands the model (`learn_tagged` /
`score_learn_tagged`): `domain` (dns), `url` and `user_agent` (http), `sni`
/ `subject` / `issuer` (tls, quic), `filename` (files, smb, ftp_data, nfs,
tftp), `hostname` (dhcp), `topic` / `client_id` (mqtt), `helo` / `mail_from`
/ `subject` (smtp), `ntlm_host` (smb), `username` (ftp), `cname` / `sname`
(krb5), `cookie` / `client_name` (rdp), `uri_user` (sip), `community`
(snmp), `desktop_name` (rfb), `node_id` (bittorrent-dht), `user` /
`query_length` pre-computed length (pgsql).

Tag names may not contain `.` (the name regexp), so the `flow` set's columns
drop the EVE prefix: `flow.pkts_toserver` → `pkts_toserver`, etc.

All files validate against
`Algorithm::Classifier::IsolationForest->validate_prototype`, and building a
model from each (`new_from_prototype` / `load_prototype`) eagerly compiles
the munger plan against `feature_names`.
