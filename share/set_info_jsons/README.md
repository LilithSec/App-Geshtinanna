# Suricata set prototype JSONs

One prototype JSON per per-event Suricata set from the top-level README, split
into two directories by how the set's model is trained:

- **[`online/`](online/)** — streaming Isolation Forest prototypes
  (`class: "online"`). This is the default pipeline: events are `learn`ed as
  they arrive and the oldest are forgotten past `window_size`; there is no
  batch `fit()`. Served by
  `Algorithm::Classifier::IsolationForest::Zorita::Online`, fed by
  `App::Geshtinanna::Suricata` when a flow's `type = "online"`.
- **[`batch/`](batch/)** — classic Isolation Forest prototypes
  (`class: "batch"`) derived from the online ones. Rows are appended to disk by
  `Algorithm::Classifier::IsolationForest::Zorita::Writer`, rolled up, and
  `fit()` on a schedule via `rebuild_model`. Fed by
  `App::Geshtinanna::Suricata` when a flow's `type = "batch"`.

Both directories carry the same feature schema (the `feature_names`, munger
plan, and `missing` policy) for a given set — they differ only in `class`, the
`missing` policy (`zero` online vs. `nan` batch), and the hyper-parameter block
(streaming `window_size` / `max_leaf_samples` / `growth` vs. classic
`sample_size` / `mode` / `extension_level` / `voting`).

## Keeping the two in sync

`online/` is the source of truth. The batch twins are generated from it:

```sh
perl maint/online2batch.pl          # (re)write batch/*.json from online/*.json
perl maint/online2batch.pl --check  # non-zero exit if any batch file is stale
```

The generated batch params are mechanical defaults, not hand-tuned — per the
top-level README's TODO they are a starting point to be gone over per set. Edit
a set's schema in `online/` and re-run the generator; only tune the batch
`params` directly if a set genuinely needs different batch knobs.

See [`online/README.md`](online/README.md) for the prototype layout, munger
conventions, and the writer input contract — all of it applies to both
directories except the class / missing / params differences noted above.
