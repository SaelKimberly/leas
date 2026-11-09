# NPVT test fixtures

These are real client exports, not generated data. They decrypt to live server
credentials and exist only to pin the parser to the app's actual wire format.

| File | Source | Secret |
|---|---|---|
| `legacy.npvt` | supplied by the project owner, NapsterV 124.0.37 export | none; legacy whitebox only |
| `passphrase.npvs` | public SiNAVM channel sample (1,017 bytes) | passphrase `@sinavm` |

The larger samples stay under `thirdparty/npvt/samples/` and are not committed.
Do not add more live-credential fixtures here; prefer a synthetic vector unless
app compatibility is the property under test. The provenance and licensing note
is in `docs/reference/npvt.md` §7.
