# telegram_collector (INTEL-002)

Observation-only ingestion of **approved** Telegram groups. Reads message
history/stream from a lawfully-authorized Telethon user session and publishes
`telegram.raw` envelopes into the pipeline (`sanitizer` → `analysis` → `ai_layer`
→ `db_writer`).

## Hard constraints (do not remove)
- **Read-only.** Uses only Telethon read methods (`get_entity`, `iter_messages`,
  `get_participants`). There is **no** send/post/reply/DM path. (TG-G3 / ARCH-001.)
- **No infiltration tooling.** No persona fabrication, vetting-bypass, ban evasion,
  or deception-based entry. `public_link` groups are joined openly (anyone can);
  all other groups are read from a session that is **already a lawful member**,
  access obtained out-of-band under documented legal authority.
- **Gated.** Only groups with `status='approved'` AND a `legal_basis_ref` are
  collected — enforced by the DB constraint `telegram_groups_legal_basis_required`
  and re-checked in `load_approved_groups()`. (TG-G2.)

## Configuration (out-of-band; never committed)
| Env | Meaning |
|-----|---------|
| `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` | Telegram app credentials |
| `TELEGRAM_SESSION` | StringSession for an **authorized** account |
| `TELEGRAM_USE_TOR` | egress via the Tor gateway (default `true`) |
| `TELEGRAM_HISTORY_LIMIT` | per-cycle backfill cap (default 500) |
| `TELEGRAM_POLL_INTERVAL` | seconds between cycles (default 300) |

With any of the three credentials missing, the service logs
`telegram_collector_unconfigured` and **idles** (it does not crash-loop).

## Incremental dedup
Per-group last-seen message id is persisted to `COLLECTOR_STATE_FILE` on the
`collector_state` volume; only `id > high_water` is fetched. The DB also enforces
`UNIQUE (tg_group_id, tg_message_id)`.

## Kill switch
Honors a `control.collection` fanout (`{"action":"disable"|"enable"}`), mirroring
the AI layer's `control.ai`.

## Not yet wired (follow-ups)
- `sanitizer` consume of `telegram.raw` (T1.3).
- `db_writer` persistence into `telegram_messages` + Neo4j actor/edge upserts (T1.4 / T2.2).
- `analysis` reply/mention/forward edge extraction (T2.1).
