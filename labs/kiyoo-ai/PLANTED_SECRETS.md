# Planted secrets inventory — kiyoo-ai lab

Every "secret" this lab serves is shaped correctly but provably fake
. None of these is a live credential. If any of them are ever
reported as a real leak by a scanner or a person, that's this lab working
as intended — point them here.

| Value | Served at | Shape matches | Real? |
|---|---|---|---|
| `sk-ant-api03-LABFAKE00000000000000000000000000000000000000AA` | `git.kiyoo-ai.lab/.env` | Anthropic API key | No — `LABFAKE` marker, never issued |
| `sk-LABFAKE000000000000000000000000000000000000` | `git.kiyoo-ai.lab/.env` | OpenAI API key | No — `LABFAKE` marker, never issued |
| `postgres://labfake:labfake@localhost/labfake` | `git.kiyoo-ai.lab/.env` | Postgres connection string | No — points at nothing real |
| `sentiment-v2.pkl` (4098 bytes, pickle magic header + random bytes) | `models.kiyoo-ai.lab/sentiment-v2.pkl` | A pickle-format model artifact | No — not a valid pickle stream, never deserialized by anything in this lab |
| MySQL 5.7.29 handshake packet | `db.kiyoo-ai.lab:3306` | A real MySQL protocol greeting | The greeting is real bytes; there is no server behind it — no auth handler, no data |
| `invoices-2026-q1.pdf` (referenced only, not served) | `files.kiyoo-ai.lab` listing | An S3 object key | No such file exists; listing only |

If you add a new fake secret to this lab, add it here in the same commit.
