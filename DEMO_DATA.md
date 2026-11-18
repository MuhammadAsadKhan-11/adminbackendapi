# Reports / Dashboard demo data

`seed_reports_demo.py` fills the Admin Dashboard and Reports charts with realistic,
clearly-marked demo records. It uses the existing Firestore collections and document
shapes (nothing new is created) and the Firebase Admin credentials already configured
for this backend (`FIREBASE_CREDENTIALS_PATH` or `FIREBASE_CREDENTIALS_JSON` in `.env`).
Nothing runs automatically — the script must be started by hand.

| Collection     | Documents | What                                                                 |
|----------------|-----------|----------------------------------------------------------------------|
| `consumptions` | 100       | Detection results: 50 Low / 30 Medium / 20 High, 14 days of readings each |
| `cases`        | 34        | Theft cases: G-10 12, G-11 7, G-13 4, I-8 9, F-10 2                  |

Every document has `isDemo: true`, `seedBatchId: "electraguard-reports-demo-v1"` and a
fixed id starting with `demo-v1-`. Risk scores sit inside the existing thresholds
(`MEDIUM_RISK_THRESHOLD`, `HIGH_RISK_THRESHOLD`); no model threshold is changed.

## Commands (run inside `electraguard_admin_api/`)

```
venv\Scripts\python seed_reports_demo.py --dry-run     # show what would be written
venv\Scripts\python seed_reports_demo.py               # seed (does nothing if already seeded)
venv\Scripts\python seed_reports_demo.py --refresh     # rewrite the batch with today's dates
venv\Scripts\python seed_reports_demo.py --remove --dry-run
venv\Scripts\python seed_reports_demo.py --remove      # delete ONLY this demo batch
```

Safety: before writing, the script checks every target id. If any of them holds a
document that is not part of this demo batch, it stops and writes nothing. `--remove`
deletes only documents with `isDemo == true` and `seedBatchId == "electraguard-reports-demo-v1"`.

The demo data covers the 14 days up to the day it was seeded. The "Last 7 days" reports
window moves forward each day, so run `--refresh` before a presentation.
