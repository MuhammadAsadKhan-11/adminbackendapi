"""simulate_case.py — consumer app ki taraf se naya case/query bana kar LIVE notification test karta hai.

Backend chal raha ho, app khuli ho (Dashboard par bell dikh raha ho), phir doosre terminal se:

    python simulate_case.py
    python simulate_case.py --consumer 54321 --type meter_tampering --text "Meter ki seal toot gayi hai"
    python simulate_case.py --escalate            # case escalated bhi mark karo

Kuch second mai bell par badge +1 hona chahiye aur notifications list mai naya case aa jana chahiye.
Yeh doc isSeed=true ke saath banta hai, isliye `python seed_data.py --clear` isay delete kar deta hai.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timezone

from google.cloud.firestore_v1.base_query import FieldFilter

from core import get_db, get_settings

ISSUE_TYPES = {
    "unusual_bill": "Unusual Bill Amount",
    "meter_tampering": "Meter Tampering",
    "power_outage": "Power Outage",
    "billing_query": "Billing Query",
}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--consumer", default="54321", help="consumerId (jaise 54321)")
    p.add_argument("--type", default="unusual_bill", choices=sorted(ISSUE_TYPES), help="issueValue")
    p.add_argument("--text", default="Bill bohat zyada aaya hai jabke consumption kam thi")
    p.add_argument("--location", default="I8")
    p.add_argument("--escalate", action="store_true")
    args = p.parse_args()

    s = get_settings()
    db = get_db()

    # consumer ka naam/email consumers collection se (agar mile)
    name, email = "Test Consumer", f"{args.consumer}@example.com"
    q = db.collection(s.consumers_collection).where(filter=FieldFilter("consumerId", "==", args.consumer)).limit(1)
    for snap in q.stream():
        d = snap.to_dict() or {}
        name = d.get("fullName") or name
        email = d.get("email") or email

    case_id = f"RPT-{random.randint(5000, 9999)}"
    doc = {
        "caseId": case_id,
        "consumerId": args.consumer,
        "consumerName": name,
        "consumerEmail": email,
        "issueType": ISSUE_TYPES[args.type],
        "issueValue": args.type,
        "description": args.text,
        "currentStatus": "Under Investigation",
        "location": args.location,
        "escalated": bool(args.escalate),
        "resolution": "",
        "assignedInspector": "",
        "riskLevel": "High" if args.escalate else "Low",
        "createdAt": datetime.now(timezone.utc),
        "isSeed": True,
    }
    ref = db.collection(s.cases_collection).document()
    ref.set(doc)
    print(f"Case {case_id} bana diya ({name}, {ISSUE_TYPES[args.type]}) — doc id: {ref.id}")


if __name__ == "__main__":
    main()
