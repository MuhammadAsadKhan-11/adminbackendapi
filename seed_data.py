"""seed_data.py — Firestore mai TEST data daalta hai, tumhari asli schema jaisa:
  consumers, consumptions (csvRaw ke saath), cases

    python seed_data.py            # sample data likho
    python seed_data.py --clear    # sirf seed kiya hua data delete karo (isSeed == True)

WARNING: yeh script tumhari .env wali collections mai likhti hai. Real project par chalane
se pehle test Firebase project use karo, ya baad mai --clear chalao.
Real docs ko --clear haath nahi lagata (sirf isSeed == True wale delete hote hain).
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

from google.cloud.firestore_v1.base_query import FieldFilter

from core import get_db, get_settings, local_tz

PERIOD_DAYS = 26

# name, consumerId, area, address, phone, base kWh/day, riskScore, theft?
REGISTERED = [
    ("Ahmed Ali",     "54001", "Blue Area",   "123 Main Street, Blue Area",      "+92 302 1234567", 3.2, 92, True),
    ("Bilal Qureshi", "54002", "DHA",         "House 45, Street 7, DHA Phase 2", "+92 300 7654321", 3.8, 88, True),
    ("Sarah Khan",    "54003", "G-15",        "House 12, Sector G-15",           "+92 321 5550123", 2.8, 75, False),
    ("Usman Tariq",   "54004", "F-10",        "Flat 8, Markaz F-10",             "+92 333 4445566", 2.2, 58, False),
    ("Ayesha Malik",  "54005", "I-8",         "House 90, Street 3, I-8/2",       "+92 345 9876543", 1.8, 31, False),
    ("Hamza Sheikh",  "54006", "Bahria Town", "Villa 21, Bahria Town Phase 4",   "+92 311 2223344", 2.5, 1,  False),
]

CASES = [
    # caseId, consumerId, issueType, issueValue, description, currentStatus, location, created N days ago, resolved N days ago
    ("RPT-4011", "54001", "Meter Tampering", "meter_tampering", "Meter seal looks broken", "Under Investigation", "Blue Area", 5, None),
    ("RPT-4012", "54002", "Unusual Bill Amount", "unusual_bill", "Bill is much higher than usual", "Under Investigation", "DHA", 3, None),
    ("RPT-4001", "54001", "Unusual Bill Amount", "unusual_bill", "Bill dispute", "Closed", "Blue Area", 45, 40),
    ("RPT-4002", "54003", "Meter Tampering", "meter_tampering", "Billing mismatch verified on site", "Resolved", "G-15", 9, 2),
]


def _local_noon(day_offset: int) -> datetime:
    d = datetime.now(local_tz()).date() - timedelta(days=day_offset)
    return datetime(d.year, d.month, d.day, 12, 0, tzinfo=local_tz())


def _csv_wide(days, values) -> str:
    """Wide layout: pehli line dates (MM/DD/YYYY), doosri line values."""
    header = ",".join(d.strftime("%m/%d/%Y") for d in days)
    row = ",".join(f"{v:.1f}" for v in values)
    return f"{header}\n{row}"


def _make_upload(rnd, cid, name, email, base, score, theft, end_offset, uploaded_offset):
    """end_offset = period ka aakhri din (aaj se kitne din pehle)."""
    days = [
        (_local_noon(end_offset + (PERIOD_DAYS - 1 - i))).date() for i in range(PERIOD_DAYS)
    ]
    values = []
    for i in range(PERIOD_DAYS):
        f = 1.0
        if theft and i >= PERIOD_DAYS - 7:
            f = 1.0 + (i - (PERIOD_DAYS - 8)) * 0.25  # aakhri hafte mai spike
        values.append(max(0.1, base * f * (1 + rnd.uniform(-0.08, 0.08))))
    total = round(sum(values), 1)
    return {
        "consumerId": cid,
        "consumerName": name,
        "email": email,
        "avgUnits": round(total / PERIOD_DAYS, 1),
        "totalUnits": total,
        "estimatedBill": round(total * rnd.uniform(18, 24)),
        "prediction": "Theft" if theft else "No Theft",
        "riskScore": score,
        "dateRange": f"{days[0].strftime('%m/%d/%Y')} – {days[-1].strftime('%m/%d/%Y')}",
        "csvRaw": _csv_wide(days, values),
        "uploadedAt": _local_noon(uploaded_offset),
    }


def seed() -> None:
    s = get_settings()
    db = get_db()
    rnd = random.Random(42)
    now = datetime.now(timezone.utc)
    batch = db.batch()
    n = 0

    def put(collection: str, doc_id: str, data: dict) -> None:
        nonlocal batch, n
        data["isSeed"] = True
        batch.set(db.collection(collection).document(doc_id), data)
        n += 1
        if n % 300 == 0:  # Firestore batch limit 500
            batch.commit()
            batch = db.batch()

    for name, cid, area, address, phone, base, score, theft in REGISTERED:
        email = f"{name.lower().replace(' ', '.')}@example.com"
        put(
            s.consumers_collection,
            f"seed_{cid}",
            {
                "fullName": name,
                "email": email,
                "mobileNumber": phone,
                "cnicNumber": f"3520{rnd.randint(1000000000, 9999999999)}",
                "consumerId": cid,
                "address": address,
                "area": area,
                "role": "consumer",
                "createdAt": now - timedelta(days=200),
            },
        )
        # purani upload (pichla period, kam consumption) + latest upload
        put(
            s.consumptions_collection,
            f"seed_{cid}_prev",
            _make_upload(rnd, cid, name, email, base * 0.9, max(score - 20, 0), False, PERIOD_DAYS + 1, PERIOD_DAYS + 1),
        )
        put(
            s.consumptions_collection,
            f"seed_{cid}_latest",
            _make_upload(rnd, cid, name, email, base, score, theft, 1, 0),
        )

    # Registered lekin abhi tak koi CSV upload nahi
    put(
        s.consumers_collection,
        "seed_54007",
        {
            "fullName": "Zara Noor",
            "email": "zara.noor@example.com",
            "mobileNumber": "+92 300 1112233",
            "consumerId": "54007",
            "role": "consumer",
            "createdAt": now - timedelta(days=30),
        },
    )

    # Upload hai lekin consumers collection mai account nahi (tumhare "54321" doc jaisa)
    put(
        s.consumptions_collection,
        "seed_54321_latest",
        _make_upload(rnd, "54321", "muhammad asad khan", "asad@example.com", 3.0, 1, False, 1, 3),
    )

    for case_id, cid, issue_type, issue_value, desc, status, location, created_ago, resolved_ago in CASES:
        data = {
            "caseId": case_id,
            "consumerId": cid,
            "consumerEmail": f"{cid}@example.com",
            "issueType": issue_type,
            "issueValue": issue_value,
            "description": desc,
            "currentStatus": status,
            "location": location,
            "escalated": False,
            "resolution": "",
            "assignedInspector": "",
            "createdAt": _local_noon(created_ago),
            # asli docs mai imageUrl bada base64 hota hai — projection test ke liye
            "imageUrl": "data:image/jpeg;base64," + "A" * 5000,
        }
        if resolved_ago is not None:
            data["resolvedAt"] = _local_noon(resolved_ago)
        put(s.cases_collection, f"seed_{case_id}", data)

    batch.commit()
    print(f"Seeded {n} documents.")


def clear() -> None:
    s = get_settings()
    db = get_db()
    total = 0
    for name in (s.consumers_collection, s.consumptions_collection, s.cases_collection):
        for snap in db.collection(name).where(filter=FieldFilter("isSeed", "==", True)).stream():
            snap.reference.delete()
            total += 1
    print(f"Deleted {total} seeded documents.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--clear", action="store_true", help="seed kiya hua data delete karo")
    args = parser.parse_args()
    clear() if args.clear else seed()
