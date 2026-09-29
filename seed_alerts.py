"""seed_alerts.py — ek sample "System Maintenance" alert Firestore (systemAlerts) mai daalta hai.

Run (ek baar):  python seed_alerts.py
Baad mai alerts Firebase Console se bhi add/edit/hata sakte ho:
    title, message, severity (critical | warning | info), createdAt (timestamp),
    active (false karo to alert screen se hat jata hai)
"""
from datetime import datetime, timezone

from core import get_db, get_settings, init_firebase

init_firebase()
ref = get_db().collection(get_settings().alerts_collection).document("maintenance-sample")
ref.set(
    {
        "title": "System Maintenance",
        "message": "Scheduled maintenance on Sep 30, 2026 from 2 AM - 4 AM",
        "severity": "info",
        "active": True,
        "createdAt": datetime.now(timezone.utc),
    }
)
print("Sample alert added to", get_settings().alerts_collection)
