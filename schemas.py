"""schemas.py — API response models (field names camelCase hain taake TS frontend se match karein)."""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel


# ── Dashboard ────────────────────────────────────────────────
class DashboardKPIs(BaseModel):
    totalConsumers: int                      # registered accounts
    totalConsumptionKwh: float               # sab consumers ki total kWh (mode: latest/all uploads)
    consumptionScopeLabel: str               # "kWh (latest)" | "kWh (all uploads)"
    consumptionChangePct: Optional[float]    # pichle month (same days) se change %
    activeMembers: int                       # registered + Active accounts
    registeredCount: int                     # consumers collection ke total accounts
    activePct: float                         # activeMembers / registeredCount
    highRiskConsumers: int
    highRiskPct: float
    theftCases: int                          # active (unresolved) cases
    revenueLoss: float                       # PKR, estimated monthly
    revenueLossFormatted: str
    casesResolved: int                       # is month resolved
    casesResolvedChangePct: Optional[float]
    tariffPkrPerKwh: float


class ChartPoint(BaseModel):
    date: str        # ISO "2026-02-09"
    label: str       # "Feb 09"
    normal: float    # blue line
    theft: float     # red line


class ConsumptionChart(BaseModel):
    points: List[ChartPoint]
    spikeRatio: Optional[float]
    windowStart: str
    windowEnd: str


class DashboardResponse(BaseModel):
    kpis: DashboardKPIs
    chart: ConsumptionChart
    generatedAt: str


# ── Risks list ───────────────────────────────────────────────
class ConsumerSummary(BaseModel):
    id: str                  # Firestore document id (navigation ke liye)
    consumerId: str          # "CON001"
    name: str
    meterNumber: str
    location: str
    riskScore: int
    riskLevel: str           # High | Medium | Low
    consumption: float       # kWh (is month)
    anomaly: float           # % anomaly
    status: str              # Active | Inactive


class RiskListResponse(BaseModel):
    total: int
    counts: Dict[str, int]   # {"All": n, "High": n, "Medium": n, "Low": n}
    items: List[ConsumerSummary]


# ── Consumer profile ─────────────────────────────────────────
class HistoryPoint(BaseModel):
    date: str
    label: str
    value: float


class TheftFlag(BaseModel):
    type: str
    date: str
    severity: str


class CaseItem(BaseModel):
    id: str
    caseNumber: str
    description: str
    status: str
    createdAt: str


class ConsumerProfile(ConsumerSummary):
    email: str
    phone: str
    cnic: str
    address: str
    lastReading: Optional[str]
    prediction: str          # ML result: "No Theft" / "Theft"
    estimatedBill: float     # PKR (latest upload)
    dateRange: str           # latest upload ka period
    consumptionHistory: List[HistoryPoint]
    theftFlags: List[TheftFlag]
    cases: List[CaseItem]


# ── Notifications ────────────────────────────────────────────
class NotificationItem(BaseModel):
    id: str
    type: str                       # case_filed | case_escalated | case_resolved | theft_detected | query | alert
    title: str
    message: str
    severity: str                   # high | medium | low | info
    createdAt: Optional[str]
    read: bool
    consumerName: str
    consumerId: str
    consumerKey: Optional[str]      # profile kholne ke liye (ConsumerProfileScreen ?id=)
    caseId: Optional[str]


class NotificationsResponse(BaseModel):
    unreadCount: int
    total: int
    items: List[NotificationItem]


class MarkReadRequest(BaseModel):
    ids: List[str] = []
    markAll: bool = False


class OkResponse(BaseModel):
    ok: bool


# ── Case Management (Cases / Case Profile / Create / Escalate) ──
class CaseSummary(BaseModel):
    id: str
    caseNumber: str
    consumerId: str
    consumerName: str
    area: str
    status: str                      # Open | In Progress | Closed | Rejected
    riskLevel: str                   # Low | Medium | High | Critical
    category: str
    description: str
    inspector: Optional[str] = None
    createdAt: str
    evidences: int


class CasesListResponse(BaseModel):
    total: int
    counts: Dict[str, int]           # {"Open": n, "In Progress": n, "Closed": n, "Rejected": n}
    items: List[CaseSummary]


class TimelineEntry(BaseModel):
    action: str
    date: str
    time: str


class EvidenceItem(BaseModel):
    name: str
    type: str                        # image | document
    url: str
    uploadedBy: Optional[str] = None
    date: Optional[str] = None


class CaseDetail(CaseSummary):
    priority: str
    meterNumber: Optional[str] = None
    timeline: List[TimelineEntry] = []
    evidence: List[EvidenceItem] = []


class AssignInspectorRequest(BaseModel):
    inspector: str


class InspectorItem(BaseModel):
    id: str
    name: str
    area: str
    available: bool


class InspectorsResponse(BaseModel):
    items: List[InspectorItem]


# ── Consumer-facing notifications ("me" endpoints) ───────────
class MyNotificationItem(BaseModel):
    id: str
    type: str
    title: str
    message: str
    caseId: Optional[str] = None
    read: bool
    createdAt: Optional[str] = None


class MyNotificationsResponse(BaseModel):
    items: List[MyNotificationItem]


class MarkMyReadRequest(BaseModel):
    ids: List[str] = []


# ── Reports & Analytics ──────────────────────────────────────
class StatValue(BaseModel):
    value: float
    changePct: float                 # pichli period se % change (negative ho sakta hai)


class ReportStats(BaseModel):
    totalCases: StatValue
    revenueLoss: StatValue           # PKR
    detectionRate: StatValue         # 0-100
    avgResponseHours: StatValue      # ghante


class RiskDistribution(BaseModel):
    low: int
    medium: int
    high: int


class AreaCases(BaseModel):
    area: str
    cases: int


class AreaLoss(BaseModel):
    area: str
    amount: float                    # PKR


class InsightItem(BaseModel):
    id: str
    type: str                        # alert | success | savings | info
    title: str
    subtitle: str


class ReportsSummaryResponse(BaseModel):
    period: str                      # 7d | 30d | 3m
    periodLabel: str
    windowStart: str
    windowEnd: str
    stats: ReportStats
    riskDistribution: RiskDistribution
    areaTheft: List[AreaCases]
    revenueLossByArea: List[AreaLoss]
    insights: List[InsightItem]
    generatedAt: str


# ── System Alerts ────────────────────────────────────────────
class AlertItem(BaseModel):
    id: str
    severity: str                    # critical | warning | info
    title: str
    message: str
    createdAt: str                   # ISO 8601 UTC ("...Z" / +00:00)


class AlertsResponse(BaseModel):
    activeCount: int
    alerts: List[AlertItem]