"""End-to-end pipeline for one sample: parse -> extract -> enrich -> evaluate -> score."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Config
from .heuristics import Finding, evaluate
from .indicators import IndicatorSet, extract_indicators
from .parse import ParsedEmail, parse_file
from .reputation import ReputationEngine
from .scoring import Verdict, score


@dataclass
class AnalysisResult:
    case_id: str
    analyzed_at: datetime
    tool_version: str
    pe: ParsedEmail
    iocs: IndicatorSet
    findings: list[Finding]
    verdict: Verdict
    reputation_mode: str
    sources: list[dict]
    audit: list[dict]
    notes: list[str] = field(default_factory=list)
    redact: bool = True


def default_case_id(pe: ParsedEmail, when: datetime) -> str:
    return f"PHISH-{when:%Y%m%d}-{pe.file_sha256[:8]}"


def analyze(path: str | Path, cfg: Config, engine: ReputationEngine, case_id: str | None = None) -> AnalysisResult:
    when = datetime.now(timezone.utc)
    pe = parse_file(path, cfg)
    iocs = extract_indicators(pe, cfg)
    audit_start, notes_start = len(engine.audit), len(engine.notes)
    engine.enrich(iocs.all())
    findings = evaluate(pe, iocs, cfg)
    checked = any(r.source != "local_intel" and r.status in ("no_detection", "not_found")
                  for i in iocs.all() for r in i.reputation)
    verdict = score(findings, checked, bool(iocs.of_type("url")),
                    any(a.detected_type != "message/rfc822" for a in pe.attachments))
    return AnalysisResult(
        case_id=case_id or default_case_id(pe, when), analyzed_at=when, tool_version=__version__,
        pe=pe, iocs=iocs, findings=findings, verdict=verdict, reputation_mode=engine.mode,
        sources=engine.describe(), audit=engine.audit[audit_start:],
        notes=engine.init_notes + engine.notes[notes_start:],
        redact=bool(cfg.analysis["redact_recipients"]),
    )
