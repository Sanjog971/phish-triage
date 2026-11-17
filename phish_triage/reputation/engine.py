"""Reputation orchestration: approval gates, data-sharing policy, budget, cache, audit."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from ..safety import defang
from ..urls import strip_url
from .providers import REGISTRY, LocalIntel, RepResult


class Cache:
    def __init__(self, path: Path, ttl_hours: float):
        self.path, self.ttl = path, ttl_hours * 3600
        self.data: dict = {}
        self.dirty = False
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            self.data = {}

    @staticmethod
    def key(source: str, t: str, v: str) -> str:
        return f"{source}|{t}|{hashlib.sha256(v.encode()).hexdigest()}"

    def get(self, source, t, v) -> RepResult | None:
        e = self.data.get(self.key(source, t, v))
        if not e or time.time() - e.get("_ts", 0) > self.ttl:
            return None
        r = RepResult(**{k: v2 for k, v2 in e.items() if not k.startswith("_")})
        r.cached = True
        return r

    def put(self, r: RepResult):
        d = r.to_dict()
        d["_ts"] = time.time()
        self.data[self.key(r.source, r.ioc_type, r.value)] = d
        self.dirty = True

    def save(self):
        if not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
        self.dirty = False


class ReputationEngine:
    def __init__(self, cfg: Config, online: bool, only: set[str] | None = None, transport=None,
                 sleep=time.sleep, use_cache: bool = True, max_lookups: int | None = None, verbose: bool = False):
        self.cfg, self.online, self.verbose = cfg, online, verbose
        self.audit: list[dict] = []
        self.notes: list[str] = []          # per-run notes (appended during enrich)
        self.init_notes: list[str] = []     # configuration notes, repeated in every report
        self.providers = []
        self.skipped: list[tuple[str, str]] = []
        self.budget = max_lookups if max_lookups is not None else int(cfg.rep["max_lookups_per_run"])
        self.lookups = 0
        self.policy = cfg.rep.get("url_outbound_policy", "strip_fragment")

        li = cfg.sources.get("local_intel", {})
        self.local = None
        if li.get("enabled", True) and li.get("path"):
            self.local = LocalIntel(cfg.resolve(li["path"]))
            if self.local.error:
                self.init_notes.append(f"local_intel: {self.local.error}")
                self.local = None

        for name, scfg in cfg.sources.items():
            if name == "local_intel":
                continue
            cls = REGISTRY.get(name)
            if cls is None:
                self.skipped.append((name, "unknown source (no provider implementation)"))
                continue
            if not scfg.get("enabled", False):
                self.skipped.append((name, "not approved (enabled = false)"))
                continue
            if not online:
                self.skipped.append((name, "offline run (use --online)"))
                continue
            if only and name not in only:
                self.skipped.append((name, "excluded by --sources"))
                continue
            p = cls(scfg, cfg.rep, self.audit, transport=transport, sleep=sleep)
            ok, why = p.ready()
            if ok:
                self.providers.append(p)
            else:
                self.skipped.append((name, why))
        self.cache = Cache(cfg.resolve(cfg.rep["cache_path"]), float(cfg.rep["cache_ttl_hours"])) \
            if (self.providers and use_cache) else None

    @property
    def mode(self) -> str:
        if not self.online:
            return "offline (local intel only; no external requests)"
        if not self.providers:
            return "online requested, but no approved source is ready (see notes)"
        return "online: " + ", ".join(p.name for p in self.providers)

    def outbound_value(self, ind) -> tuple[str, str | None]:
        if ind.type != "url":
            return ind.value, None
        if "recipient-identifier" in ind.tags or self.policy == "strip_query":
            v = strip_url(ind.value, query=True, fragment=True)
            return v, "query/fragment stripped before lookup"
        if self.policy == "strip_fragment":
            v = strip_url(ind.value, query=False, fragment=True)
            return v, ("fragment stripped before lookup" if v != ind.value else None)
        return ind.value, None

    def _log(self, msg: str):
        if self.verbose:
            print(msg, file=sys.stderr)

    def enrich(self, indicators) -> None:
        exhausted = False
        for ind in indicators:
            if self.local:
                r = self.local.match(ind)
                if r:
                    ind.reputation.append(r)
            if not self.providers or not ind.lookup_eligible:
                continue
            value, note = self.outbound_value(ind)
            for p in self.providers:
                if not p.accepts(ind.type):
                    continue
                cached = self.cache.get(p.name, ind.type, value) if self.cache else None
                if cached:
                    ind.reputation.append(cached)
                    continue
                if self.lookups >= self.budget:
                    exhausted = True
                    continue
                self.lookups += 1
                self._log(f"  [lookup] {p.name:<20} {ind.type:<6} {defang(value, ind.type)}")
                r = p.lookup(ind.type, value)
                if note:
                    r.summary += f" ({note})"
                ind.reputation.append(r)
                if self.cache and r.status not in ("error", "blocked"):
                    self.cache.put(r)
        if exhausted:
            self.notes.append(f"lookup budget of {self.budget} reached; some indicators were not checked")
        if self.cache:
            self.cache.save()

    def describe(self) -> list[dict]:
        rows = [{"source": "local_intel", "approved": bool(self.local), "ready": bool(self.local),
                 "detail": str(self.cfg.resolve(self.cfg.sources.get("local_intel", {}).get("path", "")))}]
        for p in self.providers:
            rows.append({"source": p.name, "approved": True, "ready": True,
                         "detail": "shares " + ", ".join(sorted(p.share))})
        for name, why in self.skipped:
            rows.append({"source": name, "approved": "not approved" not in why, "ready": False, "detail": why})
        return rows


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
