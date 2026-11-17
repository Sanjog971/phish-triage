"""Command-line interface.

  phish-triage analyze SAMPLE.eml [more.eml | DIR ...] [--online] [-o reports/]
  phish-triage sources            # show approved sources, keys and what each may receive
  phish-triage defang|refang VALUE...
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze
from .config import load_config
from .parse import InputRejected
from .report import write_outputs
from .reputation import REGISTRY, ReputationEngine
from .safety import defang, refang

DEFAULT_CONFIG = Path("config/triage.toml")


def _config(path: str | None):
    if path:
        return load_config(path)
    return load_config(DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else None)


def _collect(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out += sorted(x for x in p.iterdir() if x.suffix.lower() == ".eml" and x.is_file())
        elif p.is_file():
            out.append(p)
        else:
            print(f"warning: {p} not found", file=sys.stderr)
    return out


def cmd_analyze(args) -> int:
    cfg = _config(args.config)
    if args.no_unwrap:
        cfg.analysis["unwrap_reported_messages"] = False
    if args.no_redact:
        cfg.analysis["redact_recipients"] = False
    only = set(args.sources.split(",")) if args.sources else None
    engine = ReputationEngine(cfg, online=args.online, only=only, use_cache=not args.no_cache,
                              max_lookups=args.max_lookups, verbose=not args.quiet)
    files = _collect(args.paths)
    if not files:
        print("no .eml files to analyze", file=sys.stderr)
        return 1
    formats = set(args.format.split(","))
    outroot = Path(args.out)
    rc, rows = 0, []
    if not args.quiet:
        print(f"phish-triage {__version__} · reputation: {engine.mode}", file=sys.stderr)
    for n, f in enumerate(files, 1):
        case_id = None
        if args.case_id:
            case_id = args.case_id if len(files) == 1 else f"{args.case_id}-{n:02d}"
        try:
            if not args.quiet:
                print(f"[{n}/{len(files)}] {f.name}", file=sys.stderr)
            res = analyze(f, cfg, engine, case_id)
        except InputRejected as e:
            print(f"  rejected: {e}", file=sys.stderr)
            rc = 1
            continue
        except Exception as e:  # keep the batch going; report the failure
            print(f"  error: {type(e).__name__}: {e}", file=sys.stderr)
            rc = 1
            continue
        written = write_outputs(res, outroot / res.case_id, cfg.org["internal_domains"], formats)
        top = next((x.title for x in res.findings if x.severity in ("high", "medium")), "-")
        rows.append((f.name, res.verdict.label, res.verdict.score, top, written.get("md") or next(iter(written.values()), "")))
    if rows:
        w = max(len(r[0]) for r in rows)
        print(f"\n{'sample'.ljust(w)}  {'verdict':<16} score  top finding")
        for name, label, sc, top, path in rows:
            print(f"{name.ljust(w)}  {label:<16} {sc:>5}  {top}")
        print(f"\nreports written under {outroot.resolve()}")
    return rc


def cmd_sources(args) -> int:
    cfg = _config(args.config)
    import os
    print(f"config: {cfg.source or '(built-in defaults)'}\n")
    print(f"{'source':<22}{'approved':<10}{'api key':<26}{'may receive':<28}lookup endpoints")
    li = cfg.sources.get("local_intel", {})
    print(f"{'local_intel':<22}{('yes' if li.get('enabled', True) else 'no'):<10}{'n/a (offline)':<26}"
          f"{'all types (stays local)':<28}{cfg.resolve(li.get('path', ''))}")
    for name, cls in REGISTRY.items():
        scfg = cfg.sources.get(name, {})
        env = scfg.get("api_key_env", cls.default_key_env)
        key = f"{env} {'set' if os.environ.get(env) else 'MISSING'}"
        share = sorted(set(scfg.get("share", sorted(cls.supports))) & set(cls.supports))
        eps = ", ".join(sorted({f"{e.method} {e.host}{e.path_prefix}" for e in cls.endpoints}))
        print(f"{name:<22}{('yes' if scfg.get('enabled') else 'no'):<10}{key:<26}{','.join(share):<28}{eps}")
    print("\nEmail addresses are never sent externally. Reserved/sanitized, internal, private and"
          "\nfree-mail indicators are never sent. Nothing is sent at all without --online.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phish-triage", description="Static, safety-first phishing triage.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze one or more .eml files or directories")
    a.add_argument("paths", nargs="+")
    a.add_argument("-c", "--config", help=f"TOML config (default: {DEFAULT_CONFIG} if present)")
    a.add_argument("-o", "--out", default="reports", help="output root directory (default: reports)")
    a.add_argument("--online", action="store_true", help="allow lookups against APPROVED sources")
    a.add_argument("--sources", help="comma list to restrict online sources (e.g. virustotal,urlhaus)")
    a.add_argument("--max-lookups", type=int, help="cap external requests for this run")
    a.add_argument("--no-cache", action="store_true", help="ignore the reputation cache")
    a.add_argument("--case-id", help="case identifier (batch runs get -01, -02 ... suffixes)")
    a.add_argument("--format", default="md,json,csv,kql", help="outputs to write (default: md,json,csv,kql)")
    a.add_argument("--no-unwrap", action="store_true", help="analyze the outer message even if it wraps a reported email")
    a.add_argument("--no-redact", action="store_true", help="do not redact recipient addresses in reports")
    a.add_argument("-q", "--quiet", action="store_true")
    a.set_defaults(func=cmd_analyze)

    s = sub.add_parser("sources", help="list reputation sources, approval and data-sharing policy")
    s.add_argument("-c", "--config")
    s.set_defaults(func=cmd_sources)

    d = sub.add_parser("defang", help="defang indicators for safe sharing")
    d.add_argument("values", nargs="+")
    d.set_defaults(func=lambda x: print("\n".join(defang(v) for v in x.values)) or 0)
    r = sub.add_parser("refang", help="restore defanged indicators")
    r.add_argument("values", nargs="+")
    r.set_defaults(func=lambda x: print("\n".join(refang(v) for v in x.values)) or 0)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
