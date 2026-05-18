"""
scan.py — multi-format malware scanner CLI.

Auto-detects file type (PE / PowerShell / Office / PDF) and routes to the
appropriate pipeline. Same output shape across pipelines: verdict,
confidence %, and top reasons.

Usage:  python scan.py <path>
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import lightgbm as lgb

# Repo layout: src/ is a sibling of scan.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from router import (  # noqa: E402
    detect_file_type, FILE_PE, FILE_PS1, FILE_OFFICE, FILE_PDF, FILE_UNKNOWN,
)
from features_ember import PEFeatureExtractor, feature_name  # noqa: E402
from extractor import extract as rich_extract  # noqa: E402
from ps1_extractor import extract_path as ps1_extract, FEATURE_NAMES as PS1_FEATURE_NAMES  # noqa: E402
import office_scanner  # noqa: E402
import pdf_scanner  # noqa: E402
from virustotal import maybe_lookup_for_path, render_cli_block  # noqa: E402


HERE = os.path.dirname(os.path.abspath(__file__))
PE_MODEL_PATH = os.path.join(HERE, "models", "model.lgbm")
PS1_MODEL_PATH = os.path.join(HERE, "models", "ps1_model.lgbm")
PE_THRESHOLD = 0.5
PS1_THRESHOLD = 0.5


# ---------- Per-pipeline scans ----------------------------------------------

def _scan_pe(path: str) -> int:
    if not os.path.isfile(PE_MODEL_PATH):
        print(f"error: PE model {PE_MODEL_PATH} not found. run: python -m src.train", file=sys.stderr)
        return 2
    with open(path, "rb") as f:
        bytez = f.read()

    print(f"[*] type=PE  {path}  ({len(bytez):,} bytes)")
    extractor = PEFeatureExtractor()
    x = extractor.feature_vector(bytez).reshape(1, -1)

    model = lgb.Booster(model_file=PE_MODEL_PATH)
    prob = float(model.predict(x)[0])
    verdict = "MALICIOUS" if prob >= PE_THRESHOLD else "CLEAN"
    confidence = prob if verdict == "MALICIOUS" else (1.0 - prob)

    contribs = model.predict(x, pred_contrib=True)[0][:-1]
    ranked = np.argsort(-contribs) if verdict == "MALICIOUS" else np.argsort(contribs)

    top5 = []
    for idx in ranked[:5]:
        label = feature_name(int(idx))
        top5.append((label, float(x[0, idx]), float(contribs[idx])))

    rich = rich_extract(path)
    print()
    print("=" * 60)
    print(f"  verdict     : {verdict}")
    print(f"  confidence  : {confidence * 100:.2f}%")
    print(f"  raw P(mal)  : {prob:.4f}")
    print(f"  threshold   : {PE_THRESHOLD}")
    print("-" * 60)
    print("  top 5 influential features:")
    for label, value, contrib in top5:
        sign = "+" if contrib >= 0 else "-"
        print(f"    {sign} {label:<48}  value={value:< 12.4g}  contrib={contrib:+.4f}")
    print("-" * 60)
    print("  evidence (from PE structure):")
    if not rich.is_pe:
        print(f"    - file is not a valid PE: {rich.error}")
    else:
        print(f"    - sections={rich.section_count}  overall_entropy={rich.overall_entropy:.2f}")
        if rich.has_high_entropy_section:
            hi = [s.name for s in rich.sections if s.entropy >= 7.2]
            print(f"    - high-entropy section(s): {', '.join(hi)}")
        if rich.has_writable_executable_section:
            print("    - has writable+executable section (RWX)")
        if rich.no_imports:
            print("    - no imports at all (suspicious)")
        if rich.suspicious_count:
            sample = ", ".join(rich.suspicious_imports[:6])
            print(f"    - {rich.suspicious_count} suspicious imports: {sample}")
    print("=" * 60)
    if verdict == "MALICIOUS":
        vt = maybe_lookup_for_path(path)
        if vt is not None:
            print(render_cli_block(vt))
    return 0 if verdict == "CLEAN" else 1


def _scan_ps1(path: str) -> int:
    if not os.path.isfile(PS1_MODEL_PATH):
        print(f"error: PS1 model {PS1_MODEL_PATH} not found. run: python -m src.ps1_train", file=sys.stderr)
        return 2
    feats = ps1_extract(path)
    x = np.asarray([feats.vector()], dtype=np.float32)

    print(f"[*] type=PS1  {path}  ({int(feats.feature_dict['length']):,} chars)")
    model = lgb.Booster(model_file=PS1_MODEL_PATH)
    prob = float(model.predict(x)[0])
    verdict = "MALICIOUS" if prob >= PS1_THRESHOLD else "CLEAN"
    confidence = prob if verdict == "MALICIOUS" else (1.0 - prob)

    contribs = model.predict(x, pred_contrib=True)[0][:-1]
    ranked = np.argsort(-contribs) if verdict == "MALICIOUS" else np.argsort(contribs)

    top5 = []
    for idx in ranked[:5]:
        label = PS1_FEATURE_NAMES[int(idx)]
        top5.append((label, float(x[0, idx]), float(contribs[idx])))

    print()
    print("=" * 60)
    print(f"  verdict     : {verdict}")
    print(f"  confidence  : {confidence * 100:.2f}%")
    print(f"  raw P(mal)  : {prob:.4f}")
    print(f"  threshold   : {PS1_THRESHOLD}")
    print("-" * 60)
    print("  top 5 influential features:")
    for label, value, contrib in top5:
        sign = "+" if contrib >= 0 else "-"
        print(f"    {sign} {label:<28}  value={value:< 12.4g}  contrib={contrib:+.4f}")
    print("-" * 60)
    print("  rule-derived reasons:")
    if feats.reasons:
        for r in feats.reasons[:6]:
            print(f"    - {r}")
    else:
        print("    - (none - model decided on numeric shape alone)")
    print("=" * 60)
    if verdict == "MALICIOUS":
        vt = maybe_lookup_for_path(path)
        if vt is not None:
            print(render_cli_block(vt))
    return 0 if verdict == "CLEAN" else 1


def _scan_office(path: str) -> int:
    print(f"[*] type=Office  {path}")
    res = office_scanner.scan_file(path)
    print()
    print(office_scanner.render(res))
    if res.verdict == "MALICIOUS":
        vt = maybe_lookup_for_path(path)
        if vt is not None:
            print(render_cli_block(vt))
    return 0 if res.verdict == "CLEAN" else 1


def _scan_pdf(path: str) -> int:
    print(f"[*] type=PDF  {path}")
    res = pdf_scanner.scan_file(path)
    print()
    print(pdf_scanner.render(res))
    if res.verdict == "MALICIOUS":
        vt = maybe_lookup_for_path(path)
        if vt is not None:
            print(render_cli_block(vt))
    return 0 if res.verdict == "CLEAN" else 1


# ---------- Entry point ------------------------------------------------------

def scan(path: str) -> int:
    if not os.path.isfile(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    kind = detect_file_type(path)
    if kind == FILE_PE:
        return _scan_pe(path)
    if kind == FILE_PS1:
        return _scan_ps1(path)
    if kind == FILE_OFFICE:
        return _scan_office(path)
    if kind == FILE_PDF:
        return _scan_pdf(path)
    print(f"error: unsupported file type ({kind}). supported: PE/.ps1/Office/PDF", file=sys.stderr)
    return 2


def _cmd_feedback(argv: list[str]) -> int:
    from feedback import submit_feedback
    ap = argparse.ArgumentParser(prog="scan.py feedback",
                                 description="record a user-supplied correct label")
    ap.add_argument("path")
    ap.add_argument("correct_label", choices=["clean", "malicious"])
    args = ap.parse_args(argv)
    return submit_feedback(args.path, args.correct_label)


def main():
    # Subcommands: `scan.py feedback ...` and the default scan.
    if len(sys.argv) >= 2 and sys.argv[1] == "feedback":
        sys.exit(_cmd_feedback(sys.argv[2:]))

    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    args = ap.parse_args()
    rc = scan(args.path)

    # End-of-scan auto-retrain warning (cheap; reads jsonl).
    try:
        from feedback import maybe_warn_about_feedback
        maybe_warn_about_feedback()
    except Exception:
        pass
    sys.exit(rc)


if __name__ == "__main__":
    main()
