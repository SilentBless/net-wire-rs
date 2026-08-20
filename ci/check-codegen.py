#!/usr/bin/env python3
"""Gate release LLVM IR for public QUIC variable-integer operations."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# (label, public probe marker, handwritten probe marker, allowed public overhead)
# The allowances bound the prepared representation and borrowed-view bookkeeping
# that Rust 1.91 retains after inlining. Calls are never allowed implicitly.
PAIRS = (
    (
        "parse",
        "quic_varint_public_parse",
        "quic_varint_handwritten_parse",
        {"instructions": 4},
    ),
    (
        "canonical_build",
        "quic_varint_public_canonical_build",
        "quic_varint_handwritten_canonical_build",
        {"instructions": 9, "branches": 5},
    ),
    (
        "two_build",
        "quic_varint_public_two_build",
        "quic_varint_handwritten_two_build",
        {"instructions": 0},
    ),
)

FORBIDDEN_MARKERS = ("__rust_alloc", "__rust_dealloc", "__rust_realloc", "vtable")
PANIC_MARKERS = ("panic", "bounds_check", "slice_index", "copy_from_slice", "assert_failed")


def build(root: Path, target: str) -> None:
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(root / "target" / "codegen-gate")
    if sys.platform == "darwin" and target.endswith("-unknown-linux-gnu"):
        linker_variable = f"CARGO_TARGET_{target.upper().replace('-', '_')}_LINKER"
        # LLVM IR and assembly are emitted before Cargo's mandatory final link.
        # A Linux userspace is unavailable on macOS and the probe binary is never run.
        environment.setdefault(linker_variable, "/usr/bin/true")
    subprocess.run(
        [
            "cargo",
            "+1.91.0",
            "rustc",
            "--test",
            "quic",
            "--release",
            "--no-default-features",
            "--features",
            "quic",
            "--target",
            target,
            "--",
            "--emit=asm,llvm-ir",
        ],
        cwd=root,
        env=environment,
        check=True,
    )


def unquote(symbol: str) -> str:
    return symbol.strip('"')


def aliases(ir: str) -> dict[str, str]:
    found: dict[str, str] = {}
    pattern = re.compile(
        r'^@(?P<alias>"?[\w.$-]+"?)\s*=\s*.*?\balias\b.*?@(?P<target>"?[\w.$-]+"?)\s*$',
        re.MULTILINE,
    )
    for match in pattern.finditer(ir):
        found[unquote(match.group("alias"))] = unquote(match.group("target"))
    return found


def definitions(ir: str) -> dict[str, str]:
    found: dict[str, str] = {}
    headers = re.compile(r'^define\b.*?@(?P<symbol>"?[\w.$-]+"?)\(', re.MULTILINE)
    for match in headers.finditer(ir):
        start = ir.find("{", match.end())
        if start < 0:
            continue
        depth = 0
        for end in range(start, len(ir)):
            if ir[end] == "{":
                depth += 1
            elif ir[end] == "}":
                depth -= 1
                if depth == 0:
                    found[unquote(match.group("symbol"))] = ir[start + 1 : end]
                    break
    return found


def resolve(symbol: str, alias_map: dict[str, str]) -> str:
    seen: set[str] = set()
    while symbol in alias_map and symbol not in seen:
        seen.add(symbol)
        symbol = alias_map[symbol]
    if symbol in seen:
        raise RuntimeError(f"alias cycle while resolving {symbol!r}")
    return symbol


def locate(marker: str, bodies: dict[str, str], alias_map: dict[str, str]) -> tuple[str, str]:
    candidates = sorted(
        symbol for symbol in set(bodies) | set(alias_map) if marker in symbol
    )
    resolved = [(symbol, resolve(symbol, alias_map)) for symbol in candidates]
    available = [(symbol, target) for symbol, target in resolved if target in bodies]
    if len(available) != 1:
        names = ", ".join(f"{symbol}->{target}" for symbol, target in resolved) or "none"
        raise RuntimeError(f"expected one symbol containing {marker!r}; found {names}")
    symbol, target = available[0]
    return symbol, bodies[target]


def normalized(body: str) -> str:
    body = re.sub(r'\bnoundef\s+', '', body)
    body = re.sub(r', ![\w.]+ !\d+', '', body)
    body = re.sub(r'!dbg !\d+', '', body)
    body = re.sub(r'^\s*[\w.$-]+:', 'block:', body, flags=re.MULTILINE)
    body = re.sub(r'%[-\w.]+', '%value', body)
    return re.sub(r'\s+', ' ', body).strip()


def external_callees(body: str) -> set[str]:
    return {
        unquote(match.group("callee"))
        for match in re.finditer(r'\b(?:call|invoke)\b.*?@(?P<callee>"?[\w.$-]+"?)', body)
        if not unquote(match.group("callee")).startswith("llvm.")
    }


def metrics(body: str) -> dict[str, int]:
    lines = [
        line.strip()
        for line in body.splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]
    calls = [line for line in lines if re.search(r'\b(?:call|invoke)\b', line)]
    relevant_calls = [line for line in calls if "@llvm." not in line]
    return {
        "instructions": sum(not line.endswith(":") for line in lines),
        "calls": len(relevant_calls),
        "branches": sum(
            line.startswith(("br ", "switch ", "indirectbr ")) for line in lines
        ),
    }


def bad_markers(body: str) -> list[str]:
    call_lines = "\n".join(
        line for line in body.splitlines() if re.search(r"\b(?:call|invoke)\b", line)
    )
    return [marker for marker in FORBIDDEN_MARKERS if marker in body] + [
        marker for marker in PANIC_MARKERS if marker in call_lines
    ]


def latest_outputs(root: Path, target: str) -> tuple[Path, Path]:
    deps = root / "target" / "codegen-gate" / target / "release" / "deps"
    candidates = [
        path for path in deps.glob("quic-*.ll") if path.with_suffix(".s").is_file()
    ]
    if not candidates:
        raise RuntimeError(f"expected quic-*.ll and matching .s below {deps}")
    ir_path = max(candidates, key=lambda path: path.stat().st_mtime_ns)
    return ir_path, ir_path.with_suffix(".s")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu")
    args = parser.parse_args()
    root = args.root.resolve()

    build(root, args.target)
    ir_path, assembly_path = latest_outputs(root, args.target)
    ir = ir_path.read_text()
    # Requiring the matching assembly guards that cargo honored both requested emits.
    assembly_path.read_text()
    bodies = definitions(ir)
    alias_map = aliases(ir)

    failures: list[str] = []
    for label, public_marker, handwritten_marker, allowance in PAIRS:
        try:
            public_symbol, public_body = locate(public_marker, bodies, alias_map)
            handwritten_symbol, handwritten_body = locate(
                handwritten_marker, bodies, alias_map
            )
        except RuntimeError as error:
            failures.append(f"{label}: {error}")
            continue

        public_metrics = metrics(public_body)
        handwritten_metrics = metrics(handwritten_body)
        identical = normalized(public_body) == normalized(handwritten_body)
        public_callees = external_callees(public_body)
        handwritten_callees = external_callees(handwritten_body)
        extra = {
            metric: public_metrics[metric] - handwritten_metrics[metric]
            for metric in public_metrics
            if public_metrics[metric] - handwritten_metrics[metric]
            > allowance.get(metric, 0)
        }
        print(
            f"{label}: public={public_symbol} handwritten={handwritten_symbol} "
            f"identical={identical} public_metrics={public_metrics} "
            f"handwritten_metrics={handwritten_metrics}"
        )

        for owner, body in (("public", public_body), ("handwritten", handwritten_body)):
            markers = bad_markers(body)
            if markers:
                failures.append(f"{label}: {owner} body contains forbidden markers: {markers}")
        unexpected = public_callees - handwritten_callees
        if unexpected:
            failures.append(f"{label}: public body has unexpected callees: {sorted(unexpected)}")
        if not identical and not allowance:
            failures.append(f"{label}: optimized bodies differ")
        elif extra:
            failures.append(f"{label}: public overhead exceeds equivalent baseline: {extra}")

    if failures:
        print("QUIC varint codegen gate failed:", file=sys.stderr)
        print("\n".join(f"  - {failure}" for failure in failures), file=sys.stderr)
        return 1
    print("QUIC varint codegen gate passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"QUIC varint codegen gate failed: {error}", file=sys.stderr)
        raise SystemExit(1)
