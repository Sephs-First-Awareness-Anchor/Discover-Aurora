#!/usr/bin/env python3
"""
decode_dossier.py

Sequential decoder for AURORA_SYSTEM_DOSSIER_CHAINED.md.

What it does:
- Parses MASTER_KEY and all [[GATE ...]] blocks from the chained file
- Decrypts one gate at a time in order
- Verifies SHA256 for each decrypted gate
- Appends each successful plaintext section to an output file
- Stores progress in a sidecar state file so the output can be built gradually
- Supports interactive gate-by-gate stepping or full decode

Usage examples:
    python decode_dossier.py
    python decode_dossier.py --interactive
    python decode_dossier.py --all
    python decode_dossier.py --input AURORA_SYSTEM_DOSSIER_CHAINED.md --output decoded/AURORA_SYSTEM_DOSSIER.md

Notes:
- The output file is built incrementally.
- The script will not rewrite already-decoded sections unless --reset is used.
- If a gate fails verification, decoding stops immediately.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# ----------------------------
# Data structures
# ----------------------------

@dataclass
class Gate:
    gate_id: str
    verify_sha256: str
    plaintext_bytes: int
    ciphertext_b64: str


@dataclass
class ParsedDossier:
    master_key: str
    source_file: Optional[str]
    source_sha256: Optional[str]
    chain_style: Optional[str]
    section_boundary_rule: Optional[str]
    raw_text: str
    gates: List[Gate]


# ----------------------------
# Parsing
# ----------------------------

MASTER_KEY_RE = re.compile(r"^MASTER_KEY:\s*(.+?)\s*$", re.MULTILINE)
SOURCE_FILE_RE = re.compile(r"^SOURCE_FILE:\s*(.+?)\s*$", re.MULTILINE)
SOURCE_SHA256_RE = re.compile(r"^SOURCE_SHA256:\s*(.+?)\s*$", re.MULTILINE)
CHAIN_STYLE_RE = re.compile(r"^CHAIN_STYLE:\s*(.+?)\s*$", re.MULTILINE)
SECTION_BOUNDARY_RULE_RE = re.compile(r'^SECTION_BOUNDARY_RULE:\s*"(.+?)"\s*$', re.MULTILINE)

GATE_RE = re.compile(
    r"\[\[GATE\s+([0-9a-f]+)\]\]\s*"
    r"VERIFY_SHA256:\s*([0-9a-f]{64})\s*"
    r"PLAINTEXT_BYTES:\s*(\d+)\s*"
    r"CIPHERTEXT_BASE64:\s*(.*?)\s*"
    r"\[\[/GATE\s+\1\]\]",
    re.DOTALL
)


def parse_dossier(text: str) -> ParsedDossier:
    master_key_match = MASTER_KEY_RE.search(text)
    if not master_key_match:
        raise ValueError("MASTER_KEY not found in dossier.")

    source_file_match = SOURCE_FILE_RE.search(text)
    source_sha_match = SOURCE_SHA256_RE.search(text)
    chain_style_match = CHAIN_STYLE_RE.search(text)
    section_rule_match = SECTION_BOUNDARY_RULE_RE.search(text)

    gates: List[Gate] = []
    for match in GATE_RE.finditer(text):
        gate_id = match.group(1)
        verify_sha256 = match.group(2)
        plaintext_bytes = int(match.group(3))
        ciphertext_b64 = "".join(line.strip() for line in match.group(4).splitlines())
        gates.append(
            Gate(
                gate_id=gate_id,
                verify_sha256=verify_sha256,
                plaintext_bytes=plaintext_bytes,
                ciphertext_b64=ciphertext_b64,
            )
        )

    if not gates:
        raise ValueError("No gates found in dossier.")

    return ParsedDossier(
        master_key=master_key_match.group(1).strip(),
        source_file=source_file_match.group(1).strip() if source_file_match else None,
        source_sha256=source_sha_match.group(1).strip() if source_sha_match else None,
        chain_style=chain_style_match.group(1).strip() if chain_style_match else None,
        section_boundary_rule=section_rule_match.group(1).strip() if section_rule_match else None,
        raw_text=text,
        gates=gates,
    )


# ----------------------------
# Crypto helpers
# ----------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_first_working_key(master_key: str) -> bytes:
    return sha256_bytes(f"FIRST|{master_key}".encode("utf-8"))


def compute_next_working_key(previous_working_key: bytes, previous_plaintext: bytes) -> bytes:
    previous_plaintext_sha = sha256_hex(previous_plaintext)
    material = (
        previous_working_key.hex()
        + "\n"
        + previous_plaintext_sha
        + "\n"
        + previous_plaintext.decode("utf-8")
    ).encode("utf-8")
    return sha256_bytes(material)


def compute_keystream(working_key: bytes, length: int) -> bytes:
    blocks = bytearray()
    i = 0
    while len(blocks) < length:
        block_material = working_key.hex().encode("utf-8") + b"|" + str(i).encode("utf-8")
        blocks.extend(sha256_bytes(block_material))
        i += 1
    return bytes(blocks[:length])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def decode_gate(gate: Gate, working_key: bytes) -> bytes:
    ciphertext = base64.urlsafe_b64decode(pad_b64(gate.ciphertext_b64))
    if len(ciphertext) != gate.plaintext_bytes:
        raise ValueError(
            f"Gate {gate.gate_id}: ciphertext length mismatch. "
            f"Expected plaintext bytes {gate.plaintext_bytes}, got ciphertext bytes {len(ciphertext)}."
        )
    keystream = compute_keystream(working_key, gate.plaintext_bytes)
    plaintext = xor_bytes(ciphertext, keystream)

    actual_sha = sha256_hex(plaintext)
    if actual_sha != gate.verify_sha256:
        raise ValueError(
            f"Gate {gate.gate_id}: SHA256 verification failed.\n"
            f"Expected: {gate.verify_sha256}\n"
            f"Actual:   {actual_sha}"
        )
    return plaintext


def pad_b64(s: str) -> str:
    return s + "=" * ((4 - len(s) % 4) % 4)


# ----------------------------
# State handling
# ----------------------------

def default_state_path(output_path: Path) -> Path:
    return output_path.with_suffix(output_path.suffix + ".state.json")


def load_state(path: Path) -> dict:
    if not path.exists():
        return {
            "decoded_gate_count": 0,
            "last_gate_id": None,
            "previous_working_key_hex": None,
            "previous_plaintext_sha256": None,
        }
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def reset_files(output_path: Path, state_path: Path) -> None:
    if output_path.exists():
        output_path.unlink()
    if state_path.exists():
        state_path.unlink()


# ----------------------------
# Output helpers
# ----------------------------

def write_header_if_needed(output_path: Path, parsed: ParsedDossier) -> None:
    if output_path.exists() and output_path.stat().st_size > 0:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write("# AURORA SYSTEM DOSSIER - DECODED OUTPUT\n\n")
        f.write("> This file is built progressively by `decode_dossier.py`.\n")
        f.write("> It is intentionally appended gate-by-gate.\n\n")
        if parsed.source_file:
            f.write(f"- Source file: `{parsed.source_file}`\n")
        if parsed.source_sha256:
            f.write(f"- Source SHA256: `{parsed.source_sha256}`\n")
        if parsed.chain_style:
            f.write(f"- Chain style: `{parsed.chain_style}`\n")
        if parsed.section_boundary_rule:
            f.write(f'- Section boundary rule: "{parsed.section_boundary_rule}"\n')
        f.write("\n---\n\n")


def append_section(output_path: Path, gate: Gate, plaintext: str, gate_index: int) -> None:
    with output_path.open("a", encoding="utf-8") as f:
        f.write(f"\n<!-- DECODED GATE {gate_index + 1}: {gate.gate_id} -->\n")
        f.write(f"## DECODED SECTION {gate_index + 1}\n\n")
        f.write(plaintext)
        if not plaintext.endswith("\n"):
            f.write("\n")
        f.write("\n---\n")


# ----------------------------
# Main decode flow
# ----------------------------

def replay_working_key_chain(parsed: ParsedDossier, decoded_count: int) -> tuple[bytes, Optional[bytes]]:
    """
    Rebuild the working key state by decoding the already-completed gates from scratch.
    This avoids storing plaintext in state.
    Returns:
        current working key for the NEXT gate,
        previous plaintext bytes (last successfully decoded section) or None
    """
    working_key = compute_first_working_key(parsed.master_key)
    previous_plaintext: Optional[bytes] = None

    for i in range(decoded_count):
        gate = parsed.gates[i]
        plaintext = decode_gate(gate, working_key)
        previous_plaintext = plaintext
        working_key = compute_next_working_key(working_key, plaintext)

    return working_key, previous_plaintext


def decode_incrementally(
    parsed: ParsedDossier,
    output_path: Path,
    state_path: Path,
    interactive: bool,
    decode_all: bool,
) -> None:
    state = load_state(state_path)
    decoded_count = int(state.get("decoded_gate_count", 0))

    if decoded_count > len(parsed.gates):
        raise ValueError("State says more gates were decoded than actually exist.")

    write_header_if_needed(output_path, parsed)

    next_working_key, _ = replay_working_key_chain(parsed, decoded_count)

    for idx in range(decoded_count, len(parsed.gates)):
        gate = parsed.gates[idx]

        if interactive and not decode_all:
            prompt = (
                f"\nReady to decode gate {idx + 1}/{len(parsed.gates)} "
                f"({gate.gate_id}). Press Enter to continue, or type 'q' to quit: "
            )
            user_input = input(prompt).strip().lower()
            if user_input in {"q", "quit", "exit"}:
                print("Stopping without decoding further gates.")
                return

        plaintext_bytes = decode_gate(gate, next_working_key)
        plaintext_text = plaintext_bytes.decode("utf-8")

        append_section(output_path, gate, plaintext_text, idx)

        state = {
            "decoded_gate_count": idx + 1,
            "last_gate_id": gate.gate_id,
            "previous_working_key_hex": next_working_key.hex(),
            "previous_plaintext_sha256": sha256_hex(plaintext_bytes),
        }
        save_state(state_path, state)

        print(f"Decoded gate {idx + 1}/{len(parsed.gates)}: {gate.gate_id}")

        next_working_key = compute_next_working_key(next_working_key, plaintext_bytes)

    print("\nAll gates decoded successfully.")
    print(f"Output file: {output_path}")
    print(f"State file:  {state_path}")


# ----------------------------
# CLI
# ----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sequential decoder for AURORA_SYSTEM_DOSSIER_CHAINED.md"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("AURORA_SYSTEM_DOSSIER_CHAINED.md"),
        help="Path to the chained dossier file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("decoded") / "AURORA_SYSTEM_DOSSIER.md",
        help="Path to the progressively-built decoded output file",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=None,
        help="Optional explicit path to the decoder state file",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Decode one gate at a time, prompting before each new section",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Decode all remaining gates without prompting",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete output/state and start over from gate 1",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    input_path: Path = args.input
    output_path: Path = args.output
    state_path: Path = args.state if args.state else default_state_path(output_path)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    if args.reset:
        reset_files(output_path, state_path)
        print(f"Reset output and state:\n- {output_path}\n- {state_path}")

    text = input_path.read_text(encoding="utf-8")
    parsed = parse_dossier(text)

    interactive = args.interactive and not args.all
    decode_all = args.all

    try:
        decode_incrementally(
            parsed=parsed,
            output_path=output_path,
            state_path=state_path,
            interactive=interactive,
            decode_all=decode_all,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
