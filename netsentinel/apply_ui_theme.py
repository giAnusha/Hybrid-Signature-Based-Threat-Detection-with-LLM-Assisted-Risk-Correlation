#!/usr/bin/env python3
"""
Capstone 1 - Automated PCAP Analysis and Threat Detection
Dashboard UI patch: branding + pink theme + export filename prefix.

SCOPE
  Modifies exactly ONE file:
      /home/kali/Downloads/netsentinel/templates/index.html
  Creates exactly ONE new file (the backup):
      /home/kali/Downloads/netsentinel/templates/index.html.backup

GUARANTEES
  * server.py and every other file are never opened for writing.
  * The alert text-wrapping CSS is NEVER modified (APPLY_WRAP_FIX = False).
    The five wrapping properties are only ASSERTED, before and after.
  * Aborts before writing if any expected original string is missing.
  * Aborts before writing if any post-check fails.
  * No package imports beyond the standard library (os, shutil, sys, time).
  * No network access, no subprocess, no signals, no process control.
  * Nothing is deleted. Flask is never restarted or killed.
"""

import os
import shutil
import sys
import time

# ── Configuration ────────────────────────────────────────────────────
PROJECT = "/home/kali/Downloads/netsentinel"
TARGET  = os.path.join(PROJECT, "templates", "index.html")
BACKUP  = TARGET + ".backup"

# The Kali file already has the text-wrapping fix verified present.
# This script must NOT touch the wrapping CSS. Leave this False.
APPLY_WRAP_FIX = False

# ── The five wrapping properties: asserted, never written ────────────
WRAP_PROPS = [
    "flex:0 0 auto",
    "min-width:0",
    "white-space:normal",
    "word-break:break-word",
    "overflow-wrap:anywhere",
]

# ── Blue/cyan literals that must be gone afterwards ───────────────────
OLD_ACCENT_LITERALS = [
    "#4f8ef5",
    "#22d3ee",
    "#1e3a8a",
    "rgba(79,142,245,",
    "rgba(34,211,238,",
]

# ── Replacements: (label, old, new, expected_count) ───────────────────
# expected_count None = one or more; count recorded but not asserted.
# ORDER MATTERS: the :root palette block must be replaced BEFORE the
# bare hex swaps, otherwise its own #4f8ef5 / #22d3ee are rewritten
# first and the exact-match block replacement would no longer apply.
REPLACEMENTS = [

    # ---- 1. BRANDING (3 user-facing locations) ----------------------
    ("branding: browser <title>",
     "<title>NetSentinel \u2014 PCAP Threat Intelligence Platform</title>",
     "<title>PCAP Analysis \u2014 Threat Intelligence Platform</title>", 1),

    ("branding: header logo",
     '<span class="logo-txt">Net<em>Sentinel</em></span>',
     '<span class="logo-txt">PCAP<em> Analysis</em></span>', 1),

    ("branding: footer badge",
     '<span class="ftr-b">NetSentinel v2.0</span>',
     '<span class="ftr-b">PCAP Analysis v2.0</span>', 1),

    # ---- 2. EXPORT FILENAME PREFIX ---------------------------------
    ("export filename prefix",
     "download:`netsentinel-${Date.now()}.${fmt}`",
     "download:`pcap-analysis-${Date.now()}.${fmt}`", 1),

    # ---- 3. PALETTE: :root declaration (must precede hex swaps) -----
    ("palette: :root declaration",
     "  --blue:#4f8ef5;--blue-g:rgba(79,142,245,0.18);\n"
     "  --cyan:#22d3ee;--green:#34d399;--green-d:rgba(52,211,153,.15);",

     "  /* -- Brand palette (pink) -- single source of truth -- */\n"
     "  --pink:#d9578f;          /* primary   - muted rose        */\n"
     "  --pink-soft:#f2a4c4;     /* secondary - soft pink         */\n"
     "  --pink-deep:#7d2450;     /* deep plum - gradient anchors  */\n"
     "  --pink-g:rgba(217,87,143,0.18);\n"
     "  /* legacy accent names kept as aliases: no rule or class\n"
     "     is renamed, so no other CSS/JS reference changes.      */\n"
     "  --blue:var(--pink);--blue-g:var(--pink-g);\n"
     "  --cyan:var(--pink-soft);--green:#34d399;"
     "--green-d:rgba(52,211,153,.15);", 1),

    # ---- 4. HARDCODED ACCENT LITERALS ------------------------------
    # CSS variables cannot reach these (gradients, glows, Chart.js).
    ("accent rgba  blue  -> pink",
     "rgba(79,142,245,", "rgba(217,87,143,", None),

    ("accent rgba  cyan  -> soft pink",
     "rgba(34,211,238,", "rgba(242,164,196,", None),

    ("gradient anchor #1e3a8a -> plum",
     "#1e3a8a", "var(--pink-deep)", None),

    ("accent hex   #4f8ef5 -> pink",
     "#4f8ef5", "#d9578f", None),

    ("accent hex   #22d3ee -> soft pink",
     "#22d3ee", "#f2a4c4", None),
]


def fail(msg, detail_lines=None):
    print("\n" + "=" * 64)
    print("  RESULT: FAILED")
    print("=" * 64)
    print("  " + msg)
    if detail_lines:
        print()
        for line in detail_lines:
            print("    " + line)
    print("\n  NO CHANGES WERE WRITTEN. Your file is untouched.")
    print("=" * 64 + "\n")
    sys.exit(1)


def main():
    print("=" * 64)
    print("  Capstone 1 - Automated PCAP Analysis and Threat Detection")
    print("  Dashboard UI patch: branding + pink theme + export prefix")
    print("=" * 64)
    print("  Target file : " + TARGET)
    print("  Backup file : " + BACKUP)
    print("  APPLY_WRAP_FIX = %s  (wrapping CSS will NOT be modified)"
          % APPLY_WRAP_FIX)

    # ---- Guard: the wrap fix must never be applied by this script ---
    if APPLY_WRAP_FIX:
        fail("APPLY_WRAP_FIX is True. This build must not alter wrapping "
             "CSS. Set it back to False and re-run.")

    if not os.path.isfile(TARGET):
        fail("Target file not found. Check that PROJECT points at your "
             "Capstone 1 project root.")

    with open(TARGET, encoding="utf-8") as fh:
        original = fh.read()
    text = original

    # =================================================================
    # [1/6] PRE-FLIGHT
    # =================================================================
    print("\n[1/6] Pre-flight: expected original content")

    if "pcap-analysis-${Date.now()}" in text:
        print("      This file already contains the new export prefix,")
        print("      so it appears to have been patched already.")
        print("      Aborting so nothing is double-applied.")
        print("      To re-apply, restore the backup first:")
        print("        cp %s %s" % (BACKUP, TARGET))
        print("\n  RESULT: NO CHANGES MADE (already patched).\n")
        sys.exit(0)

    missing = [label for label, old, _new, _c in REPLACEMENTS
               if old not in text]
    if missing:
        fail("Expected original string(s) not found in the file. "
             "Your copy differs from what this script was built for.",
             ["MISSING -> " + m for m in missing])
    print("      All %d expected strings found." % len(REPLACEMENTS))

    # ---- Pre-flight: wrapping properties must already be present ----
    print("\n[2/6] Pre-flight: existing text-wrapping fix")
    wrap_missing = [p for p in WRAP_PROPS if p not in text]
    if wrap_missing:
        fail("The text-wrapping fix is NOT fully present in this file, "
             "but you stated it was verified. Refusing to proceed so "
             "the discrepancy can be investigated.",
             ["MISSING -> " + p for p in wrap_missing])
    wrap_counts_before = {p: text.count(p) for p in WRAP_PROPS}
    for p in WRAP_PROPS:
        print("      present  x%-2d  %s" % (wrap_counts_before[p], p))

    # =================================================================
    # [3/6] BACKUP
    # =================================================================
    print("\n[3/6] Backup")
    if os.path.exists(BACKUP):
        print("      A backup already exists; it will NOT be overwritten.")
        print("      " + BACKUP)
    else:
        shutil.copy2(TARGET, BACKUP)
        print("      Created: " + BACKUP)

    # =================================================================
    # [4/6] APPLY REPLACEMENTS (in memory)
    # =================================================================
    print("\n[4/6] Applying replacements (in memory)")
    total = 0
    for label, old, new, expected in REPLACEMENTS:
        found = text.count(old)
        if expected is not None and found != expected:
            fail("%s: expected exactly %d occurrence(s) but found %d."
                 % (label, expected, found))
        text = text.replace(old, new)
        total += found
        print("      %-34s %2d replaced" % (label, found))
    print("      %-34s %2d total" % ("", total))

    # =================================================================
    # [5/6] VERIFY (before writing anything to disk)
    # =================================================================
    print("\n[5/6] Verification")

    raw_brand_count = text.count("PCAP Analysis")
    checks = [
        ("branding 1/3: <title> = PCAP Analysis",
         "<title>PCAP Analysis" in text),
        ("branding 2/3: header logo = PCAP Analysis",
         'class="logo-txt">PCAP<em> Analysis</em></span>' in text),
        ("branding 3/3: footer badge = PCAP Analysis v2.0",
         "PCAP Analysis v2.0" in text),
        ("export prefix 'pcap-analysis-' appears exactly 1 time",
         text.count("pcap-analysis-") == 1),
        ("palette '--pink:#d9578f' appears exactly 1 time",
         text.count("--pink:#d9578f") == 1),
        ("palette: --pink-soft / --pink-deep / --pink-g defined",
         "--pink-soft:#f2a4c4" in text
         and "--pink-deep:#7d2450" in text
         and "--pink-g:rgba(217,87,143,0.18)" in text),
        ("old blue/cyan literals all gone",
         not any(lit in text for lit in OLD_ACCENT_LITERALS)),
        ("severity colours untouched (red/amber/green/purple)",
         "--red:#f87171" in text and "--amber:#fbbf24" in text
         and "--green:#34d399" in text and "--purple:#a78bfa" in text),
        ("no 'NetSentinel' left in the dashboard template",
         "NetSentinel" not in text and "netsentinel" not in text),
        ("CSS/JS brace balance unchanged",
         text.count("{") - text.count("}")
         == original.count("{") - original.count("}")),
        ("file length sane (no truncation)",
         abs(len(text) - len(original)) < 4000),
    ]

    # The five wrapping properties must be present AND unchanged in count
    for p in WRAP_PROPS:
        checks.append(
            ("wrapping preserved (x%d): %s" % (wrap_counts_before[p], p),
             text.count(p) == wrap_counts_before[p] and text.count(p) > 0))

    all_ok = True
    for label, passed in checks:
        print("      [%s] %s" % ("PASS" if passed else "FAIL", label))
        all_ok = all_ok and passed

    print()
    print("      Note: the literal string 'PCAP Analysis' occurs %d times"
          % raw_brand_count)
    print("      across the 3 branding locations. The header logo renders")
    print("      as PCAP<em> Analysis</em>, so a tag sits between the two")
    print("      words and that line does not contain the contiguous")
    print("      string. All 3 locations are verified individually above.")

    if not all_ok:
        fail("One or more post-checks failed. File NOT written.")

    # =================================================================
    # [6/6] WRITE
    # =================================================================
    print("\n[6/6] Writing file")
    with open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("      Written: " + TARGET)

    server_py = os.path.join(PROJECT, "server.py")
    if os.path.isfile(server_py):
        print("      server.py was never opened for writing by this script.")
        print("      server.py mtime: %s"
              % time.ctime(os.path.getmtime(server_py)))
        print("      Confirm independently:  md5sum server.py")

    print("\n" + "=" * 64)
    print("  RESULT: SUCCESS - dashboard UI patched")
    print("=" * 64)
    print("  Changed : templates/index.html   (this file only)")
    print("  Created : templates/index.html.backup")
    print("  Wrapping CSS: asserted present, never modified")
    print("  Backend : not touched (no other file opened for writing)")
    print()
    print("  This script did NOT restart or stop Flask.")
    print("  Restart the server yourself, then hard-reload the page")
    print("  with Ctrl+Shift+R (the CSS is inline in the template).")
    print()
    print("  To revert:")
    print("    cp %s %s" % (BACKUP, TARGET))
    print("=" * 64 + "\n")


if __name__ == "__main__":
    main()
