"""Create an explicit, revision-pinned v2 PATT payload import manifest.

The script never writes to a graph.  Fetching is opt-in and the caller must
name an immutable upstream commit, so a later ``ckg ingest --patt-cwe`` can be
repeated from the saved manifest without a network dependency.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

from ckg.ingestion.patt.payload_importer import slice_for_cwe


_COMMIT_RE = re.compile(r"[0-9a-f]{40,64}\Z")


def _fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": "ckg-patt-manifest/2"})
    with urlopen(request, timeout=60) as response:  # noqa: S310 - explicit user URL
        return response.read()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create one local, revision-pinned v2 PATT import manifest."
    )
    parser.add_argument("--patt-cwe", required=True, help="One supported CWE slice, for example CWE-79")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Local PATT Markdown or Intruder wordlist")
    source.add_argument("--url", help="Pinned raw.githubusercontent.com URL")
    parser.add_argument("--commit", required=True, help="Immutable 40+ hexadecimal PATT git commit")
    parser.add_argument("--kind", choices=("markdown", "wordlist"), default="markdown")
    parser.add_argument("--technology", help="Optional technology name for filename-split PATT sources")
    parser.add_argument("--source-file", help="Stable source filename stored in provenance")
    parser.add_argument("--output", help="Write the JSON manifest here instead of stdout")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    slice_ = slice_for_cwe(args.patt_cwe)
    if not _COMMIT_RE.fullmatch(args.commit):
        raise ValueError("--commit must be an immutable 40+ hexadecimal git commit")
    if args.kind == "wordlist" and slice_.intruder_family is None:
        raise ValueError(f"{args.patt_cwe} has no supported Burp Intruder wordlist family")
    if args.file:
        path = Path(args.file)
        content = path.read_text(encoding="utf-8")
        source_url = path.resolve().as_uri()
        source_file = args.source_file or path.name
    else:
        if args.commit not in args.url:
            raise ValueError("--url must contain the supplied immutable --commit; branch URLs are not reproducible")
        content = _fetch(args.url).decode("utf-8")
        source_url = args.url
        source_file = args.source_file or args.url.rsplit("/", 1)[-1]
    manifest = {
        "sources": [{
            "source_file": source_file,
            "source_url": source_url,
            "source_revision": args.commit,
            "content": content,
            "kind": args.kind,
            **({"technology": args.technology} if args.technology else {}),
        }],
    }
    rendered = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
