# MIT License
#
# Copyright (c) 2026 DeJavaEx
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Optional standalone file metadata utility; not used by the DeJavaEx app."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


def analyze_file_info(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    data = path.read_bytes()
    counts = Counter(data)
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()) if data else 0.0

    if data.startswith(b"\xca\xfe\xba\xbe"):
        file_type = "Java class"
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        file_type = "ZIP/JAR archive"
    elif data.startswith(b"MZ"):
        file_type = "Windows PE executable"
    else:
        file_type = "Unknown binary"

    return {
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "file_type": file_type,
        "extension": path.suffix.lower(),
        "size_bytes": len(data),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(entropy, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Read basic file information without executing the file.")
    parser.add_argument("file", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(analyze_file_info(arguments.file), indent=2))


if __name__ == "__main__":
    main()