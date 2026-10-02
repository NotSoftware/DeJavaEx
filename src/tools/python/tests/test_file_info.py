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

import hashlib
import tempfile
import unittest
from pathlib import Path

from src.tools.python.file_info import analyze_file_info


class FileInfoTests(unittest.TestCase):
    def test_java_class_identity_and_entropy(self):
        data = b"\xca\xfe\xba\xbe\x00\x00\x00\x3d"
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.class"
            sample.write_bytes(data)
            result = analyze_file_info(sample)

        self.assertEqual(result["file_type"], "Java class")
        self.assertEqual(result["md5"], hashlib.md5(data, usedforsecurity=False).hexdigest())
        self.assertEqual(result["sha1"], hashlib.sha1(data, usedforsecurity=False).hexdigest())
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertGreater(result["entropy"], 0)


if __name__ == "__main__":
    unittest.main()