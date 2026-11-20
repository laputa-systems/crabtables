import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class BenchmarkSelection(unittest.TestCase):
    def test_requested_workload_must_not_be_silently_excluded(self):
        for args in [
            ["--tier", "edit", "--workload", "transaction"],
            ["--tier", "change", "--workload", "transaction", "--workload", "upstream"],
            ["--tier", "change", "--workload", "transaction", "--skip", "transaction"],
        ]:
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, "scripts/bench.py", "run", *args, "--dry-run"],
                                        cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("workload", result.stderr)


if __name__ == "__main__":
    unittest.main()
