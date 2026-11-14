"""Compare stdio ordering with the unmodified, pinned original client."""
import errno
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import time
import unittest

import test_integration as integration

ORIGINAL = "a2dbeb73c1d2b5e7a58cf536b27dd4c40497d3e0"


class OutputOrderTests(unittest.TestCase):
    # Reuse only fixture helpers, without inheriting and rerunning its tests.
    setUp = integration.OriginalContractTests.setUp
    tearDown = integration.OriginalContractTests.tearDown
    start_server = integration.OriginalContractTests.start_server
    wait_for = integration.OriginalContractTests.wait_for
    process_alive = staticmethod(integration.OriginalContractTests.process_alive)

    def original_client(self):
        binary = self.root / "original-client"
        if not binary.exists():
            source = subprocess.run(["git", "show", ORIGINAL + ":ssu_vim.c"],
                                    cwd=integration.ROOT, capture_output=True, check=True).stdout
            path = self.root / "original-client.c"
            path.write_bytes(source)
            # The original contains known warnings/unsafe signal code. Build
            # it unchanged as an output oracle, not as the sanitizer target.
            built = subprocess.run(["gcc", "-std=gnu11", "-w", str(path), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stderr)
        return str(binary)

    @staticmethod
    def normalize_times(output):
        # The original aliases localtime() storage. Compare ordering separately
        # from timestamp values, which have their own integration assertion.
        return re.sub(r"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]", "[TIME]", output)

    def captured(self, binary, options, destination, answer="", env=None):
        command = [binary, "sample.txt", *options]
        kwargs = dict(cwd=self.root, env=env or self.env, input=answer,
                      text=True, stderr=subprocess.PIPE, timeout=15)
        if destination == "pipe":
            result = subprocess.run(command, stdout=subprocess.PIPE, **kwargs)
            output = result.stdout
        else:
            path = self.root / "output.txt"
            with path.open("w") as stream:
                result = subprocess.run(command, stdout=stream, **kwargs)
            output = path.read_text()
        self.assertEqual(result.returncode, 0, output + result.stderr)
        self.assertNotIn("ERROR: AddressSanitizer", result.stderr)
        self.assertNotIn("runtime error:", result.stderr)
        return output

    def test_read_order_matches_original_for_pipe_and_file(self):
        for destination in ("pipe", "file"):
            with self.subTest(destination=destination):
                original = self.captured(self.original_client(), ["-r", "-t"], destination)
                current = self.captured(integration.CLIENT, ["-r", "-t"], destination)
                self.assertTrue(original.startswith("original\n"), original)
                self.assertEqual(self.normalize_times(current), self.normalize_times(original))

    def test_cancel_order_matches_original_for_pipe_and_file(self):
        self.start_server()
        for destination in ("pipe", "file"):
            with self.subTest(destination=destination):
                original = self.captured(self.original_client(), ["-rw", "-t"], destination, "no\n")
                current = self.captured(integration.CLIENT, ["-rw", "-t"], destination, "no\n")
                self.assertTrue(original.startswith("original\n"), original)
                self.assertEqual(self.normalize_times(current), self.normalize_times(original))

    def terminal_output(self, binary, mode):
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen([binary, "sample.txt", mode, "-t"], cwd=self.root,
                                       env=self.env, stdin=slave, stdout=slave,
                                       stderr=subprocess.PIPE, text=True, start_new_session=True)
            self.clients.append(process)
        finally:
            os.close(slave)
        output = b""
        answered = False
        deadline = time.monotonic() + 8
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                try:
                    chunk = os.read(master, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output += chunk
                if mode == "-rw" and not answered and b"(yes/no) : " in output:
                    os.write(master, b"no\n")
                    answered = True
            if mode == "-rw":
                self.assertTrue(answered, "Confirmation must be visible before typing the answer")
            _, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stderr, "")
        finally:
            os.close(master)
        return output.decode().replace("\r\n", "\n")

    def test_terminal_read_and_confirmation_match_original(self):
        self.start_server()
        for mode in ("-r", "-rw"):
            with self.subTest(mode=mode):
                original = self.terminal_output(self.original_client(), mode)
                current = self.terminal_output(integration.CLIENT, mode)
                self.assertTrue(original.startswith("##[Modification Time]##\n"), original)
                self.assertEqual(self.normalize_times(current), self.normalize_times(original))

    def test_editor_and_diff_order_match_original_for_pipe_and_file(self):
        self.start_server()
        # Give the original's first-PID-only lookup this test's real daemon,
        # excluding zombies left by earlier tests; the C source is unchanged.
        bindir = self.root / "lookup"
        bindir.mkdir()
        lookup = bindir / "ps"
        lookup.write_text(f"#!/bin/sh\nprintf 'PID TTY TIME CMD\\n{self.daemon} ? 00:00:00 ssu_ofm\\n'\n")
        lookup.chmod(0o755)
        environment = dict(self.env, PATH=str(bindir) + os.pathsep + self.env["PATH"])
        # Vim's own file message uses the inherited stdout descriptor. Opening
        # /dev/stdout separately would distort offsets when stdout is a file.
        labels = {"editor": '"sample.txt"', "diff": "1a2\n> edited\n",
                  "time": "Last Modification time of 'sample.txt':",
                  "changed": "There was modification.\n", "size": "##[File Size]##\n",
                  "compare": "##[Compare with Previous File]##\n"}
        for mode in ("-w", "-rw"):
            for destination in ("pipe", "file"):
                with self.subTest(mode=mode, destination=destination):
                    orders = []
                    for binary in (self.original_client(), integration.CLIENT):
                        completed = self.log.read_text().count("Finished Process ID")
                        self.target.write_text("original\n")
                        os.utime(self.target, (946684800, 946684800))
                        output = self.captured(binary, [mode, "-t", "-s", "-d"],
                                               destination, "yes\n", environment)
                        self.wait_for(lambda: self.log.read_text().count("Finished Process ID") == completed + 1)
                        self.assertEqual(self.target.read_text(), "original\nedited\n")
                        for label in labels.values():
                            self.assertIn(label, output)
                        orders.append(sorted(labels, key=lambda key: output.index(labels[key])))
                    self.assertEqual(orders[0], ["editor", "diff", "time", "changed", "size", "compare"])
                    self.assertEqual(orders[1], orders[0])


if __name__ == "__main__":
    unittest.main()
