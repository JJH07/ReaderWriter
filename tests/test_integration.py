"""Black-box regressions: real Linux sockets, processes and file operations."""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVER = str(ROOT / "ssu_ofm")
CLIENT = str(ROOT / "ssu_vim")
GRANTED, QUEUED, BUSY, INVALID, SHUTDOWN, DONE = range(1, 7)

EDITOR_SCRIPT = '''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import time
root = Path(os.environ["TEST_ROOT"])
label = os.environ.get("TEST_LABEL", "edit")
guard = root / "exclusive"
try:
    fd = os.open(guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except FileExistsError:
    (root / "collision").touch()
    sys.exit(99)
try:
    (root / ("started-" + label)).touch()
    if os.environ.get("TEST_GATE"):
        deadline = time.monotonic() + 8
        while not (root / ("gate-" + label)).exists():
            if time.monotonic() >= deadline:
                sys.exit(98)
            time.sleep(0.01)
    path = Path(sys.argv[1])
    old = path.stat()
    if not os.environ.get("TEST_NOOP"):
        with path.open("a") as out:
            out.write(label + "\\n")
    if os.environ.get("TEST_KEEP_TIME"):
        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
finally:
    os.close(fd)
    guard.unlink()
'''


class ReaderWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rw-test-")
        self.root = Path(self.temp.name)
        self.file = self.root / "sample.txt"
        self.file.write_text("original\n")
        self.sock = self.root / "ipc" / "ofm.sock"
        self.editor = self.root / "editor"
        self.editor.write_text(EDITOR_SCRIPT)
        self.editor.chmod(0o700)
        self.env = dict(os.environ, EDITOR=str(self.editor), TEST_ROOT=str(self.root),
                        TMPDIR=str(self.root))
        self.processes = []
        self.connections = []
        self.server = None

    def tearDown(self):
        for connection in self.connections:
            connection.close()
        for process in self.processes:
            # Each test process owns an isolated process group, including editors.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                _, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                _, stderr = process.communicate(timeout=3)
            self.assertNotIn("ERROR: AddressSanitizer", stderr)
            self.assertNotIn("ERROR: LeakSanitizer", stderr)
            self.assertNotIn("runtime error:", stderr)
        self.temp.cleanup()

    def wait_for(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("Timed out waiting for test condition")

    def spawn(self, arguments, env=None):
        process = subprocess.Popen(arguments, cwd=self.root, env=env or self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        self.processes.insert(0, process)
        return process

    def run_client(self, *options, input=None, env=None, target=None):
        return subprocess.run([CLIENT, str(target or self.file), *options,
                               "--socket", str(self.sock)], cwd=self.root,
                              env=env or self.env, input=input, capture_output=True,
                              text=True, timeout=8)

    def start_server(self, *options):
        self.server = self.spawn([SERVER, str(self.file), "-f", "--socket",
                                  str(self.sock), *options])
        self.wait_for(lambda: self.sock.exists() or self.server.poll() is not None)
        self.assertIsNone(self.server.poll(), "Server failed to start")

    def connect_request(self, path=None, packet=None):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        connection.settimeout(4)
        self.connections.append(connection)
        connection.connect(str(self.sock))
        if packet is None:
            packet = struct.pack("=I4096s", 0x52573131,
                                 os.fsencode(path or self.file.resolve()))
        connection.sendall(packet)
        return connection

    def status(self, connection):
        packet = connection.recv(4)
        self.assertEqual(len(packet), 4)
        return struct.unpack("=I", packet)[0]

    def active(self):
        connection = self.connect_request()
        self.assertEqual(self.status(connection), QUEUED)
        self.assertEqual(self.status(connection), GRANTED)
        return connection

    def done(self, connection):
        connection.sendall(struct.pack("=I", DONE))

    def test_read_without_daemon_and_correct_timestamp(self):
        os.utime(self.file, (946684800, 946684800))
        result = self.run_client("-r", "-t")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("original", result.stdout)
        lines = result.stdout.splitlines()
        self.assertNotEqual(lines[0].split(": ", 1)[1], lines[1].split(": ", 1)[1])

    def test_missing_and_conflicting_arguments(self):
        cases = [[CLIENT], [CLIENT, str(self.file)], [SERVER],
                 [CLIENT, str(self.file), "-r", "-w"],
                 [CLIENT, str(self.file), "-t"],
                 [SERVER, str(self.file), "-n", "0"],
                 [SERVER, str(self.file), "-n", "-1"],
                 [SERVER, str(self.file), "-n", "garbage"],
                 [SERVER, str(self.file), "-p"],
                 [CLIENT, str(self.file), "-w", "--timeout", "0"]]
        for command in cases:
            with self.subTest(command=command):
                result = subprocess.run(command, cwd=self.root, capture_output=True,
                                        text=True, timeout=3)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_cancel_preserves_literal_temp_name_and_target(self):
        sentinel = self.root / "tempXXXXXX"
        sentinel.write_text("keep me\n")
        result = self.run_client("-rw", input="no\n", target=sentinel)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sentinel.read_text(), "keep me\n")
        self.assertFalse(list(self.root.glob("readerwriter-*")))

    def test_long_confirmation_is_rejected(self):
        result = self.run_client("-rw", input="x" * 5000 + "\n")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.file.read_text(), "original\n")

    def test_cold_start_permissions_and_edit_report(self):
        self.start_server("-t", "-id", "-l")
        self.assertEqual(self.sock.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.sock.stat().st_mode & 0o777, 0o700)
        result = self.run_client("-w", "-t", "-s", "-d")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("There was modification.", result.stdout)
        self.assertIn("+edit", result.stdout)
        self.assertIn("Before modification: 9 bytes", result.stdout)
        self.assertEqual(self.file.read_text(), "original\nedit\n")
        self.assertFalse(list(self.root.glob("readerwriter-*")))
        self.wait_for(lambda: bool(list(self.root.glob("ssu_log.txt.*"))))
        self.assertIn("uid=", (self.root / "ssu_log.txt").read_text())

    def test_noop_and_preserved_mtime_content_detection(self):
        self.start_server()
        result = self.run_client("-w", "-t", env=dict(self.env, TEST_NOOP="1"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("There was no modification.", result.stdout)
        result = self.run_client("-w", "-t", "-d", env=dict(self.env, TEST_KEEP_TIME="1"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("There was modification.", result.stdout)
        self.assertIn("+edit", result.stdout)

    def test_editor_failure_releases_permission(self):
        self.start_server()
        result = self.run_client("-w", env=dict(self.env, EDITOR="/nonexistent/editor"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.file.read_text(), "original\n")
        self.assertFalse(list(self.root.glob("readerwriter-*")))
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_failure_releases_permission(self):
        self.start_server()
        result = self.run_client("-w", env=dict(self.env, TMPDIR=str(self.root / "missing")))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.file.read_text(), "original\n")
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_file_is_rejected(self):
        self.start_server()
        other = self.root / "other.txt"
        other.write_text("other\n")
        result = self.run_client("-w", target=other)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not managed", result.stderr)
        self.assertEqual(other.read_text(), "other\n")

    def test_queue_full_is_explicit(self):
        self.start_server("-n", "1")
        holder = self.active()
        waiting = self.connect_request()
        self.assertEqual(self.status(waiting), QUEUED)
        result = self.run_client("-w")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("queue is full", result.stderr)
        self.done(holder)
        self.assertEqual(self.status(waiting), GRANTED)

    def test_disconnected_waiter_does_not_block_successor(self):
        self.start_server()
        holder = self.active()
        departed = self.connect_request()
        self.assertEqual(self.status(departed), QUEUED)
        successor = self.connect_request()
        self.assertEqual(self.status(successor), QUEUED)
        departed.close()
        self.done(holder)
        self.assertEqual(self.status(successor), GRANTED)

    def test_disconnected_holder_releases_permission(self):
        self.start_server()
        holder = self.active()
        successor = self.connect_request()
        self.assertEqual(self.status(successor), QUEUED)
        holder.close()
        self.assertEqual(self.status(successor), GRANTED)

    def test_burst_requests_are_framed_and_ordered(self):
        self.start_server()
        holder = self.active()
        waiters = []
        for _ in range(8):
            connection = self.connect_request()
            self.assertEqual(self.status(connection), QUEUED)
            waiters.append(connection)
        self.done(holder)
        for connection in waiters:
            self.assertEqual(self.status(connection), GRANTED)
            self.done(connection)

    def test_malformed_packets_do_not_break_server(self):
        self.start_server()
        for packet in (b"bad", struct.pack("=I4096s", 0, b"x"), b"x" * 5000,
                       struct.pack("=I", 0x52573131) + b"x" * 4096):
            with self.subTest(size=len(packet)):
                connection = self.connect_request(packet=packet)
                self.assertEqual(self.status(connection), INVALID)
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wait_timeout_removes_request(self):
        self.start_server()
        holder = self.active()
        result = self.run_client("-w", "--timeout", "1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Timed out", result.stderr)
        self.done(holder)
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_duplicate_daemon_cannot_replace_live_socket(self):
        self.start_server()
        result = subprocess.run([SERVER, str(self.file), "-f", "--socket", str(self.sock)],
                                cwd=self.root, capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_non_socket_is_preserved(self):
        self.sock.parent.mkdir(mode=0o700)
        self.sock.write_text("keep\n")
        result = subprocess.run([SERVER, str(self.file), "-f", "--socket", str(self.sock)],
                                cwd=self.root, capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sock.read_text(), "keep\n")

    def test_graceful_shutdown_waits_for_editor_lease(self):
        self.start_server()
        holder = self.active()
        waiting = self.connect_request()
        self.assertEqual(self.status(waiting), QUEUED)
        self.server.terminate()
        self.assertEqual(self.status(waiting), SHUTDOWN)
        self.assertIsNone(self.server.poll())
        self.done(holder)
        self.assertEqual(self.server.wait(timeout=3), 0)
        self.assertFalse(self.sock.exists())

    def test_wrapper_death_does_not_unlock_running_editor(self):
        self.start_server()
        first = self.spawn([CLIENT, str(self.file), "-w", "--socket", str(self.sock)],
                           dict(self.env, TEST_LABEL="first", TEST_GATE="1"))
        self.wait_for(lambda: (self.root / "started-first").exists())
        first.kill()  # Kill wrapper only; editor must retain the connection.
        first.wait(timeout=3)
        second = self.spawn([CLIENT, str(self.file), "-w", "--socket", str(self.sock)],
                            dict(self.env, TEST_LABEL="second"))
        time.sleep(0.2)
        self.assertFalse((self.root / "started-second").exists())
        (self.root / "gate-first").touch()
        stdout, stderr = second.communicate(timeout=5)
        self.assertEqual(second.returncode, 0, stdout + stderr)
        self.assertEqual(self.file.read_text(), "original\nfirst\nsecond\n")
        self.assertFalse((self.root / "collision").exists())

    def test_parallel_editors_never_overlap(self):
        self.start_server()
        workers = [self.spawn([CLIENT, str(self.file), "-w", "--socket", str(self.sock)],
                              dict(self.env, TEST_LABEL=str(i))) for i in range(8)]
        for worker in workers:
            stdout, stderr = worker.communicate(timeout=6)
            self.assertEqual(worker.returncode, 0, stdout + stderr)
        self.assertFalse((self.root / "collision").exists())
        self.assertEqual(set(self.file.read_text().splitlines()),
                         {"original", *(str(i) for i in range(8))})

    def test_background_startup_and_shutdown(self):
        result = subprocess.run([SERVER, str(self.file), "--socket", str(self.sock)],
                                cwd=self.root, env=self.env, capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        pid = int(result.stdout.split("pid=", 1)[1].strip())
        try:
            result = self.run_client("-w")
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.kill(pid, signal.SIGTERM)
            self.wait_for(lambda: not self.sock.exists())

    def test_stale_socket_restart_without_active_editor(self):
        self.start_server()
        self.server.kill()
        self.server.wait(timeout=3)
        self.assertTrue(self.sock.exists())
        self.start_server()
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_read_write_confirmation_yes(self):
        self.start_server()
        result = self.run_client("-rw", "-t", input="yes\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("original", result.stdout)
        self.assertEqual(self.file.read_text(), "original\nedit\n")

    def test_non_traversable_socket_directory_is_reported(self):
        self.sock.parent.mkdir(mode=0o600)
        try:
            result = subprocess.run([SERVER, str(self.file), "-f", "--socket", str(self.sock)],
                                    cwd=self.root, capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("directory permissions", result.stderr)
        finally:
            self.sock.parent.chmod(0o700)

    def test_default_socket_and_custom_log_directory(self):
        self.server = self.spawn([SERVER, str(self.file), "-f", "-p", "logs"])
        self.wait_for(lambda: (self.root / "tmp" / "readerwriter.sock").exists()
                      or self.server.poll() is not None)
        self.assertIsNone(self.server.poll())
        result = subprocess.run([CLIENT, str(self.file), "-w"], cwd=self.root,
                                env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "logs" / "ssu_log.txt").is_file())


if __name__ == "__main__":
    unittest.main()
