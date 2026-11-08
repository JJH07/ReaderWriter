"""Test the original CLI and FIFO/signals using the actual /usr/bin/vim."""
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVER = str(ROOT / "ssu_ofm")
CLIENT = str(ROOT / "ssu_vim")

VIMRC = r'''
set nocompatible noswapfile noundofile nobackup nowritebackup
set viminfo=
function! TestEdit()
  call writefile([string(getpid())], $CASE_ROOT . '/started-' . $CASE_LABEL)
  if $CASE_GATE == '1'
    let started = reltime()
    while !filereadable($CASE_ROOT . '/gate-' . $CASE_LABEL)
      if reltimefloat(reltime(started)) > 60
        cquit
      endif
      sleep 10m
    endwhile
  endif
  if $CASE_LABEL != 'noop'
    call append(line('$'), $CASE_LABEL)
    silent write
  endif
  qall!
endfunction
autocmd VimEnter * call TestEdit()
'''


class OriginalContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rw-contract-")
        self.root = Path(self.temp.name)
        self.target = self.root / "sample.txt"
        self.target.write_text("original\n")
        os.utime(self.target, (946684800, 946684800))
        rc = self.root / "test.vim"
        rc.write_text(VIMRC)
        self.env = dict(os.environ, VIMINIT="source " + str(rc), TERM="xterm",
                        CASE_ROOT=str(self.root), CASE_LABEL="edited", CASE_GATE="0", TZ="UTC")
        self.clients = []
        self.daemon = None

    def tearDown(self):
        diagnostics = []
        for client in self.clients:
            try:
                os.killpg(client.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                _, stderr = client.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(client.pid, signal.SIGKILL)
                _, stderr = client.communicate(timeout=3)
            diagnostics.append(stderr)
        if self.daemon:
            try:
                os.kill(self.daemon, signal.SIGCONT)
                os.kill(self.daemon, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.wait_for(lambda: not self.process_alive(self.daemon))
        self.temp.cleanup()
        for stderr in diagnostics:
            self.assertNotIn("ERROR: AddressSanitizer", stderr)
            self.assertNotIn("runtime error:", stderr)

    @staticmethod
    def process_alive(pid):
        try:
            value = Path(f"/proc/{pid}/stat").read_text()
            return value.rsplit(")", 1)[1].split()[0] != "Z"
        except FileNotFoundError:
            return False

    def wait_for(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("Timed out waiting for test condition")

    def start_server(self, *options, executable=SERVER):
        result = subprocess.run([executable, "sample.txt", *options], cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Daemon Process Initialization\n")
        directory = self.root
        if "-p" in options:
            directory /= options[options.index("-p") + 1]
        self.log = directory / "ssu_log.txt"
        self.assertTrue(self.log.exists(), "Daemon did not create its log")
        self.assertIn("Initialized with Default", self.log.read_text(),
                      "Daemon returned ready before flushing startup log")
        self.daemon = int(re.search(r"pid : (\d+)>>", self.log.read_text())[1])

    def run_client(self, *options, input=None, target="sample.txt", env=None):
        result = subprocess.run([CLIENT, target, *options], cwd=self.root,
                                env=env or self.env, input=input, text=True,
                                capture_output=True, timeout=12)
        self.assertNotIn("ERROR: AddressSanitizer", result.stderr)
        self.assertNotIn("runtime error:", result.stderr)
        return result

    def spawn_client(self, label, gate=False, *options):
        environment = dict(self.env, CASE_LABEL=label, CASE_GATE="1" if gate else "0")
        process = subprocess.Popen([CLIENT, "sample.txt", "-w", *options], cwd=self.root,
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        self.clients.append(process)
        return process

    def started(self, label):
        return (self.root / ("started-" + label)).exists()

    def release(self, label):
        (self.root / ("gate-" + label)).touch()

    def finish(self, client):
        stdout, stderr = client.communicate(timeout=12)
        self.assertEqual(client.returncode, 0, stdout + stderr)
        return stdout

    def test_only_original_three_files_are_needed_to_build(self):
        build = self.root / "isolated"
        build.mkdir()
        for name in ("ssu_ofm.c", "ssu_vim.c", "Makefile"):
            shutil.copyfile(ROOT / name, build / name)
        result = subprocess.run(["make"], cwd=build, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((build / "ssu_ofm").is_file())
        self.assertTrue((build / "ssu_vim").is_file())
        self.assertEqual(sorted(p.name for p in ROOT.glob("*.c")), ["ssu_ofm.c", "ssu_vim.c"])
        self.assertFalse(list(ROOT.glob("*.h")))

    def test_read_only_stdout_is_unchanged(self):
        result = self.run_client("-r", "-s", "-d")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "original\n")

    def test_time_labels_and_values(self):
        result = self.run_client("-r", "-t")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^##\[Modification Time\]##\nLast Modification time of 'sample.txt': \[2000-01-01 00:00:00\]\nCurrent time: \[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]\noriginal\n$")

    def test_no_daemon_behavior_includes_rw_no(self):
        for mode in ("-w", "-rw"):
            result = self.run_client(mode, input="no\n")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "where is ssu_ofm?\nssu_vim error\n")

    def test_new_options_are_removed(self):
        for options in (("-r", "--timeout", "1"), ("-r", "--socket", "x"), ("--help",)):
            result = self.run_client(*options)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for options in (("-f",), ("--socket", "x"), ("--help",)):
            result = subprocess.run([SERVER, "sample.txt", *options], cwd=self.root,
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 1)

    def test_missing_and_conflicting_arguments_fail_safely(self):
        for command in ([CLIENT], [CLIENT, "sample.txt"], [CLIENT, "sample.txt", "-r", "-w"],
                        [SERVER], [SERVER, "sample.txt", "-n"], [SERVER, "sample.txt", "-p"]):
            result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("runtime error:", result.stderr)

    def test_default_queue_and_fifo_path(self):
        self.start_server()
        self.assertTrue(stat.S_ISFIFO((self.root / "tmp" / "fifo").stat().st_mode))
        self.assertIn("Initialized with Default Value : 16\n", self.log.read_text())
        self.assertFalse(list((self.root / "tmp").glob("*.sock*")))

    def test_n_no_artificial_1024_limit(self):
        self.start_server("-n", "1025")
        self.assertIn("Initialized with Default Value : 1025\n", self.log.read_text())

    def test_cancel_keeps_literal_temp_file_and_exact_prompt(self):
        self.start_server()
        literal = self.root / "tempXXXXXX"
        literal.write_text("keep\n")
        result = self.run_client("-rw", input="no\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "original\n\nWould you like to modify 'sample.txt'? (yes/no) : ")
        self.assertEqual(literal.read_text(), "keep\n")
        self.assertNotIn("Requested Process", self.log.read_text())

    def test_cancel_time_footer_and_unknown_answer(self):
        self.start_server()
        for answer in ("no\n", "x" * 5000 + "\n", ""):
            result = self.run_client("-rw", "-t", input=answer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.endswith("##[Modification Time]##\nThere was no modification.\n"))
        self.assertEqual(self.target.read_text(), "original\n")

    def test_write_uses_original_vim_diff_and_size_labels(self):
        self.start_server()
        result = self.run_client("-w", "-t", "-s", "-d",
                                 env=dict(self.env, EDITOR="/nonexistent/ignored"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("There was modification.\n", result.stdout)
        self.assertIn("##[File Size]##\nBefore modification : 9(bytes)\nAfter modification : 16(bytes)\n", result.stdout)
        self.assertIn("##[Compare with Previous File]##\n1a2\n> edited\n", result.stdout)
        self.assertNotIn("@@", result.stdout)
        self.assertEqual(self.target.read_text(), "original\nedited\n")
        self.assertFalse(list(self.root.glob("temp??????")))

    def test_rw_yes_still_edits(self):
        self.start_server()
        result = self.run_client("-rw", input="yes\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Would you like to modify 'sample.txt'? (yes/no) : ", result.stdout)
        self.assertEqual(self.target.read_text(), "original\nedited\n")

    def test_no_change_does_not_print_size_or_diff(self):
        self.start_server()
        result = self.run_client("-w", "-t", "-s", "-d", env=dict(self.env, CASE_LABEL="noop"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("There was no modification.\n", result.stdout)
        self.assertNotIn("##[File Size]##", result.stdout)
        self.assertNotIn("##[Compare with Previous File]##", result.stdout)

    def test_log_identity_timestamp_and_backup_filename(self):
        import pwd
        user = pwd.getpwuid(os.getuid())
        self.start_server("-t", "-id", "-l", "-p", "logs")
        result = self.run_client("-w")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.wait_for(lambda: "Finished Process ID" in self.log.read_text())
        self.assertIn(f"User : {user.pw_name}, UID : {user.pw_uid}, GID : {user.pw_gid}\n", self.log.read_text())
        self.assertRegex(self.log.read_text(), r"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] Requested Process ID : \d+, Requested Filename : sample.txt")
        self.wait_for(lambda: len(list(self.log.parent.iterdir())) > 1)
        backups = [p for p in self.log.parent.iterdir() if p.name != "ssu_log.txt"]
        self.assertEqual(len(backups), 1)
        self.assertRegex(backups[0].name, r"^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]$")
        self.assertIn("Finished Process ID", backups[0].read_text())

    def test_wrong_filename_uses_original_rejection_message(self):
        self.start_server()
        (self.root / "other").write_text("other\n")
        result = self.run_client("-w", target="other")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Can't Manage File(other) : Incorrect ofm filename\n", result.stdout)

    def test_queue_full_waits_and_eventually_progresses(self):
        self.start_server("-n", "1")
        first = self.spawn_client("first", True)
        self.wait_for(lambda: self.started("first"))
        second = self.spawn_client("second", True)
        self.wait_for(lambda: self.log.read_text().count("Requested Process") >= 2)
        third = self.spawn_client("third")
        time.sleep(1.2)
        self.assertIsNone(third.poll())
        self.release("first")
        self.finish(first)
        self.wait_for(lambda: self.started("second"))
        self.assertFalse(self.started("third"))
        self.release("second")
        self.finish(second)
        self.finish(third)
        self.assertEqual(self.target.read_text(), "original\nfirst\nsecond\nthird\n")

    def test_zero_wait_queue_still_allows_sequential_edits(self):
        self.start_server("-n", "0")
        first = self.spawn_client("first", True)
        self.wait_for(lambda: self.started("first"))
        second = self.spawn_client("second")
        time.sleep(0.2)
        self.assertFalse(self.started("second"))
        self.release("first")
        self.finish(first)
        self.finish(second)

    def test_dead_waiter_does_not_stall_queue(self):
        self.start_server()
        first = self.spawn_client("first", True)
        self.wait_for(lambda: self.started("first"))
        departed = self.spawn_client("departed")
        self.wait_for(lambda: self.log.read_text().count("Requested Process") >= 2)
        departed.kill()
        departed.wait(timeout=3)
        successor = self.spawn_client("successor")
        self.release("first")
        self.finish(first)
        self.finish(successor)
        self.assertFalse(self.started("departed"))

    def test_dead_sender_notice_cannot_consume_successor_request(self):
        # Compile the actual daemon with two scheduling stops around its first
        # orphan-data cleanup. No product flags, protocol changes or sleeps
        # deciding which request wins are needed to force this interleaving.
        import array
        import fcntl
        import termios

        build = self.root / "schedule-test"
        build.mkdir()
        source = build / "schedule.c"
        executable = build / "ssu_ofm"
        source.write_text(r'''
#define _GNU_SOURCE
#include <sys/file.h>
#include <signal.h>
#include <unistd.h>
static int scheduled_flock(int fd, int operation);
#define flock(fd, operation) scheduled_flock((fd), (operation))
#include "ssu_ofm.c"
#undef flock
static int scheduled_flock(int fd, int operation)
{
    static int stage;
    if (fd == fifofd && operation == (LOCK_EX | LOCK_NB) && stage == 0) {
        stage = 1;
        raise(SIGSTOP);
    }
    int result = flock(fd, operation);
    if (fd == fifofd && operation == LOCK_UN && stage == 1 && result == 0) {
        stage = 2;
        raise(SIGSTOP);
    }
    return result;
}
''')
        command = [os.environ.get("TEST_CC", "gcc"), "-std=c11", "-Wall",
                   "-Wextra", "-Wpedantic", "-Werror", "-O1", "-g"]
        if os.environ.get("TEST_SANITIZE") == "true":
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-fno-pie", "-no-pie"]
        command += ["-I", str(ROOT), str(source), "-o", str(executable)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.start_server(executable=str(executable))

        def stopped():
            value = Path(f"/proc/{self.daemon}/stat").read_text()
            return value.rsplit(")", 1)[1].split()[0] == "T"

        def request_pending():
            status = Path(f"/proc/{self.daemon}/status").read_text()
            masks = re.findall(r"^(?:SigPnd|ShdPnd):\s*([0-9a-f]+)$", status, re.M)
            return any(int(mask, 16) & (1 << (signal.SIGUSR1 - 1)) for mask in masks)

        self.wait_for(stopped)
        departed = self.spawn_client("departed")
        self.wait_for(request_pending)
        departed.kill()
        departed.wait(timeout=3)
        os.kill(self.daemon, signal.SIGCONT)

        # The second stop is after cleanup released its FIFO lock. Observe
        # empty FIFO as well as stopped state to distinguish the first stop.
        fd = os.open(self.root / "tmp" / "fifo", os.O_RDONLY | os.O_NONBLOCK)
        try:
            def drained_and_stopped():
                unread = array.array("i", [0])
                fcntl.ioctl(fd, termios.FIONREAD, unread, True)
                return unread[0] == 0 and stopped()
            self.wait_for(drained_and_stopped)
            successor = self.spawn_client("successor")

            def successor_written():
                unread = array.array("i", [0])
                fcntl.ioctl(fd, termios.FIONREAD, unread, True)
                return unread[0] > 0 and request_pending()
            self.wait_for(successor_written)
            os.kill(self.daemon, signal.SIGCONT)
            self.finish(successor)
        finally:
            os.close(fd)
        self.assertEqual(self.target.read_text(), "original\nsuccessor\n")
        self.assertFalse(self.started("departed"))
        self.wait_for(lambda: "Finished Process ID" in self.log.read_text())
        records = self.log.read_text()
        self.assertEqual(records.count("Requested Process ID"), 1)
        self.assertIn(f"Requested Process ID : {successor.pid}, Requested Filename : sample.txt\n", records)
        self.assertIn(f"Finished Process ID : {successor.pid}\n", records)

    def test_request_burst_keeps_filename_and_pid_paired(self):
        self.start_server()
        clients = [self.spawn_client(str(i)) for i in range(6)]
        for client in clients:
            self.finish(client)
        lines = self.target.read_text().splitlines()
        self.assertEqual(len(lines), 7)
        self.assertEqual(set(lines), {"original", *(str(i) for i in range(6))})
        self.assertEqual(self.log.read_text().count("Requested Process ID"), 6)

    def test_default_wait_has_no_thirty_second_limit(self):
        self.start_server()
        first = self.spawn_client("first", True)
        self.wait_for(lambda: self.started("first"))
        second = self.spawn_client("second")
        time.sleep(31)
        self.assertIsNone(second.poll())
        self.assertFalse(self.started("second"))
        self.release("first")
        self.finish(first)
        self.finish(second)

    def test_existing_non_fifo_is_not_removed(self):
        (self.root / "tmp").mkdir()
        (self.root / "tmp" / "fifo").write_text("keep\n")
        result = subprocess.run([SERVER, "sample.txt"], cwd=self.root,
                                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 1)
        self.assertEqual((self.root / "tmp" / "fifo").read_text(), "keep\n")


if __name__ == "__main__":
    unittest.main()
