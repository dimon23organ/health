#!/usr/bin/env python3
"""Проверки самого health.

Смысл любой диагностики — в том, что она ловит поломку. Скрипт,
который всегда говорит «всё живо», хуже отсутствия скрипта: он
убеждает, что всё в порядке, когда это не так. Поэтому здесь
проверяется не «запускается», а «на подсунутой поломке переходит
в СТОП».

    python3 tests/test_health.py
"""

import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
SCRIPT = HERE / "bin" / "health"


def load():
    loader = importlib.machinery.SourceFileLoader("healthmod", str(SCRIPT))
    spec = importlib.util.spec_from_loader("healthmod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def run_health(home: Path) -> tuple[int, str]:
    """Запускает health как настоящий процесс с подменённым HOME."""
    env = dict(os.environ, HOME=str(home), NO_COLOR="1")
    res = subprocess.run([sys.executable, str(SCRIPT), "--no-color"],
                         capture_output=True, text=True, env=env, timeout=120)
    return res.returncode, res.stdout


def scratch_dir(prefix: str) -> Path:
    """Каталог на настоящем разделе, а не в /tmp.

    В /tmp у нас 7.8 ГБ, и проверка диска честно предупреждает об этом.
    Тест «чистая машина» должен проходить по существу, а не упираться
    в размер временного каталога.
    """
    base = Path.home() / ".local" / "state" / "health-selftest"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


FAKE_PROCS: list = []


def kill_fakes() -> None:
    while FAKE_PROCS:
        proc = FAKE_PROCS.pop()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


class Baseline(unittest.TestCase):
    """Чистая машина обязана проходить. Всё остальное — на фоне этого."""

    def setUp(self):
        self.home = scratch_dir("health-ok-")
        self.addCleanup(kill_fakes)
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        build_fake_machine(self.home)

    def test_clean_machine_passes(self):
        code, out = run_health(self.home)
        self.assertEqual(code, 0, "чистая машина не прошла:\n%s" % out)

    def test_exit_code_is_zero_when_all_ok(self):
        code, _ = run_health(self.home)
        self.assertEqual(code, 0)


def build_fake_machine(home: Path) -> None:
    """Домашний каталог, на котором все проверки должны быть зелёными."""
    # --- сервисы. Подсунуть свой pid нельзя: health сверяет имя в
    # cmdline именно для того, чтобы ловить переиспользование номера.
    # Поэтому поднимаем настоящие процессы, названные как сервисы.
    # Именно копия бинарника, а не шелл-обёртка: `exec` в обёртке
    # заменяет процесс, и в cmdline остаётся sleep, а не имя сервиса —
    # ровно то, от чего health и защищается.
    bins = home / ".fakebin"
    bins.mkdir(parents=True, exist_ok=True)
    sleep = shutil.which("sleep")
    for name in ("autosync-dima", "tg-logbook", "opencode-db-backup"):
        shim = bins / name
        shutil.copy2(sleep, shim)
        shim.chmod(0o755)
        proc = subprocess.Popen([str(shim), "120"])
        FAKE_PROCS.append(proc)

        d = home / ".config" / "sv" / name / "supervise"
        d.mkdir(parents=True, exist_ok=True)
        (d.parent / "run").write_text("#!/bin/sh\nexec %s 120\n" % sleep)
        (d / "pid").write_text(str(proc.pid))
        logd = home / ".local" / "state" / "sv" / name
        logd.mkdir(parents=True, exist_ok=True)
        (logd / "current").write_text("всё хорошо\n")

    # --- бэкапы: настоящая база со снимком внутри
    snaps = home / ".local" / "state" / "opencode-backups"
    snaps.mkdir(parents=True, exist_ok=True)
    db = snaps / "opencode-2026-10-13_10-00.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE session_v2 (id TEXT PRIMARY KEY)")
    con.execute("INSERT INTO session_v2 VALUES ('ses_1')")
    con.commit()
    con.close()

    # --- карантин пуст
    (home / "Drop" / "md-unsent").mkdir(parents=True, exist_ok=True)

    # --- свежий кит
    kit = home / "Drop" / "Server"
    kit.mkdir(parents=True, exist_ok=True)
    (kit / "void-kit.7z").write_bytes(b"PK\x03\x04" + b"x" * 2048)

    # --- telegram: взведён, права 600
    tgc = home / ".config" / "tg-logbook"
    tgc.mkdir(parents=True, exist_ok=True)
    (tgc / "config.json").write_text(json.dumps({
        "token": "1234567890:AAHfakefakefakefakefakefakefake",
        "armed": True, "allowed_chats": ["-1001"]}), encoding="utf-8")
    (tgc / "config.json").chmod(0o600)

    # --- ключ к серверу
    ssh = home / ".ssh"
    ssh.mkdir(parents=True, exist_ok=True)
    key = ssh / "dima_server"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    key.chmod(0o600)

    # --- конфиг opencode
    oc = home / ".config" / "opencode"
    (oc / "agent").mkdir(parents=True, exist_ok=True)
    (oc / "skills").mkdir(parents=True, exist_ok=True)
    (oc / "opencode.jsonc").write_text('{"model": "opencode/space-bunny-free"}',
                                       encoding="utf-8")
    (oc / "agent" / "build.md").write_text("# build\n", encoding="utf-8")
    sk = oc / "skills" / "void-linux"
    sk.mkdir(parents=True, exist_ok=True)
    (sk / "SKILL.md").write_text("# void-linux\n", encoding="utf-8")


class Faults(unittest.TestCase):
    """Каждая поломка — отдельный случай. Ни одна не должна проходить."""

    def setUp(self):
        self.home = scratch_dir("health-bad-")
        self.addCleanup(kill_fakes)
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        build_fake_machine(self.home)

    def assertCatches(self, what: str, code: int, out: str) -> None:
        self.assertEqual(code, 2, "%s НЕ поймана, код %d:\n%s" % (what, code, out))
        self.assertIn("СТОП", out, "%s: нет пометки СТОП" % what)

    def test_dead_service_is_caught(self):
        # pid, которого не существует
        p = self.home / ".config" / "sv" / "tg-logbook" / "supervise" / "pid"
        p.write_text("999999")
        self.assertCatches("мёртвый сервис", *run_health(self.home))

    def test_missing_service_is_caught(self):
        shutil.rmtree(self.home / ".config" / "sv" / "tg-logbook")
        self.assertCatches("удалённый сервис", *run_health(self.home))

    def test_quarantine_is_caught(self):
        (self.home / "Drop" / "md-unsent" / "llm.md").write_text("секрет")
        self.assertCatches("файл в карантине", *run_health(self.home))

    def test_corrupt_snapshot_is_caught(self):
        snaps = self.home / ".local" / "state" / "opencode-backups"
        for f in snaps.glob("*.db"):
            f.unlink()
        (snaps / "opencode-2026-10-13_10-00.db").write_text("не база")
        self.assertCatches("повреждённый снимок", *run_health(self.home))

    def test_empty_snapshot_is_caught(self):
        snaps = self.home / ".local" / "state" / "opencode-backups"
        for f in snaps.glob("*.db"):
            f.unlink()
        empty = snaps / "opencode-2026-10-13_10-00.db"
        con = sqlite3.connect(str(empty))
        con.execute("CREATE TABLE session_v2 (id TEXT PRIMARY KEY)")
        con.commit()
        con.close()
        self.assertCatches("пустой снимок", *run_health(self.home))

    def test_stale_backups_are_caught(self):
        snaps = self.home / ".local" / "state" / "opencode-backups"
        old = snaps / "opencode-2026-09-01_10-00.db"
        shutil.copy2(next(snaps.glob("*.db")), old)
        for f in snaps.glob("*.db"):
            if f != old:
                f.unlink()
        stale = time.time() - 5 * 86400
        os.utime(old, (stale, stale))
        self.assertCatches("протухший бэкап", *run_health(self.home))

    def test_no_backups_at_all_is_caught(self):
        shutil.rmtree(self.home / ".local" / "state" / "opencode-backups")
        self.assertCatches("бэкапов нет вовсе", *run_health(self.home))

    def test_loose_token_permissions_are_caught(self):
        cfg = self.home / ".config" / "tg-logbook" / "config.json"
        cfg.chmod(0o644)
        self.assertCatches("права на конфиг бота", *run_health(self.home))

    def test_empty_token_is_caught(self):
        cfg = self.home / ".config" / "tg-logbook" / "config.json"
        data = json.loads(cfg.read_text())
        data["token"] = ""
        cfg.write_text(json.dumps(data))
        cfg.chmod(0o600)
        self.assertCatches("пустой токен", *run_health(self.home))

    def test_loose_key_permissions_are_caught(self):
        key = self.home / ".ssh" / "dima_server"
        key.chmod(0o644)
        self.assertCatches("права на ключ", *run_health(self.home))

    def test_missing_kit_is_caught(self):
        (self.home / "Drop" / "Server" / "void-kit.7z").unlink()
        self.assertCatches("нет кита", *run_health(self.home))

    def test_pause_flag_is_a_warning(self):
        (self.home / ".config" / "tg-logbook" / "PAUSE").write_text("")
        code, out = run_health(self.home)
        self.assertEqual(code, 1, "PAUSE должен быть предупреждением, не поломкой")
        self.assertIn("ВНИМАНИЕ", out)


class Units(unittest.TestCase):
    """Мелочи, на которых скрипт может тихо врать."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load()

    def test_proc_info_on_this_process(self):
        info = self.mod.proc_info(os.getpid())
        self.assertIsNotNone(info, "свой собственный процесс не найден")
        cmd, uptime = info
        self.assertIn("python", cmd)
        self.assertGreater(uptime, 0)
        self.assertLess(uptime, 86400, "аптайм собственного процесса подозрительно велик")

    def test_proc_info_on_dead_pid(self):
        self.assertIsNone(self.mod.proc_info(999999))

    def test_human_sizes(self):
        self.assertEqual(self.mod.human(0), "0 Б")
        self.assertEqual(self.mod.human(1023), "1023 Б")
        self.assertTrue(self.mod.human(1536).startswith("1.5"))

    def test_age_words(self):
        self.assertIn("с", self.mod.age_words(30))
        self.assertIn("мин", self.mod.age_words(600))
        self.assertIn("ч", self.mod.age_words(7200))
        self.assertIn("дн", self.mod.age_words(3 * 86400))


if __name__ == "__main__":
    unittest.main(verbosity=2)