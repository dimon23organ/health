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

# Имена сервисов в тестовой машине — нейтральные. Реальные названия
# лежат в ~/.config/health/config на конкретной машине и в репозиторий
# не попадают.
SERVICES = ("alpha", "beta", "gamma")


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
    # --- конфиг health: без него скрипт не знает, какие сервисы искать
    hconf = home / ".config" / "health"
    hconf.mkdir(parents=True, exist_ok=True)
    (hconf / "config").write_text(
        "services = %s\nssh_key = ~/.ssh/id_ed25519\n" % ", ".join(SERVICES),
        encoding="utf-8")

    # --- сервисы. Подсунуть свой pid нельзя: health сверяет имя в
    # cmdline именно для того, чтобы ловить переиспользование номера.
    # Поэтому поднимаем настоящие процессы, названные как сервисы.
    # Именно копия бинарника, а не шелл-обёртка: `exec` в обёртке
    # заменяет процесс, и в cmdline остаётся sleep, а не имя сервиса —
    # ровно то, от чего health и защищается.
    bins = home / ".fakebin"
    bins.mkdir(parents=True, exist_ok=True)
    sleep = shutil.which("sleep")
    for name in SERVICES:
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
    key = ssh / "id_ed25519"
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
        p = (self.home / ".config" / "sv" / SERVICES[0]
             / "supervise" / "pid")
        p.write_text("999999")
        self.assertCatches("мёртвый сервис", *run_health(self.home))

    def test_missing_service_is_caught(self):
        shutil.rmtree(self.home / ".config" / "sv" / SERVICES[0])
        self.assertCatches("удалённый сервис", *run_health(self.home))

    def test_quarantine_is_caught(self):
        # Имя файла тут не важно — важно, что он лежит в карантине.
        # Берётся максимально безобидное, чтобы публичный репозиторий
        # не содержал даже намёка на чьи-то настоящие имена.
        (self.home / "Drop" / "md-unsent" / "private-notes.md").write_text("секрет")
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
        key = self.home / ".ssh" / "id_ed25519"
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


class ConfLoading(unittest.TestCase):
    """Конфиг — единственное место, где живёт обстановка машины.

    Значит, читать его надо аккуратно: битая строка не должна молча
    оставлять скрипт в состоянии «всё хорошо» при пустом списке.
    """

    @classmethod
    def setUpClass(cls):
        cls.mod = load()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="health-conf-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.saved = {n: getattr(self.mod, n)
                      for n in ("SERVICES", "SSH_KEY", "SERVER_HOST",
                                "SERVER_PORT")}
        self.addCleanup(
            lambda: [setattr(self.mod, k, v) for k, v in self.saved.items()])

    def write(self, text: str) -> Path:
        p = self.tmp / "config"
        p.write_text(text, encoding="utf-8")
        return p

    def test_services_are_read(self):
        self.assertTrue(self.mod.load_conf(self.write("services = a, b ,c\n")))
        self.assertEqual(self.mod.SERVICES, ("a", "b", "c"))

    def test_comments_and_blank_lines_ignored(self):
        self.write("# так не считается\n\nservices = x, y  # хвост\n")
        self.mod.load_conf(self.tmp / "config")
        self.assertEqual(self.mod.SERVICES, ("x", "y"))

    def test_key_host_and_port(self):
        self.write("ssh_key = ~/.ssh/k\nserver_host = h.example\n"
                   "server_port = 2222\n")
        self.mod.load_conf(self.tmp / "config")
        self.assertEqual(self.mod.SSH_KEY, "~/.ssh/k")
        self.assertEqual(self.mod.SERVER_HOST, "h.example")
        self.assertEqual(self.mod.SERVER_PORT, 2222)

    def test_bad_port_leaves_previous_value(self):
        before = self.mod.SERVER_PORT
        self.write("server_port = не число\n")
        self.mod.load_conf(self.tmp / "config")      # бросать не должен
        self.assertEqual(self.mod.SERVER_PORT, before)

    def test_missing_file_leaves_defaults(self):
        before = self.mod.SERVICES
        self.assertFalse(self.mod.load_conf(self.tmp / "нет-такого"))
        self.assertEqual(self.mod.SERVICES, before)

    def test_empty_services_keeps_previous(self):
        """Пустой services не должен обнулить список: иначе health
        молча перестанет проверять всё."""
        self.mod.load_conf(self.write("services = a, b\n"))
        self.mod.load_conf(self.write("services =\n"))
        self.assertEqual(self.mod.SERVICES, ("a", "b"))


class ShippedDefaults(unittest.TestCase):
    """Репозиторий публичный — в поставляемом коде не должно быть
    обстановки конкретной машины.

    Запрещённый список НЕ зашит в тест. Раньше он был зашит, и сам
    тест становился утечкой: перечисляя имена для поиска, он их и
    публиковал. Теперь список выводится из ~/.config/health/config
    машины, на которой тест идёт.

    Личными считаются адрес сервера и имя ключа. Названия проектов
    вроде tg-logbook — не личные данные, и они в коде остаются:
    скрипт о них и рассказывает.
    """

    @classmethod
    def personal_terms(cls):
        terms = set()
        conf = Path.home() / ".config" / "health" / "config"
        if not conf.exists():
            return terms
        for raw in conf.read_text(encoding="utf-8").splitlines():
            raw = raw.split("#", 1)[0].strip()
            if "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key not in ("server_host", "server_port"):
                continue
            if not value:
                continue
            terms.add(value)
            terms.add(value.split(".")[0]) if "." in value else None
        # Имя ключа берём только из имени файла.
        for raw in conf.read_text(encoding="utf-8").splitlines():
            raw = raw.split("#", 1)[0].strip()
            if raw.startswith("ssh_key"):
                value = raw.split("=", 1)[1].strip()
                name = Path(value).name
                if len(name) >= 4:
                    terms.add(name)
        return {t for t in terms if t and len(t) >= 4}

    def test_source_avoids_personal_terms(self):
        terms = self.personal_terms()
        if not terms:
            self.skipTest("нет ~/.config/health/config — нечего сверять")
        for path in (SCRIPT, HERE / "README.md"):
            if not path.exists():
                continue
            src = path.read_text(encoding="utf-8")
            for term in sorted(terms):
                self.assertNotIn(
                    term, src,
                    "в %s осталось машинное: %s" % (path.name, term))

    def test_source_has_no_lan_addresses(self):
        import re as _re
        for path in (SCRIPT, HERE / "README.md"):
            if not path.exists():
                continue
            src = path.read_text(encoding="utf-8")
            found = _re.findall(
                r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.[0-9.]+\b", src)
            self.assertEqual(found, [],
                             "в %s адрес локальной сети: %s" % (path.name, found))

    def test_shipped_defaults_are_placeholders(self):
        """Значения по умолчанию в коде обязаны быть заглушками."""
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('SERVICES = ("my-service",)', src,
                      "по умолчанию должно быть нейтральное имя сервиса")
        self.assertIn('SERVER_HOST = "192.0.2.1"', src,
                      "адрес по умолчанию должен быть из 192.0.2.0/24")
        self.assertIn('SSH_KEY = "~/.ssh/id_ed25519"', src)


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