#!/usr/bin/env python3
"""
download_ciadpi.py — скачивание готового бинарника ciadpi из релизов hufrea/byedpi.

Компилировать byedpi из исходников не нужно: берём официальный ассет релиза,
распаковываем в bin/ и делаем исполняемым.

  python host/download_ciadpi.py                # под текущую ОС/архитектуру
  python host/download_ciadpi.py --all          # все платформы (для сборки дистрибутива)
  python host/download_ciadpi.py --version v0.17.3
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import stat
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paths

REPO = "hufrea/byedpi"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
API_TAG = "https://api.github.com/repos/{REPO}/releases/tags/{tag}"
UA = {"User-Agent": "byedpi-firefox-installer", "Accept": "application/vnd.github+json"}

# (platform, arch) -> (суффикс ассета, расширение, имя файла внутри архива, целевое имя)
ASSET_MAP = {
    ("linux", "x86_64"):  ("x86_64", ".tar.gz", None, "ciadpi-linux-x64"),
    ("linux", "i686"):    ("i686", ".tar.gz", None, "ciadpi-linux-i686"),
    ("linux", "aarch64"): ("aarch64", ".tar.gz", None, "ciadpi-linux-aarch64"),
    ("linux", "armv6"):   ("armv6", ".tar.gz", None, "ciadpi-linux-armv6"),
    ("linux", "armv7l"):  ("armv7l", ".tar.gz", None, "ciadpi-linux-armv7l"),
    ("windows", "x86_64"): ("x86_64-w64", ".zip", "ciadpi.exe", "ciadpi-win-x64.exe"),
    ("windows", "i686"):   ("i686-w64", ".zip", "ciadpi.exe", "ciadpi-win-i686.exe"),
}


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_release(version: str = "") -> dict:
    url = API_TAG.format(tag=version) if version else API_LATEST
    try:
        return json.loads(http_get(url, timeout=30).decode("utf-8"))
    except Exception as e:
        raise SystemExit(f"Не удалось получить список релизов {REPO}: {e}\n"
                         "Проверьте интернет или скачайте ciadpi вручную:\n"
                         f"  https://github.com/{REPO}/releases")


def pick_asset(release: dict, plat: str, arch: str):
    spec = ASSET_MAP.get((plat, arch))
    if not spec:
        return None, None
    suffix, ext, inner, target = spec
    for a in release.get("assets", []):
        name = a["name"]
        if name.endswith(ext) and f"-{suffix}" in name:
            return a, {"ext": ext, "inner": inner, "target": target}
    return None, None


def extract_binary(data: bytes, spec: dict) -> bytes:
    if spec["ext"] == ".zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            wanted = spec["inner"]
            for n in names:
                if n.endswith(wanted) or (wanted is None and "ciadpi" in n.lower()):
                    return z.read(n)
            raise SystemExit(f"В архиве не найден {wanted}: {names}")
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t.getmembers():
            if m.isfile() and ("ciadpi" in m.name):
                f = t.extractfile(m)
                if f:
                    return f.read()
    raise SystemExit("В tar-архиве не найден бинарник ciadpi")


def install_binary(raw: bytes, target_name: str, plat: str) -> Path:
    bdir = paths.bin_dir()
    out = bdir / target_name
    tmp = out.with_suffix(".part")
    tmp.write_bytes(raw)
    os.replace(tmp, out)
    if plat != "windows":
        out.chmod(out.stat().st_mode | 0o111)
    return out


def version_of(binary: Path) -> str:
    try:
        import subprocess
        flags = 0x08000000 if paths.IS_WIN else 0
        out = subprocess.run([str(binary), "-v"], capture_output=True, text=True,
                             timeout=8, creationflags=flags)
        txt = (out.stdout or out.stderr).strip().splitlines()
        return txt[0].strip() if txt else ""
    except Exception:
        return ""


def download_one(release: dict, plat: str, arch: str, force: bool = False) -> bool:
    asset, spec = pick_asset(release, plat, arch)
    if not asset:
        print(f"  [{plat}/{arch}] нет готовой сборки в релизе "
              f"{'(для macOS ciadpi нужно собрать вручную: git clone + make)' if plat == 'macos' else ''}")
        return False
    out = paths.bin_dir() / spec["target"]
    if out.is_file() and not force:
        v = version_of(out)
        print(f"  [{plat}/{arch}] уже скачан: {out.name} (v{v or '?'}) — используйте --force")
        return True
    print(f"  [{plat}/{arch}] скачиваю {asset['name']} ({asset['size']/1e6:.2f} МБ)…")
    data = http_get(asset["browser_download_url"], timeout=120)
    raw = extract_binary(data, spec)
    path = install_binary(raw, spec["target"], plat)
    sha = hashlib.sha256(raw).hexdigest()
    meta_path = paths.bin_dir() / "VERSION.json"
    meta = {}
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except ValueError:
            meta = {}
    meta[spec["target"]] = {
        "release": release.get("tag_name"), "asset": asset["name"],
        "platform": plat, "arch": arch, "bytes": len(raw), "sha256": sha,
        "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": asset["browser_download_url"],
        "version": version_of(path) if plat == paths.platform_id() else "",
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [{plat}/{arch}] готово: {path} ({len(raw)} байт, sha256 {sha[:16]}…)")
    if plat == paths.platform_id() and arch == paths.arch():
        v = version_of(path)
        print(f"  [{plat}/{arch}] ciadpi -v => {v or '(не удалось запустить)'}")
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Скачать бинарник ciadpi (byedpi)")
    ap.add_argument("--version", default="", help="тег релиза, например v0.17.3")
    ap.add_argument("--all", action="store_true", help="скачать сборки для всех платформ")
    ap.add_argument("--force", action="store_true", help="перезаписать существующие файлы")
    ns = ap.parse_args(argv)

    print(f"Репозиторий: {REPO}" + (f", тег {ns.version}" if ns.version else " (последний релиз)"))
    release = get_release(ns.version)
    print(f"Релиз: {release.get('tag_name')} от {release.get('published_at','?')[:10]}")
    print(f"Каталог: {paths.bin_dir()}")

    ok = True
    if ns.all:
        for (plat, arch) in ASSET_MAP:
            ok &= download_one(release, plat, arch, force=ns.force)
    else:
        ok = download_one(release, paths.platform_id(), paths.arch(), force=ns.force)

    found = paths.find_binary()
    if found[0]:
        print(f"\nНайден бинарник: {found[0]} (источник: {found[1]})")
    else:
        print("\n" + "!" * 60)
        print("Бинарник ciadpi не найден. Для macOS соберите его вручную:")
        print(f"  git clone https://github.com/{REPO} && cd byedpi && make")
        print("затем укажите путь: python host/ctl.py set binary=/путь/к/ciadpi")
        print("!" * 60)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
