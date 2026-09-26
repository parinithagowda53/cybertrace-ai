from __future__ import annotations

import io
import hashlib
import json
import random
import sqlite3
import zipfile
from pathlib import Path

from PIL import Image
from pypdf import PdfWriter

ROOT = Path(__file__).parent / "evaluation"
RANDOM = random.Random(20260925)


def make_jpeg(path: Path, color: tuple[int, int, int]) -> bytes:
    image = Image.new("RGB", (96, 96), color)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=92)
    data = buffer.getvalue()
    path.write_bytes(data)
    return data


def make_pdf(path: Path) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=240, height=240)
    buffer = io.BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()
    path.write_bytes(data)
    return data


def make_sqlite(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, event TEXT, severity TEXT)")
    connection.executemany("INSERT INTO events (event, severity) VALUES (?, ?)", [("login", "low"), ("database access", "high")])
    connection.commit()
    connection.close()
    return path.read_bytes()


def make_zip(path: Path) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("incident.txt", "Recovered incident evidence\n")
        archive.writestr("timeline.log", "03:01 database access\n")
    return path.read_bytes()


def fragmented(data: bytes, marker: bytes) -> bytes:
    split = max(16, data.find(marker) + len(marker))
    return data[:split] + b"\x00" * 32 + data[split:]


def corrupted(data: bytes, expected_type: str) -> bytes:
    output = bytearray(data)
    if expected_type == "database" and len(output) > 4096:
        output[4096] ^= 0xFF
        return bytes(output)
    start = max(8, len(output) // 3)
    for index in range(start, min(start + 12, len(output))):
        output[index] ^= 0xA5
    return bytes(output[:-8]) if len(output) > 20 else bytes(output)


def write_case(name: str, data: bytes, source_data: bytes, condition: str, expected_type: str) -> dict:
    path = ROOT / name
    path.write_bytes(data)
    return {
        "file": str(path.relative_to(ROOT)),
        "condition": condition,
        "expectedType": expected_type,
        "bytes": len(data),
        "inputSha256": hashlib.sha256(data).hexdigest(),
        "sourceSha256": hashlib.sha256(source_data).hexdigest(),
        "fragmentationMethod": "ordered chunks separated by a synthetic zero-filled gap" if condition == "fragmented" else None,
    }


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    manifest = []
    jpeg = make_jpeg(ROOT / "source_photo.jpg", (40, 150, 90))
    pdf = make_pdf(ROOT / "source_document.pdf")
    sqlite_data = make_sqlite(ROOT / "source_database.sqlite")
    zip_data = make_zip(ROOT / "source_archive.zip")
    sources = [("photo", jpeg, b"JFIF", ".jpg"), ("document", pdf, b"%PDF-", ".pdf"), ("database", sqlite_data, b"database access", ".sqlite"), ("archive", zip_data, b"incident evidence", ".zip")]
    for kind, data, marker, extension in sources:
        manifest.append(write_case(f"intact_{kind}{extension}", data, data, "intact", kind))
        manifest.append(write_case(f"fragmented_{kind}{extension}", fragmented(data, marker), data, "fragmented", kind))
        manifest.append(write_case(f"corrupted_{kind}{extension}", corrupted(data, kind), data, "corrupted", kind))
    for source in ["source_photo.jpg", "source_document.pdf", "source_database.sqlite", "source_archive.zip"]:
        (ROOT / source).unlink(missing_ok=True)
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Created {len(manifest)} evaluation files in {ROOT}")


if __name__ == "__main__":
    main()
