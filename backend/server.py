
from __future__ import annotations

import json
import io
import hashlib
import math
import mimetypes
import os
import re
import sqlite3
import struct
import tempfile
import threading
import time
import uuid
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

HOST = os.getenv("RECOVERY_HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
FRONTEND = Path(__file__).parent / "frontend"
DATABASE = Path(__file__).parent / "recovery_cases.sqlite3"
RECOVERED = Path(__file__).parent / "recovered"
EVIDENCE = Path(__file__).parent / "evidence"
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

SIGNATURES = {
    "JPEG photo": (b"\xff\xd8\xff", b"\xff\xd9", "photo", "high"),
    "PNG image": (b"\x89PNG\r\n\x1a\n", b"IEND", "photo", "high"),
    "PDF document": (b"%PDF-", b"%%EOF", "document", "high"),
    "SQLite database": (b"SQLite format 3\x00", b"", "database", "critical"),
    "ZIP archive": (b"PK\x03\x04", b"PK\x05\x06", "archive", "medium"),
}


def sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-max(-30, min(30, value))))


class RecoveryRanker:
    feature_names = ("integrity", "confidence", "footer", "gap_free", "priority", "entropy")

    def __init__(self) -> None:
        training_rows = [
            ([0.95, 0.98, 1, 0.98, 1.0, 0.90], 1),
            ([0.86, 0.91, 1, 0.95, 0.8, 0.75], 1),
            ([0.71, 0.78, 1, 0.72, 0.8, 0.60], 1),
            ([0.48, 0.42, 0, 0.55, 0.5, 0.35], 0),
            ([0.32, 0.27, 0, 0.30, 0.3, 0.20], 0),
            ([0.16, 0.12, 0, 0.18, 0.2, 0.10], 0),
        ]
        self.weights = [0.0] * len(self.feature_names)
        self.bias = 0.0
        for _ in range(500):
            for features, label in training_rows:
                prediction = sigmoid(self.bias + sum(weight * value for weight, value in zip(self.weights, features)))
                error = prediction - label
                self.bias -= 0.08 * error
                self.weights = [weight - 0.08 * error * value for weight, value in zip(self.weights, features)]

    def predict(self, features: dict[str, float]) -> float:
        values = [features[name] for name in self.feature_names]
        return sigmoid(self.bias + sum(weight * value for weight, value in zip(self.weights, values)))


RANKER = RecoveryRanker()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def ranges_for_gaps(data: bytes) -> list[dict]:
    gaps = []
    start = None
    for index, value in enumerate(data):
        missing = value in (0x00, 0xFF)
        if missing and start is None:
            start = index
        elif not missing and start is not None:
            if index - start >= 8:
                gaps.append({"offset": start, "length": index - start, "kind": "unresolved cluster"})
            start = None
    if start is not None and len(data) - start >= 8:
        gaps.append({"offset": start, "length": len(data) - start, "kind": "unresolved cluster"})
    return gaps[:12]


def find_signature(data: bytes, signature: bytes) -> int:
    return data.find(signature) if signature else -1


def decode_ewf(data: bytes) -> bytes:
    try:
        import pyewf
    except ImportError as error:
        raise ValueError("E01/EWF support requires pyewf. Convert the image to raw .dd/.img format, then upload it.") from error
    with tempfile.NamedTemporaryFile(suffix=".E01") as image_file:
        image_file.write(data)
        image_file.flush()
        handle = pyewf.handle()
        handle.open([image_file.name])
        try:
            media_size = handle.get_media_size()
            if media_size > 25 * 1024 * 1024:
                raise ValueError("This working build accepts forensic images up to 25 MB; use a smaller test image or stream a full image in production.")
            chunks = []
            offset = 0
            while offset < media_size:
                chunk_size = min(1024 * 1024, media_size - offset)
                chunks.append(handle.read_buffer_at_offset(chunk_size, offset))
                offset += chunk_size
            return b"".join(chunks)
        finally:
            handle.close()


def find_all_signatures(data: bytes, signature: bytes) -> list[int]:
    offsets = []
    start = 0
    while signature:
        offset = data.find(signature, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + len(signature)
    return offsets


def analyze(data: bytes, filename: str, source: str = "uploaded media") -> dict:
    artifacts = []
    all_headers = sorted(offset for header, _, _, _ in SIGNATURES.values() for offset in find_all_signatures(data, header))
    archive_ranges = []
    for label, (header, footer, category, priority) in SIGNATURES.items():
        for offset in find_all_signatures(data, header):
            if category == "archive" and any(start <= offset < end for start, end in archive_ranges):
                continue
            end = data.find(footer, offset + len(header)) if footer else -1
            if end < 0 and not footer:
                next_header = next((candidate for candidate in all_headers if candidate > offset), len(data))
                recovered_end = next_header
            else:
                recovered_end = end + len(footer) if end >= 0 else len(data)
            if category == "archive" and end >= 0 and end + 22 <= len(data):
                comment_length = struct.unpack_from("<H", data, end + 20)[0]
                recovered_end = min(len(data), end + 22 + comment_length)
            if category == "archive":
                archive_ranges.append((offset, recovered_end))
            payload = data[offset:recovered_end]
            entropy = shannon_entropy(payload)
            missing = ranges_for_gaps(payload)
            completeness = 1.0 if footer and end >= 0 else 0.68
            completeness -= min(0.35, sum(g["length"] for g in missing) / max(1, len(payload)))
            integrity = max(0.05, min(0.99, completeness * 0.75 + min(entropy / 8, 1) * 0.25))
            confidence = max(0.12, min(0.99, integrity + (0.08 if footer and end >= 0 else -0.06)))
            features = {
                "integrity": integrity,
                "confidence": confidence,
                "footer": 1.0 if footer and end >= 0 else 0.0,
                "gap_free": max(0.0, 1.0 - sum(g["length"] for g in missing) / max(1, len(payload))),
                "priority": {"critical": 1.0, "high": 0.8, "medium": 0.5}.get(priority, 0.3),
                "entropy": min(entropy / 8, 1.0),
            }
            ml_score = round(RANKER.predict(features) * 100)
            decision = "restore first" if ml_score >= 80 else "restore after review" if ml_score >= 55 else "manual investigation"
            artifacts.append({
                "id": f"artifact-{len(artifacts) + 1}",
                "name": f"{filename} / {label}",
                "type": category,
                "priority": priority,
                "offset": offset,
                "size": len(payload),
                "integrity": round(integrity * 100),
                "confidence": round(confidence * 100),
                "status": "recoverable" if ml_score >= 70 else "partially recoverable",
                "mlScore": ml_score,
                "mlFeatures": {name: round(value, 3) for name, value in features.items()},
                "missingClusters": missing,
                "decision": decision,
                "evidence": [
                    f"Header signature matched at byte {offset}",
                    "Footer signature confirmed" if footer and end >= 0 else "Footer not found; tail reconstruction applied",
                    f"Entropy profile {entropy:.2f} bits/byte",
                ],
            })

    if not artifacts:
        printable = len(re.findall(rb"[ -~]{6,}", data))
        artifacts.append({
            "id": "artifact-1", "name": f"{filename} / unidentified binary", "type": "system trace",
            "priority": "medium", "offset": 0, "size": len(data), "integrity": 38,
            "confidence": min(75, 25 + printable * 5), "status": "needs review",
            "mlScore": 18, "mlFeatures": {"integrity": 0.38, "confidence": 0.25, "footer": 0.0, "gap_free": 0.5, "priority": 0.5, "entropy": 0.2},
            "missingClusters": ranges_for_gaps(data),
            "evidence": ["No known file signature matched", f"Found {printable} printable regions"],
        })

    artifacts.sort(key=lambda item: item["offset"])
    relationships = []
    graph_nodes = [artifact["id"] for artifact in artifacts]
    node_details = [{"id": artifact["id"], "label": artifact["name"], "kind": "artifact"} for artifact in artifacts]
    for artifact in artifacts:
        for cluster_index, cluster in enumerate(artifact.get("missingClusters", []), start=1):
            cluster_id = f"{artifact['id']}-cluster-{cluster_index}"
            graph_nodes.append(cluster_id)
            node_details.append({"id": cluster_id, "label": f"unresolved cluster · {cluster['length']} bytes", "kind": "cluster"})
            relationships.append({"from": artifact["id"], "to": cluster_id, "gap": cluster["offset"], "relationship": "contains unresolved cluster"})
    for previous, current in zip(artifacts, artifacts[1:]):
        gap = current["offset"] - (previous["offset"] + previous["size"])
        if 0 <= gap <= 256:
            relationships.append({"from": previous["id"], "to": current["id"], "gap": gap, "relationship": "adjacent recovered cluster"})
    gaps = ranges_for_gaps(data)
    recoverable_bytes = sum(a["size"] for a in artifacts)
    return {
        "source": source,
        "filename": filename,
        "mediaSize": len(data),
        "fragmentCount": max(1, len(gaps) + len(artifacts)),
        "unresolvedClusters": len(gaps),
        "recoverableBytes": recoverable_bytes,
        "overallIntegrity": round(sum(a["integrity"] for a in artifacts) / len(artifacts)),
        "artifacts": sorted(artifacts, key=lambda item: (-item["mlScore"], {"critical": 0, "high": 1, "medium": 2}.get(item["priority"], 3))),
        "fragmentGraph": {"nodes": graph_nodes, "nodeDetails": node_details, "edges": relationships},
        "model": {"name": "RecoveryRanker", "type": "logistic regression", "features": list(RANKER.feature_names), "trainingRows": 6},
        "recommendations": [
            "Export high-confidence artifacts before attempting repair of low-confidence clusters.",
            "Preserve the source image read-only and work from a hash-verified copy.",
            "Review unresolved clusters manually; repeated zero-fill suggests overwritten allocation space.",
        ],
    }


def demo_data() -> bytes:
    jpeg = b"\xff\xd8\xff\xe0" + b"JFIF-demo-photo" + bytes(range(1, 80)) + b"\x00" * 12 + b"RECOVERED" + b"\xff\xd9"
    pdf = b"%PDF-1.7\n1 0 obj\n<</Type /Catalog>>\n" + b"\x00" * 16 + b"recovered investigator notes\n%%EOF"
    sqlite = b"SQLite format 3\x00" + b"\x00" * 48 + b"audit_events" + b"\xff" * 10
    return jpeg + b"\x00" * 20 + pdf + b"\xff" * 14 + sqlite


def initialize_database() -> None:
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                overall_integrity INTEGER NOT NULL,
                artifact_count INTEGER NOT NULL,
                result_json TEXT NOT NULL
            )
        """)


def recovered_extension(category: str) -> str:
    return {"photo": ".jpg", "document": ".pdf", "database": ".sqlite", "archive": ".zip"}.get(category, ".bin")


def remove_missing_clusters(payload: bytes, clusters: list[dict]) -> bytes:
    if not clusters:
        return payload
    pieces = []
    cursor = 0
    for cluster in clusters:
        start = max(cursor, cluster["offset"])
        pieces.append(payload[cursor:start])
        cursor = min(len(payload), start + cluster["length"])
    pieces.append(payload[cursor:])
    return b"".join(pieces)


def reconstruct_payload(payload: bytes, clusters: list[dict], category: str) -> bytes:
    if not clusters:
        return payload
    if category not in ("photo", "document", "database", "archive"):
        return remove_missing_clusters(payload, clusters)
    best = None
    cluster_count = min(len(clusters), 12)
    for mask in range(1 << cluster_count):
        selected = [clusters[index] for index in range(cluster_count) if mask & (1 << index)]
        candidate = remove_missing_clusters(payload, selected)
        validation = validate_artifact(candidate, category)
        if validation["valid"]:
            if best is None or len(candidate) > len(best):
                best = candidate
    return best if best is not None else remove_missing_clusters(payload, clusters)


def validate_artifact(data: bytes, category: str) -> dict:
    try:
        if category == "photo":
            from PIL import Image
            with Image.open(io.BytesIO(data)) as image:
                image.verify()
                return {"valid": True, "format": image.format, "width": image.width, "height": image.height}
        if category == "document":
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data), strict=False)
            return {"valid": bool(reader.pages), "format": "PDF", "pages": len(reader.pages)}
        if category == "archive":
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                corrupt_member = archive.testzip()
                return {"valid": corrupt_member is None, "format": "ZIP", "members": len(archive.infolist()), "corruptMember": corrupt_member}
        if category == "database":
            database_file = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
            database_path = Path(database_file.name)
            try:
                database_file.write(data)
                database_file.close()
                connection = sqlite3.connect(database_path)
                try:
                    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                    tables = connection.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]
                finally:
                    connection.close()
                return {"valid": integrity == "ok", "format": "SQLite", "integrityCheck": integrity, "tables": tables}
            finally:
                if not database_file.closed:
                    database_file.close()
                database_path.unlink(missing_ok=True)
    except Exception as error:
        return {"valid": False, "format": category, "error": str(error)}
    return {"valid": False, "format": category, "error": "No validator available"}


def save_case(result: dict, source_data: bytes | None = None) -> dict:
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DATABASE) as connection:
        case_id = f"RC-{connection.execute('SELECT COALESCE(MAX(id), 0) + 1 FROM cases').fetchone()[0]:04d}"
        connection.execute(
            "INSERT INTO cases (case_id, filename, source, created_at, overall_integrity, artifact_count, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, result["filename"], result["source"], created_at, result["overallIntegrity"], len(result["artifacts"]), json.dumps(result)),
        )
    result["caseId"] = case_id
    result["createdAt"] = created_at
    if source_data is not None:
        EVIDENCE.mkdir(exist_ok=True)
        suffix = Path(result["filename"]).suffix.lower() or ".bin"
        evidence_file = EVIDENCE / f"{case_id}_input{suffix}"
        evidence_file.write_bytes(source_data)
        result["inputFile"] = str(evidence_file)
        result["inputUrl"] = f"/api/evidence/{case_id}"
        result["inputSha256"] = hashlib.sha256(source_data).hexdigest()
        result["inputBytes"] = len(source_data)
        result["provenance"] = [{"event": "evidence acquired", "timestamp": created_at, "filename": result["filename"], "sha256": result["inputSha256"], "bytes": len(source_data), "readOnly": True}]
        RECOVERED.mkdir(exist_ok=True)
        for artifact in result["artifacts"]:
            recovered_file = RECOVERED / f"{case_id}_{artifact['id']}{recovered_extension(artifact['type'])}"
            payload = source_data[artifact["offset"]:artifact["offset"] + artifact["size"]]
            reconstructed = reconstruct_payload(payload, artifact.get("missingClusters", []), artifact["type"])
            reconstructed_file = RECOVERED / f"{case_id}_{artifact['id']}_reconstructed{recovered_extension(artifact['type'])}"
            recovered_file.write_bytes(payload)
            reconstructed_file.write_bytes(reconstructed)
            artifact["recoveredFile"] = str(recovered_file)
            artifact["recoveredUrl"] = f"/api/recovered/{case_id}/{artifact['id']}"
            artifact["reconstructedFile"] = str(reconstructed_file)
            artifact["reconstructedUrl"] = f"/api/reconstructed/{case_id}/{artifact['id']}"
            artifact["reconstruction"] = {"method": "removed detected missing clusters", "rawBytes": len(payload), "reconstructedBytes": len(reconstructed), "removedBytes": len(payload) - len(reconstructed)}
            if artifact["type"] == "document":
                try:
                    from pypdf import PdfReader, PdfWriter
                    reader = PdfReader(io.BytesIO(reconstructed), strict=False)
                    writer = PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    normalized = io.BytesIO()
                    writer.write(normalized)
                    reconstructed = normalized.getvalue()
                    reconstructed_file.write_bytes(reconstructed)
                    artifact["documentValidation"] = {"valid": True, "pages": len(reader.pages), "normalization": "rewritten with pypdf"}
                except Exception as error:
                    artifact["documentValidation"] = {"valid": False, "error": str(error)}
            if artifact["type"] == "photo":
                try:
                    from PIL import Image
                    viewable_file = RECOVERED / f"{case_id}_{artifact['id']}_viewable.png"
                    with Image.open(io.BytesIO(reconstructed)) as image:
                        image.load()
                        image.convert("RGB").save(viewable_file, format="PNG")
                    artifact["viewableFile"] = str(viewable_file)
                    artifact["viewableUrl"] = f"/api/viewable/{case_id}/{artifact['id']}"
                except Exception as error:
                    artifact["viewableError"] = f"Reconstructed photo could not be decoded: {error}"
            artifact["validation"] = validate_artifact(reconstructed, artifact["type"])
            if artifact["validation"]["valid"]:
                repaired_bytes = artifact["reconstruction"]["removedBytes"]
                if repaired_bytes:
                    artifact["status"] = "partially recoverable"
                    artifact["decision"] = "restore after review"
                else:
                    artifact["status"] = "recoverable"
                    artifact["decision"] = "restore first" if artifact["integrity"] >= 75 else "restore after review"
                artifact["decisionBasis"] = "format validation and reconstruction evidence"
            else:
                artifact["status"] = "needs review"
                artifact["decision"] = "manual investigation"
                artifact["decisionBasis"] = "format validation failed"
                artifact["evidence"].append("Format validation failed: " + artifact["validation"].get("error", "integrity check failed"))
            artifact["rawSha256"] = hashlib.sha256(payload).hexdigest()
            artifact["reconstructedSha256"] = hashlib.sha256(reconstructed).hexdigest()
            if artifact.get("viewableFile"):
                artifact["viewableSha256"] = hashlib.sha256(Path(artifact["viewableFile"]).read_bytes()).hexdigest()
        with sqlite3.connect(DATABASE) as connection:
            connection.execute("UPDATE cases SET result_json = ? WHERE case_id = ?", (json.dumps(result), case_id))
    return result


def list_cases() -> list[dict]:
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT case_id, filename, source, created_at, overall_integrity, artifact_count FROM cases ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def get_case(case_id: str) -> dict | None:
    with sqlite3.connect(DATABASE) as connection:
        row = connection.execute("SELECT result_json FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    return json.loads(row[0]) if row else None


def update_job(job_id: str, **values) -> None:
    with JOBS_LOCK:
        JOBS[job_id].update(values)


def run_analysis_job(job_id: str, data: bytes, filename: str, source: str = "uploaded media") -> None:
    stages = [
        ("Storage acquisition", 15),
        ("Fragment extraction", 35),
        ("Fragment DNA generation", 50),
        ("Artifact classification", 68),
        ("Fragment relationship analysis", 82),
        ("Reconstruction", 94),
    ]
    try:
        for stage, progress in stages:
            update_job(job_id, stage=stage, progress=progress)
            time.sleep(0.08)
        result = save_case(analyze(data, filename, source), data)
        update_job(job_id, status="complete", stage="Integrity verification", progress=100, result=result)
    except Exception as error:
        update_job(job_id, status="error", stage="Analysis failed", error=str(error))


def evidence_answer(case: dict, question: str) -> dict:
    terms = set(re.findall(r"[a-z0-9]{3,}", question.lower()))
    ranked = []
    for artifact in case["artifacts"]:
        text = " ".join([artifact["name"], artifact["type"], artifact["status"], *artifact["evidence"]]).lower()
        matches = sorted(term for term in terms if term in text)
        ranked.append((len(matches), artifact, matches))
    ranked.sort(key=lambda item: (-item[0], -item[1].get("mlScore", 0)))
    sources = [{"id": artifact["id"], "name": artifact["name"], "matches": matches, "mlScore": artifact.get("mlScore", 0)} for score, artifact, matches in ranked[:4] if score]
    if not sources:
        sources = [{"id": artifact["id"], "name": artifact["name"], "matches": [], "mlScore": artifact.get("mlScore", 0)} for _, artifact, _ in ranked[:3]]
    answer = f"Evidence search found {len(sources)} related artifact(s). " + " ".join(source["name"] + " is ranked " + str(source["mlScore"]) + "% by the recovery model." for source in sources)
    return {"answer": answer, "sources": sources, "mode": "local evidence retrieval"}


def report_text(case: dict) -> str:
    lines = [
        "CYBERTRACE AI - FORENSIC RECOVERY REPORT",
        "=" * 48,
        f"Case ID: {case['caseId']}",
        f"Input: {case['filename']}",
        f"Input SHA-256: {case.get('inputSha256', 'not recorded')}",
        f"Input bytes: {case.get('inputBytes', 'not recorded')}",
        f"Overall integrity: {case['overallIntegrity']}%",
        f"Fragments mapped: {case['fragmentCount']}",
        f"Unresolved clusters: {case['unresolvedClusters']}",
        "",
        "ARTIFACTS",
    ]































































































    for artifact in case["artifacts"]:
        lines.append(f"- {artifact['name']} | {artifact['status']} | integrity {artifact['integrity']}% | ML rank {artifact.get('mlScore', 0)}% | {artifact.get('decision', 'manual investigation')}")
        if artifact.get("validation"):
            lines.append(f"  Validation: {artifact['validation'].get('valid')} | raw SHA-256: {artifact.get('rawSha256', 'not recorded')} | reconstructed SHA-256: {artifact.get('reconstructedSha256', 'not recorded')}")
    lines.extend(["", "PROVENANCE", json.dumps(case.get("provenance", []), indent=2), "", "FRAGMENT RELATIONSHIPS", json.dumps(case.get("fragmentGraph", {}), indent=2), "", "RECOMMENDATIONS"])
    lines.extend(f"- {recommendation}" for recommendation in case["recommendations"])
    return "\n".join(lines)


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200, content_type="application/json"):
        body = payload if isinstance(payload, bytes) else (json.dumps(payload).encode() if content_type == "application/json" else payload.encode())
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(b"", 204)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._send({"ok": True, "service": "recovery-intelligence"})
        if path == "/api/demo":
            data = demo_data()
            return self._send(save_case(analyze(data, "forensic-demo.img", "synthetic damaged media"), data))
        if path == "/api/cases":
            return self._send({"cases": list_cases()})
        if path.startswith("/api/evidence/"):
            case_id = path.rsplit("/", 1)[-1]
            case = get_case(case_id)
            if not case or not case.get("inputFile"):
                return self._send({"error": "evidence not found"}, 404)
            evidence_file = Path(case["inputFile"])
            if not evidence_file.is_file() or evidence_file.parent.resolve() != EVIDENCE.resolve():
                return self._send({"error": "evidence file unavailable"}, 404)
            body = evidence_file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename={evidence_file.name}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            return self._send(job or {"error": "job not found"}, 200 if job else 404)
        if path.startswith("/api/cases/") and path.endswith("/report"):
            case = get_case(path.split("/")[3])
            if not case:
                return self._send({"error": "case not found"}, 404)
            return self._send(report_text(case), content_type="text/plain; charset=utf-8")
        if path.startswith("/api/recovered/") or path.startswith("/api/reconstructed/") or path.startswith("/api/viewable/"):
            parts = path.split("/")
            if len(parts) != 5:
                return self._send({"error": "invalid recovered file path"}, 400)
            case_id, artifact_id = parts[3], parts[4]
            reconstructed = path.startswith("/api/reconstructed/")
            viewable = path.startswith("/api/viewable/")
            with sqlite3.connect(DATABASE) as connection:
                row = connection.execute("SELECT result_json FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return self._send({"error": "case not found"}, 404)
            result = json.loads(row[0])
            artifact = next((item for item in result["artifacts"] if item["id"] == artifact_id), None)
            file_key = "viewableFile" if viewable else "reconstructedFile" if reconstructed else "recoveredFile"
            if not artifact or not artifact.get(file_key):
                return self._send({"error": "recovered artifact not found"}, 404)
            recovered_file = Path(artifact[file_key])
            if not recovered_file.is_file() or recovered_file.parent.resolve() != RECOVERED.resolve():
                return self._send({"error": "recovered file unavailable"}, 404)
            self.send_response(200)
            content_type = mimetypes.guess_type(recovered_file.name)[0] or "application/octet-stream"
            self.send_header("Content-Type", content_type)
            disposition = "inline" if parse_qs(urlparse(self.path).query).get("preview") == ["1"] else "attachment"
            self.send_header("Content-Disposition", f"{disposition}; filename={recovered_file.name}")
            self.send_header("Content-Length", str(recovered_file.stat().st_size))
            self.end_headers()
            self.wfile.write(recovered_file.read_bytes())
            return
        if path == "/samples/fragmented_photo.jpg":
            sample = Path(__file__).parent / "samples" / "fragmented_photo.jpg"
            if sample.is_file():
                body = sample.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Disposition", "attachment; filename=fragmented_photo.jpg")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            return self._send({"error": "sample not found"}, 404)
        if path == "/" or path == "/index.html":
            return self._send((FRONTEND / "index.html").read_bytes(), content_type="text/html; charset=utf-8")
        if path.startswith("/static/"):
            file = FRONTEND / path.removeprefix("/static/")
            if file.exists() and file.is_file():
                return self._send(file.read_bytes(), content_type=mimetypes.guess_type(file.name)[0] or "application/octet-stream")
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/analyze", "/api/jobs", "/api/ask"):
            return self._send({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            if path == "/api/ask":
                request = json.loads(data.decode())
                case = get_case(request.get("caseId", ""))
                if not case:
                    return self._send({"error": "case not found"}, 404)
                return self._send(evidence_answer(case, request.get("question", "")))
            filename = self.headers.get("X-Filename", "uploaded.bin")
            if not data or len(data) > 25 * 1024 * 1024:
                return self._send({"error": "Provide a non-empty file up to 25 MB."}, 400)
            source = "uploaded media"
            if filename.lower().endswith((".e01", ".ex01")):
                data = decode_ewf(data)
                source = "EWF/E01 forensic image"
            if path == "/api/jobs":
                job_id = uuid.uuid4().hex[:12]
                with JOBS_LOCK:
                    JOBS[job_id] = {"jobId": job_id, "status": "running", "stage": "Queued", "progress": 0}
                threading.Thread(target=run_analysis_job, args=(job_id, data, filename, source), daemon=True).start()
                return self._send({"jobId": job_id, "status": "running"}, 202)
            self._send(save_case(analyze(data, filename, source), data))
        except (ValueError, OSError) as error:
            self._send({"error": str(error)}, 400)


if __name__ == "__main__":
    initialize_database()
    print(f"Recovery Intelligence running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
