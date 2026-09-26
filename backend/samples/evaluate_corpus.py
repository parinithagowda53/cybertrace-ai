from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server

ROOT = Path(__file__).parent / "evaluation"


def main() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    for sample in manifest:
        started = time.perf_counter()
        input_data = (ROOT / sample["file"]).read_bytes()
        result = server.analyze(input_data, sample["file"])
        expected_type = sample["expectedType"]
        artifact = next((item for item in result["artifacts"] if item["type"] == expected_type), None)
        if artifact is None:
            rows.append({"file": sample["file"], "condition": sample["condition"], "typeCorrect": False, "validOutput": False, "exactSourceMatch": False, "elapsedMs": round((time.perf_counter() - started) * 1000, 2)})
            continue
        carved = input_data[artifact["offset"]:artifact["offset"] + artifact["size"]]
        reconstructed = server.reconstruct_payload(carved, artifact.get("missingClusters", []), expected_type)
        validation = server.validate_artifact(reconstructed, expected_type)
        output_hash = hashlib.sha256(reconstructed).hexdigest()
        rows.append({
            "file": sample["file"],
            "condition": sample["condition"],
            "expectedType": expected_type,
            "detectedType": artifact["type"],
            "typeCorrect": True,
            "validOutput": validation["valid"],
            "exactSourceMatch": output_hash == sample["sourceSha256"],
            "mlScore": artifact["mlScore"],
            "rankedRecoverable": artifact["mlScore"] >= 70,
            "integrityScore": artifact["integrity"],
            "elapsedMs": round((time.perf_counter() - started) * 1000, 2),
            "validation": validation,
        })
    total = len(rows)
    true_positive = sum(row.get("rankedRecoverable", False) and row["validOutput"] for row in rows)
    false_positive = sum(row.get("rankedRecoverable", False) and not row["validOutput"] for row in rows)
    false_negative = sum(not row.get("rankedRecoverable", False) and row["validOutput"] for row in rows)
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    exact_candidates = [row for row in rows if row.get("condition") in ("intact", "fragmented")]
    elapsed = sum(row.get("elapsedMs", 0) for row in rows)
    brier = sum((row.get("mlScore", 0) / 100 - int(row["validOutput"])) ** 2 for row in rows) / max(1, total)
    report = {
        "samples": total,
        "typeAccuracy": round(sum(row["typeCorrect"] for row in rows) / max(1, total) * 100, 1),
        "validOutputRate": round(sum(row["validOutput"] for row in rows) / max(1, total) * 100, 1),
        "exactOriginalReconstructionRate": round(sum(row["exactSourceMatch"] for row in rows) / max(1, total) * 100, 1),
        "exactMatchOnIntactAndFragmented": round(sum(row["exactSourceMatch"] for row in exact_candidates) / max(1, len(exact_candidates)) * 100, 1),
        "rankerThreshold": 70,
        "rankerPrecision": round(precision * 100, 1),
        "rankerRecall": round(recall * 100, 1),
        "rankerF1": round((2 * precision * recall / max(0.000001, precision + recall)) * 100, 1),
        "rankerBrierScore": round(brier, 4),
        "highRankInvalidOutputs": false_positive,
        "evaluationTimeMs": round(elapsed, 2),
        "samplesPerSecond": round(total / max(0.001, elapsed / 1000), 2),
        "bySample": rows,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
