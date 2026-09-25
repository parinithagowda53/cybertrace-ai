# Recovery Intelligence Prototype

A dependency-free functional prototype for the AI-assisted data recovery challenge. It demonstrates file-signature discovery, damaged-cluster detection, integrity and confidence scoring, artifact classification, and recovery recommendations.

The ranking layer uses a dependency-free logistic-regression model trained at startup on labeled recovery examples. It combines integrity, confidence, footer validation, gap coverage, artifact value, and entropy into an ML recovery score. This is a transparent prototype model; production deployment should retrain it on a larger forensic dataset.

Analysis results are persisted in `backend/recovery_cases.sqlite3`, a local SQLite database created automatically on first start. The history endpoint is available at `GET /api/cases`.

Uploaded raw media is also signature-carved into `backend/recovered/`. Each artifact returned by the API includes a download URL such as `/api/recovered/RC-0001/artifact-1`.

Raw forensic images with `.img` and `.dd` extensions use the recovery engine directly. `.E01` and `.EX01` inputs use an optional `pyewf` adapter when that package is available; otherwise the API returns an explicit conversion message and the image should be converted to raw `.dd`/`.img` before upload. The current working build limits uploaded payloads to 25 MB.

## Run

From `backend`:

```powershell
python server.py
```

Open http://127.0.0.1:8000. Select **Run synthetic damaged case** for the prepared demonstration, or upload a binary file/image up to 25 MB.

## Share on the same Wi-Fi

Start the server with `python backend/server.py`, find your computer's IPv4 address with `ipconfig`, and share `http://YOUR_IPV4_ADDRESS:8000`. LAN binding is enabled by default. Allow Python through Windows Firewall on private networks if prompted. This exposes the prototype only to devices that can reach your local network.

For public sharing, deploy the backend to a Python host such as Render, Railway, or PythonAnywhere. Do not expose the development server directly to the public internet; add authentication, HTTPS, upload limits, and isolated storage first.

## Deploy for a friend

Push this repository to GitHub, then create a Render **Web Service** from the repository. Render will use `render.yaml`, install `requirements.txt`, and start `python backend/server.py`. The generated `onrender.com` URL can be shared publicly. GitHub Pages alone cannot run the Python recovery backend.

## Presentation flow

1. Introduce the problem: recovery is not just extraction; investigators need confidence and prioritization.
2. Run the synthetic case and explain how JPEG, PDF, and SQLite signatures become artifacts.
3. Point out integrity, confidence, unresolved clusters, and priority labels.
4. Upload a known file to show the live API path.
5. Explain the production architecture: read-only acquisition and hashing, signature/entropy feature extraction, fragment graph, ML ranking model, analyst review, and export.

## Prototype boundary

This demo intentionally never mutates source media. Its reconstruction model is a transparent heuristic baseline suitable for the hackathon demo; a production system would add filesystem-aware carving, learned fragment adjacency, content validation, and chain-of-custody logging.
