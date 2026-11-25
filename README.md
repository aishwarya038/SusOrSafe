# SusOrSafe
1. `pip install -r requirements.txt`
2. `cp .env.example .env` and add your API keys (VirusTotal, abuse.ch, Anthropic). OSV.dev needs no key.
3. `python app.py` then open http://localhost:5000
Files are only read as bytes in memory. They are never executed or saved. Hash-only mode uploads nothing.
