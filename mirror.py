#!/usr/bin/env python3
"""Espejo de avisos públicos de CISA para Cyber Deck (vista «Noticias»).

El widget no puede leer las fuentes de CISA directamente (no mandan CORS). Este script es el
corazón del espejo público https://github.com/Barrios137/cyber-deck-feeds (creado el 7 de
noviembre de 2026), donde vive como ``mirror.py``: su GitHub Action
(``.github/workflows/mirror.yml``) lo ejecuta cada 2 h y publica ``feeds.json``, que el widget
pide a https://raw.githubusercontent.com/Barrios137/cyber-deck-feeds/main/feeds.json (CORS ``*``).
La copia de trabajo está en el repositorio de los widgets, en ``dev/cyber-deck/news-mirror.py``:
las dos se mantienen idénticas.

Fuentes: los repositorios de datos oficiales de CISA en GitHub. Los RSS de cisa.gov
(``cybersecurity-advisories/all.xml`` y ``news.xml``) responden 403 a los servidores de las
GitHub Actions (medido el 7 de noviembre de 2026), y no se disfrazan las peticiones para
saltarse ese bloqueo.
  - Avisos ICS y de vulnerabilidades en CSAF: https://github.com/cisagov/CSAF
    (``csaf_files/{OT,IT}/white/<año>/*.json``; se leen los 40 más recientes).
  - Catálogo KEV: https://github.com/cisagov/kev-data (CC0 1.0); una entrada por día de altas.
El contenido de CISA es obra del Gobierno de EE. UU., de dominio público (17 U.S.C. § 105).
No se usa su logotipo ni se insinúa respaldo.

Del aviso sólo salen **título, enlace, fecha, fuente y etiqueta**: ni descripciones, ni
puntuaciones. Sólo biblioteca estándar. En la Action, ``GITHUB_TOKEN`` autentica la única
llamada a la API de GitHub (el árbol del repositorio CSAF).

Uso:
    python -I mirror.py                    # escribe feeds.json junto al script
                                           # (en dev/cyber-deck/: dev/cache/cyber-deck/feeds.json)
    python -I mirror.py --out feeds.json   # ruta de salida (la Action)
    python -I mirror.py --check            # sólo valida y resume

Salida:
    {
      "v": 1,
      "generated": "2026-11-07T09:00:00Z",
      "sources": {"cisa": {"name": "CISA", "lang": "en", "home": "https://www.cisa.gov/",
                           "license": "Public domain (17 U.S.C. § 105); KEV data CC0 1.0"}},
      "items": [{"title": "...", "link": "https://www.cisa.gov/...", "date": "2026-11-03T06:00:00Z",
                 "source": "cisa", "tag": "ics"}, ...]
    }
Etiquetas: ics (ICSA), medical (ICSMA), advisory (VA y demás) y alert (altas en el KEV). Si el
contenido no cambia, ``generated`` conserva el valor del archivo anterior para que la Action
no haga un commit vacío. El código de salida es 1 si una fuente falla o el resultado no supera
las comprobaciones mínimas: la Action no publica y el widget sigue con el último JSON bueno.
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
# En el repositorio de los widgets la salida va a la caché ignorada por git; en el espejo, al lado.
if HERE.name == "cyber-deck" and HERE.parent.name == "dev":
	DEFAULT_OUT = HERE.parents[1] / "dev" / "cache" / "cyber-deck" / "feeds.json"
else:
	DEFAULT_OUT = HERE / "feeds.json"
USER_AGENT = "cyber-deck-feeds/0.2 (+https://github.com/Barrios137/cyber-deck-feeds; legal@simple-code.cloud)"

SOURCES = {
	"cisa": {
		"name": "CISA",
		"lang": "en",
		"home": "https://www.cisa.gov/",
		"license": "Public domain (17 U.S.C. § 105); KEV data CC0 1.0",
	},
}

CSAF_TREE = "https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1"
CSAF_RAW = "https://raw.githubusercontent.com/cisagov/CSAF/develop/"
KEV_JSON = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

ADVISORIES_KEEP = 40   # avisos CSAF más recientes
ADVISORIES_MIN = 10
KEV_DAYS = 45          # días de altas en el KEV que se resumen
TOTAL_KEEP = 60

LINK_OK = re.compile(r"^https://(www\.)?cisa\.gov/\S+$")
CSAF_PATH = re.compile(r"^csaf_files/(OT|IT)/white/(\d{4})/([a-z]+)-(\d{2})-(\d{3})-(\d{2})\.json$")


def fetch(url: str, api: bool = False) -> bytes:
	headers = {"User-Agent": USER_AGENT}
	if api:
		headers["Accept"] = "application/vnd.github+json"
		token = os.environ.get("GITHUB_TOKEN")
		if token:
			headers["Authorization"] = "Bearer " + token
	req = urllib.request.Request(url, headers=headers)
	with urllib.request.urlopen(req, timeout=60) as resp:
		return resp.read()


def iso(text: str):
	"""«2026-11-03T06:00:00.000000Z» o «2026-11-03» → «2026-11-03T06:00:00Z» (UTC)."""
	text = (text or "").strip()
	if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
		text += "T12:00:00Z"  # el KEV sólo da el día; CISA publica sus altas hacia el mediodía
	try:
		d = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
	except ValueError:
		return None
	if d.tzinfo is None:
		d = d.replace(tzinfo=dt.timezone.utc)
	return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(text: str) -> str:
	return re.sub(r"\s+", " ", text or "").strip()


# ---------- Avisos CSAF ----------

def newest_advisories(tree: dict) -> list:
	"""Rutas de los avisos más recientes, por su identificador (año-día-número)."""
	if tree.get("truncated"):
		raise ValueError("el árbol de cisagov/CSAF llegó truncado")
	this_year = dt.datetime.now(dt.timezone.utc).year
	found = []
	for node in tree.get("tree", []):
		m = CSAF_PATH.match(node.get("path", ""))
		if node.get("type") != "blob" or not m or int(m.group(2)) < this_year - 1:
			continue
		found.append(((m.group(4), m.group(5), m.group(6), m.group(3)), m.group(3), node["path"]))
	found.sort(reverse=True)
	return [(kind, path) for _, kind, path in found[:ADVISORIES_KEEP]]


def advisory_item(kind: str, doc: dict):
	d = doc.get("document", {})
	if str(d.get("distribution", {}).get("tlp", {}).get("label", "")).upper() not in ("WHITE", "CLEAR"):
		return None
	title = clean(d.get("title"))
	date = iso(d.get("tracking", {}).get("initial_release_date"))
	link = ""
	for ref in d.get("references", []):
		url = str(ref.get("url", ""))
		if ref.get("category") == "self" and LINK_OK.match(url) and "/news-events/" in url:
			link = url
			break
	if not title or len(title) > 300 or not date or not link:
		return None
	tag = {"icsa": "ics", "icsma": "medical"}.get(kind, "advisory")
	return {"title": title, "link": link, "date": date, "source": "cisa", "tag": tag}


# ---------- Catálogo KEV ----------

def kev_name(v: dict) -> str:
	# «WordPress» + «WordPress Core» → «WordPress Core»; «Ivanti» + «Connect Secure» → «Ivanti Connect Secure».
	vendor, product = clean(v.get("vendorProject")), clean(v.get("product"))
	return product if product.lower().startswith(vendor.lower()) else clean(f"{vendor} {product}")


def kev_items(kev: dict) -> list:
	by_day = {}
	for v in kev.get("vulnerabilities", []):
		day = str(v.get("dateAdded", ""))
		if re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
			by_day.setdefault(day, []).append(v)
	if not by_day:
		raise ValueError("el KEV llegó vacío")
	cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=KEV_DAYS)).strftime("%Y-%m-%d")
	out = []
	for day in sorted(by_day, reverse=True):
		if day < cutoff:
			break
		vulns = sorted(by_day[day], key=lambda v: str(v.get("cveID", "")))
		names = [kev_name(v) + f" ({v.get('cveID', '')})" for v in vulns[:3]]
		more = f" and {len(vulns) - 3} more" if len(vulns) > 3 else ""
		n = len(vulns)
		head = "Known exploited vulnerability added to the KEV catalog" if n == 1 else f"{n} known exploited vulnerabilities added to the KEV catalog"
		out.append({
			"title": f"{head}: {', '.join(names)}{more}"[:300],
			"link": KEV_PAGE,
			"date": iso(day),
			"source": "cisa",
			"tag": "alert",
		})
	return out


def build() -> dict:
	tree = json.loads(fetch(CSAF_TREE, api=True))
	items, seen = [], set()
	for kind, path in newest_advisories(tree):
		it = advisory_item(kind, json.loads(fetch(CSAF_RAW + path)))
		if it and it["link"] not in seen:
			seen.add(it["link"])
			items.append(it)
	if len(items) < ADVISORIES_MIN:
		raise ValueError(f"sólo {len(items)} avisos CSAF válidos")
	items += kev_items(json.loads(fetch(KEV_JSON)))
	# Más recientes primero; a igual fecha, los avisos antes que el resumen del KEV (sort estable).
	items.sort(key=lambda x: x["date"], reverse=True)
	return {"v": 1, "generated": None, "sources": SOURCES, "items": items[:TOTAL_KEEP]}


def dump(doc: dict) -> str:
	# Un titular por línea: los diffs del repositorio del espejo se leen solos.
	head = json.dumps({k: doc[k] for k in ("v", "generated", "sources")}, ensure_ascii=False, separators=(",", ":"))
	lines = ",\n".join(json.dumps(it, ensure_ascii=False, separators=(",", ":")) for it in doc["items"])
	return head[:-1] + ',"items":[\n' + lines + "\n]}\n"


def main() -> int:
	ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
	ap.add_argument("--out", default=str(DEFAULT_OUT))
	ap.add_argument("--check", action="store_true", help="valida y resume sin escribir")
	a = ap.parse_args()
	try:
		sys.stdout.reconfigure(encoding="utf-8")  # consola de Windows
	except (AttributeError, ValueError):
		pass

	try:
		doc = build()
	except Exception as e:  # noqa: BLE001 — cualquier fallo deja el JSON anterior
		print(f"ERROR: {e}", file=sys.stderr)
		return 1

	out = Path(a.out)
	doc["generated"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	if out.exists():
		try:
			prev = json.loads(out.read_text(encoding="utf-8"))
			if prev.get("items") == doc["items"] and prev.get("sources") == doc["sources"] and prev.get("generated"):
				doc["generated"] = prev["generated"]
		except (ValueError, OSError):
			pass

	tags = {}
	for it in doc["items"]:
		tags[it["tag"]] = tags.get(it["tag"], 0) + 1
	newest = doc["items"][0]["date"] if doc["items"] else "-"
	print(f"{len(doc['items'])} titulares · más reciente {newest} · " + ", ".join(f"{k} {v}" for k, v in sorted(tags.items())))
	if a.check:
		return 0
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(dump(doc), encoding="utf-8", newline="\n")
	print(out)
	return 0


if __name__ == "__main__":
	sys.exit(main())
