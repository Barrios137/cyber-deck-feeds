#!/usr/bin/env python3
"""Espejo de avisos públicos para Cyber Deck (vista «Noticias»).

Las fuentes de dominio público no mandan CORS, así que el widget no puede leerlas
directamente. Este script es el corazón del espejo público
https://github.com/Barrios137/cyber-deck-feeds (creado el 7 de noviembre de 2026), donde
vive como ``mirror.py``: su GitHub Action (``.github/workflows/mirror.yml``) lo ejecuta cada
2 h y publica ``feeds.json``, que el widget pide a
https://raw.githubusercontent.com/Barrios137/cyber-deck-feeds/main/feeds.json (CORS ``*``).
La copia de trabajo está en el repositorio de los widgets, en ``dev/cyber-deck/news-mirror.py``:
las dos se mantienen idénticas.

Fuentes (medidas el 28 de octubre de 2026):
  - CISA, todos los avisos: https://www.cisa.gov/cybersecurity-advisories/all.xml
    (unos 6 MB, casi todo descripciones; se quedan los 60 más recientes)
  - CISA, noticias: https://www.cisa.gov/news.xml
CISA publica obra del Gobierno de EE. UU., de dominio público (17 U.S.C. § 105). No se
usa su logotipo ni se insinúa respaldo.

Del feed sólo salen **título, enlace, fecha, fuente y etiqueta**: ni descripciones, ni
imágenes, ni autores. Sólo biblioteca estándar.

Uso:
    python -I mirror.py                    # escribe feeds.json junto al script
                                           # (en dev/cyber-deck/: dev/cache/cyber-deck/feeds.json)
    python -I mirror.py --out feeds.json   # ruta de salida (la Action)
    python -I mirror.py --check            # sólo valida y resume

Salida:
    {
      "v": 1,
      "generated": "2026-10-28T09:00:00Z",
      "sources": {"cisa": {"name": "CISA", "lang": "en", "home": "https://www.cisa.gov/",
                           "license": "Public domain (17 U.S.C. § 105)"}},
      "items": [{"title": "...", "link": "https://www.cisa.gov/...", "date": "2026-10-27T12:00:00Z",
                 "source": "cisa", "tag": "ics"}, ...]
    }
Etiquetas: alert, advisory, ics, medical, analysis, news, resource y other. Si el contenido
no cambia, ``generated`` conserva el valor del archivo anterior para que la Action no haga
un commit vacío. El código de salida es 1 si una fuente falla o el resultado no supera las
comprobaciones mínimas: la Action no publica y el widget sigue con el último JSON bueno.
"""
import argparse
import datetime as dt
import email.utils
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
# En el repositorio de los widgets la salida va a la caché ignorada por git; en el espejo, al lado.
if HERE.name == "cyber-deck" and HERE.parent.name == "dev":
	DEFAULT_OUT = HERE.parents[1] / "dev" / "cache" / "cyber-deck" / "feeds.json"
else:
	DEFAULT_OUT = HERE / "feeds.json"
USER_AGENT = "cyber-deck-feeds/0.1 (+https://simple-code.cloud; legal@simple-code.cloud)"

SOURCES = {
	"cisa": {
		"name": "CISA",
		"lang": "en",
		"home": "https://www.cisa.gov/",
		"license": "Public domain (17 U.S.C. § 105)",
	},
}

FEEDS = [
	{"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "source": "cisa", "keep": 60, "min": 5},
	{"url": "https://www.cisa.gov/news.xml", "source": "cisa", "keep": 20, "min": 1},
]

# Primer tramo de la ruta tras /news-events/ → etiqueta del widget.
TAGS = {
	"alerts": "alert",
	"cybersecurity-advisories": "advisory",
	"ics-advisories": "ics",
	"ics-medical-advisories": "medical",
	"analysis-reports": "analysis",
	"news": "news",
	"blogs": "news",
}
LINK_OK = re.compile(r"^https://(www\.)?cisa\.gov/\S+$")


def fetch(url: str) -> bytes:
	req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml"})
	with urllib.request.urlopen(req, timeout=60) as resp:
		return resp.read()


def tag_for(link: str) -> str:
	m = re.match(r"^https://(?:www\.)?cisa\.gov/news-events/([^/]+)/", link)
	if m:
		return TAGS.get(m.group(1), "other")
	if re.match(r"^https://(?:www\.)?cisa\.gov/resources-tools/", link):
		return "resource"
	return "other"


def clean_title(text: str) -> str:
	# Algunos feeds traen entidades escapadas dos veces («&amp;amp;»): se deshace una vez.
	text = html.unescape(text or "")
	return re.sub(r"\s+", " ", text).strip()


def parse_date(text: str):
	# CISA usa años de dos cifras («Tue, 27 Oct 26 12:00:00 +0000»); email.utils lo resuelve.
	try:
		d = email.utils.parsedate_to_datetime((text or "").strip())
	except (TypeError, ValueError, IndexError):
		return None
	if d is None:
		return None
	if d.tzinfo is None:
		d = d.replace(tzinfo=dt.timezone.utc)
	return d.astimezone(dt.timezone.utc)


def parse_feed(raw: bytes, feed: dict) -> list:
	root = ET.fromstring(raw)
	channel = root.find("channel")
	if channel is None:
		raise ValueError("no es RSS 2.0")
	base = root.get("{http://www.w3.org/XML/1998/namespace}base") or "https://www.cisa.gov/"
	out = []
	for item in channel.findall("item"):
		title = clean_title(item.findtext("title"))
		link = (item.findtext("link") or "").strip()
		if link.startswith("/"):
			link = base.rstrip("/") + link
		date = parse_date(item.findtext("pubDate"))
		if not title or len(title) > 300 or not LINK_OK.match(link) or date is None:
			continue
		out.append({
			"title": title,
			"link": link,
			"date": date.strftime("%Y-%m-%dT%H:%M:%SZ"),
			"source": feed["source"],
			"tag": tag_for(link),
		})
	# Más recientes primero; a igual fecha se respeta el orden del feed (sort estable).
	out.sort(key=lambda x: x["date"], reverse=True)
	if len(out) < feed["min"]:
		raise ValueError(f"sólo {len(out)} entradas válidas")
	return out[: feed["keep"]]


def build(feeds_raw: dict) -> dict:
	items, seen = [], set()
	for feed in FEEDS:
		for it in parse_feed(feeds_raw[feed["url"]], feed):
			if it["link"] in seen:
				continue
			seen.add(it["link"])
			items.append(it)
	items.sort(key=lambda x: x["date"], reverse=True)
	return {"v": 1, "generated": None, "sources": SOURCES, "items": items}


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

	raw = {}
	for feed in FEEDS:
		try:
			raw[feed["url"]] = fetch(feed["url"])
		except Exception as e:  # noqa: BLE001 — cualquier fallo de red deja el JSON anterior
			print(f"ERROR al descargar {feed['url']}: {e}", file=sys.stderr)
			return 1
	try:
		doc = build(raw)
	except (ET.ParseError, ValueError) as e:
		print(f"ERROR al parsear: {e}", file=sys.stderr)
		return 1

	out = Path(a.out)
	now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	doc["generated"] = now
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
