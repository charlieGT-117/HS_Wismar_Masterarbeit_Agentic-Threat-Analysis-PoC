"""Drawio_Positionen.py: Extrahiert die exakten Elementpositionen aus der XML-Quelle des Architekturdiagramms, ordnet diese über einen Namensabgleich den Modellelementen (E-xx) zu und normalisiert die Koordinaten auf den Bereich 0 bis 1. 
Unterstützt komprimierte und unkomprimierte .drawio-Dateien und vermeidet eine bildbasierte Schätzung der Positionen.
"""

import base64
import difflib
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path


def drawio_pfad() -> str | None:
    """Findet die hochgeladene draw.io-/XML-Quelle."""
    projekt = Path(__file__).resolve().parent
    kandidaten = []
    for endung in ("*.drawio", "*.xml"):
        kandidaten += list((projekt / "Input").glob(endung))
    return str(kandidaten[0]) if kandidaten else None


def _model_aus_diagramm(diag: ET.Element) -> ET.Element:
    """Gibt das mxGraphModel zurueck - auch wenn das Diagramm komprimiert vorliegt."""
    model = diag.find("mxGraphModel")
    if model is not None:
        return model
    roh = (diag.text or "").strip()
    if not roh:
        raise ValueError("Leeres Diagramm.")
    daten = base64.b64decode(roh)
    xml = zlib.decompress(daten, -15).decode("utf-8")   # raw deflate
    xml = urllib.parse.unquote(xml)
    return ET.fromstring(xml)


def _lade_zellen(pfad: str) -> dict:
    """Liest alle mxCell der ERSTEN Seite als {id: {parent, geo, value, vertex}}."""
    root = ET.parse(pfad).getroot()
    diag = root.find("diagram")
    model = _model_aus_diagramm(diag) if diag is not None else root
    cells = {}
    for cell in model.iter("mxCell"):
        geo = cell.find("mxGeometry")
        g = None
        if geo is not None and geo.get("x") is not None:
            g = (float(geo.get("x", 0)), float(geo.get("y", 0)),
                 float(geo.get("width", 0)), float(geo.get("height", 0)))
        cells[cell.get("id")] = {
            "parent": cell.get("parent"),
            "geo": g,
            "value": cell.get("value") or "",
            "vertex": cell.get("vertex") == "1",
        }
    return cells


def _abs_center(cid: str, cells: dict):
    """Absoluter Mittelpunkt eines Kastens (Kindkoordinaten sind relativ zum Container)."""
    g = cells[cid]["geo"]
    if not g:
        return None
    ax = ay = 0.0
    cur = cid
    seen = set()
    while cur in cells and cur not in ("0", "1") and cur not in seen:
        seen.add(cur)
        g2 = cells[cur]["geo"]
        if g2:
            ax += g2[0]
            ay += g2[1]
        cur = cells[cur]["parent"]
    w, h = g[2], g[3]
    return (ax + w / 2, ay + h / 2, w, h)


def _strip(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    return re.sub(r"\s+", " ", text).strip()


def _norm(text: str) -> str:
    text = _strip(text).lower()
    text = re.sub(r"[^a-z0-9äöüß ]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _boxes(cells: dict) -> list:
    """Alle beschrifteten Kaesten mit absolutem Mittelpunkt."""
    out = []
    for cid, c in cells.items():
        if not c["geo"] or not _strip(c["value"]):
            continue
        w, h = c["geo"][2], c["geo"][3]
        if w <= 0 or h <= 0:
            continue
        zentrum = _abs_center(cid, cells)
        if zentrum:
            out.append({"cx": zentrum[0], "cy": zentrum[1], "w": w, "h": h,
                        "label": _strip(c["value"])})
    return out


def _score(a: str, b: str) -> float:
    na, nb = _norm(a), _norm(b)
    if not na or not nb:
        return 0.0
    ratio = difflib.SequenceMatcher(None, na, nb).ratio()
    ta, tb = set(na.split()), set(nb.split())
    overlap = len(ta & tb) / len(ta) if ta else 0.0
    enthalten = 1.0 if (na in nb or nb in na) else 0.0
    return max(ratio, overlap, enthalten * 0.9)


def positionen_aus_drawio(elemente: list, pfad: str, schwelle: float = 0.5):
    """Ordnet Elementen (E-xx mit 'name') die draw.io-Kaesten zu.

    Rueckgabe: (positionen{eid:{x,y}}, zuordnung[list], unklar[list]).
    x,y sind 0..1 relativ zur Gesamtausdehnung der Zeichnung (== PNG-Export).
    """
    cells = _lade_zellen(pfad)
    boxes = _boxes(cells)
    if not boxes:
        return {}, [], [e.get("id") for e in elemente]

    minx = min(b["cx"] - b["w"] / 2 for b in boxes)
    maxx = max(b["cx"] + b["w"] / 2 for b in boxes)
    miny = min(b["cy"] - b["h"] / 2 for b in boxes)
    maxy = max(b["cy"] + b["h"] / 2 for b in boxes)
    spanx = (maxx - minx) or 1.0
    spany = (maxy - miny) or 1.0

    positionen, zuordnung, unklar = {}, [], []
    for e in elemente:
        eid, name = e.get("id"), e.get("name", "")
        best, bestscore = None, 0.0
        for b in boxes:
            s = _score(name, b["label"])
            if s > bestscore:
                best, bestscore = b, s
        if best and bestscore >= schwelle:
            x = (best["cx"] - minx) / spanx
            y = (best["cy"] - miny) / spany
            positionen[eid] = {"x": round(x, 4), "y": round(y, 4)}
            zuordnung.append({"element": eid, "name": name,
                              "kasten": best["label"], "score": round(bestscore, 2)})
        else:
            unklar.append({"element": eid, "name": name,
                           "bester_treffer": best["label"] if best else "-",
                           "score": round(bestscore, 2)})
    return positionen, zuordnung, unklar


if __name__ == "__main__":
    import json
    from ausgabe import AUSGABE
    pfad = drawio_pfad()
    print("draw.io-Quelle:", pfad)
    if pfad:
        modell = json.loads((AUSGABE / "analysemodell.json").read_text(encoding="utf-8"))
        pos, zu, unklar = positionen_aus_drawio(modell.get("elemente", []), pfad)
        print(f"{len(pos)} Elemente positioniert, {len(unklar)} unklar.")
        for z in zu:
            print(f"  {z['element']:6} '{z['name']}' -> Kasten '{z['kasten']}' (Score {z['score']})")
        for u in unklar:
            print(f"  [unklar] {u['element']} '{u['name']}' (bester: '{u['bester_treffer']}', {u['score']})")
