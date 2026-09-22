"""Bild_Marker.py - annotiert das hochgeladene Architektur-Bild mit Findings-Markern.

Ein Architektur-Bild (PNG/JPG) enthaelt keine Koordinaten. Deshalb lokalisiert ein
bildfaehiges Modell EINMALIG jedes Element (E-xx) im Bild und speichert
Naeherungs-Koordinaten (0..1) im Analysemodell (element_positionen, mit Cache).
Danach zeichnet dieses Modul zu jedem Schritt farbige, beschriftete Marker auf eine
Kopie des Bildes:
  - Schritt 2: Angriffsflaechen (AF-xx) auf den betroffenen Elementen,
  - Schritt 4: Bedrohungen (T-xx) auf den betroffenen Elementen,
  - Schritt 5: dieselben Bedrohungen, eingefaerbt nach Prioritaet (hoch/mittel/niedrig).

Die Positionen sind Naeherungen; die begleitende Legende sichert die eindeutige
Zuordnung ueber die Kennungen.
"""

import json
from collections import OrderedDict
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from llm import frage_modell_mit_bild, repariere_json
from ausgabe import AUSGABE
from modelle import modell_fuer, temperatur_fuer

MODELL = modell_fuer("architekt")   # bildfaehig und guenstig
TEMPERATUR = temperatur_fuer("architekt")

AF_FARBE  = "#9673a6"               # Angriffsflaechen (Schritt 2)
STD_FARBE = "#6c8ebf"               # Bedrohungen ohne Prioritaet (Schritt 4)
PRIO_FARBE = {"kritisch": "#7a1f1f", "hoch": "#b85450",
              "mittel": "#d79b00", "niedrig": "#82b366"}  # Schritt 5


# --- Fonts -----------------------------------------------------------------
def _font(size: int):
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


# --- Bild finden -----------------------------------------------------------
def diagramm_pfad() -> str | None:
    """Findet das hochgeladene Architektur-Bild (bevorzugt im Input-Ordner)."""
    projekt = Path(__file__).resolve().parent
    kandidaten = []
    for endung in ("*.png", "*.jpg", "*.jpeg"):
        kandidaten += list((projekt / "Input").glob(endung))
    if not kandidaten:
        for endung in ("*.png", "*.jpg", "*.jpeg"):
            kandidaten += [p for p in projekt.rglob(endung) if "Output" not in p.parts]
    return str(kandidaten[0]) if kandidaten else None


# --- Vision: Element-Positionen (einmalig, mit Cache) ----------------------
def ermittle_element_positionen(modell: dict, bildpfad: str) -> dict:
    """Lokalisiert die Elemente im Bild als 0..1-Koordinaten. Cache in modell['element_positionen']."""
    if modell.get("element_positionen"):
        return modell["element_positionen"]

    elemente = [{"id": e.get("id"), "name": e.get("name"), "art": e.get("art")}
                for e in modell.get("elemente", []) if e.get("id")]
    if not elemente:
        return {}

    auftrag = (
        "Dir liegt ein Architekturdiagramm als Bild vor. Zu jedem unten genannten Element "
        "(mit Name) finde den zugehoerigen BESCHRIFTETEN KASTEN im Bild - ordne ihn ueber "
        "die sichtbare Beschriftung zu, nicht ueber eine Vermutung. Gib die Bounding-Box "
        "dieses Kastens an, als GANZZAHLEN auf einem Raster von 0 bis 1000, wobei (0,0) die "
        "obere linke und (1000,1000) die untere rechte Ecke des GESAMTEN Bildes ist.\n"
        "- x0,y0 = linke obere Ecke des Kastens; x1,y1 = rechte untere Ecke.\n"
        "- Gib NUR Elemente an, deren Kasten du ueber die Beschriftung eindeutig findest.\n"
        "- Erfinde keine Position; lass unklare Elemente weg.\n\n"
        "Antworte ausschliesslich als JSON-Objekt:\n"
        '{"boxen": [{"id": "E-01", "label": "<sichtbare Beschriftung>", '
        '"x0": 40, "y0": 120, "x1": 210, "y1": 180}]}\n\n'
        "ELEMENTE:\n" + json.dumps(elemente, ensure_ascii=False, indent=2)
    )
    roh = frage_modell_mit_bild(auftrag, bildpfad, modell=MODELL, max_tokens=3000,
                                temperatur=TEMPERATUR)
    daten = repariere_json(roh, MODELL)

    pos, zuordnung = {}, []
    for b in daten.get("boxen", daten.get("positionen", [])):
        pid = b.get("id")
        try:
            x0, y0 = float(b.get("x0")), float(b.get("y0"))
            x1, y1 = float(b.get("x1")), float(b.get("y1"))
        except (TypeError, ValueError):
            # Rueckfall auf altes Format (Mittelpunkt x,y als Bruchteil)
            try:
                x, y = float(b.get("x")), float(b.get("y"))
            except (TypeError, ValueError):
                continue
            if pid and 0.0 <= x <= 1.0 and 0.0 <= y <= 1.0:
                pos[pid] = {"x": x, "y": y}
            continue
        cx = (x0 + x1) / 2.0 / 1000.0
        cy = (y0 + y1) / 2.0 / 1000.0
        if pid and 0.0 <= cx <= 1.0 and 0.0 <= cy <= 1.0:
            pos[pid] = {"x": round(cx, 4), "y": round(cy, 4)}
            zuordnung.append({"element": pid, "kasten": b.get("label", "")})

    modell["element_positionen"] = pos
    modell["_pos_quelle"] = "vision"
    modell["_pos_zuordnung"] = zuordnung
    (AUSGABE / "analysemodell.json").write_text(
        json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")
    return pos


def positionen_sicherstellen(modell: dict, bildpfad: str) -> dict:
    """Bestimmt die Element-Positionen. Bevorzugt EXAKT aus der draw.io-Quelle
    (falls hochgeladen), sonst als Fallback per Vision aus dem Bild."""
    try:
        from Drawio_Positionen import drawio_pfad, positionen_aus_drawio
        dpfad = drawio_pfad()
    except Exception:
        dpfad = None

    if dpfad and modell.get("_pos_quelle") != "drawio":
        pos, zuordnung, unklar = positionen_aus_drawio(modell.get("elemente", []), dpfad)
        if pos:
            modell["element_positionen"] = pos
            modell["_pos_quelle"] = "drawio"
            modell["_pos_zuordnung"] = zuordnung
            modell["_pos_unklar"] = unklar
            (AUSGABE / "analysemodell.json").write_text(
                json.dumps(modell, ensure_ascii=False, indent=2), encoding="utf-8")
            return pos

    if modell.get("element_positionen"):
        return modell["element_positionen"]
    return ermittle_element_positionen(modell, bildpfad)


# --- Marker-Listen je Schritt ---------------------------------------------
def marker_angriffsflaechen(modell: dict, nur_ids: list | None = None) -> list:
    out = []
    for af in modell.get("angriffsflaechen", []):
        if nur_ids and af.get("id") not in nur_ids:
            continue
        for eref in af.get("element_refs", []):
            out.append({"element_ref": eref, "id": af.get("id", "AF-?"),
                        "farbe": AF_FARBE, "titel": af.get("name", ""), "extra": ""})
    return out


def marker_bedrohungen(modell: dict, nur_ids: list | None = None) -> list:
    """nur_ids = Liste von Angriffsflaechen-Kennungen (surface_ref); None = alle."""
    out = []
    for t in modell.get("bedrohungen", []):
        if nur_ids and t.get("surface_ref") not in nur_ids:
            continue
        eref = t.get("element_ref")
        if not eref:
            continue
        out.append({"element_ref": eref, "id": t.get("id", "T-?"),
                    "farbe": STD_FARBE, "titel": t.get("titel", ""),
                    "extra": t.get("stride", "")})
    return out


def marker_bewertung(modell: dict) -> list:
    nach_id = {t["id"]: t for t in modell.get("bedrohungen", [])}
    out = []
    for b in modell.get("bewertungen", []):
        t = nach_id.get(b.get("threat_ref"), {})
        eref = t.get("element_ref")
        if not eref:
            continue
        prio = (b.get("prioritaet") or "").lower()
        out.append({"element_ref": eref, "id": b.get("threat_ref", "T-?"),
                    "farbe": PRIO_FARBE.get(prio, STD_FARBE), "titel": t.get("titel", ""),
                    "extra": f"Prio {prio} · Score {b.get('score','?')}"})
    return out


# --- Zeichnen --------------------------------------------------------------
def annotiere(bildpfad: str, positionen: dict, marker: list):
    """Zeichnet die Marker auf eine Bildkopie.

    Rueckgabe: (PIL.Image, platziert: list, fehlende: list) - fehlende sind Marker,
    deren Element keine bekannte Position im Bild hat.
    """
    img = Image.open(bildpfad).convert("RGB")
    W, H = img.size
    draw = ImageDraw.Draw(img)
    fs = max(13, W // 85)
    font = _font(fs)
    r = max(5, W // 170)
    pillh = fs + 8

    grp = OrderedDict()
    for mk in marker:
        grp.setdefault(mk["element_ref"], []).append(mk)

    platziert, fehlende = [], []
    for eref, items in grp.items():
        p = positionen.get(eref)
        if not p:
            fehlende.extend(items)
            continue
        px, py = int(p["x"] * W), int(p["y"] * H)
        draw.ellipse([px - r, py - r, px + r, py + r], fill="#111111", outline="white", width=2)
        for j, it in enumerate(items):
            label = it["id"]
            tw = draw.textlength(label, font=font)
            pw = int(tw) + 16
            x0 = px + r + 6
            y0 = py - pillh // 2 + j * (pillh + 3)
            if x0 + pw > W:                       # nach links kippen, wenn rechts kein Platz
                x0 = px - r - 6 - pw
            y0 = max(0, min(y0, H - pillh))
            draw.rounded_rectangle([x0, y0, x0 + pw, y0 + pillh], radius=6,
                                   fill=it.get("farbe", STD_FARBE), outline="white", width=2)
            draw.text((x0 + 8, y0 + 4), label, fill="white", font=font)
            platziert.append(it)
    return img, platziert, fehlende


if __name__ == "__main__":
    pfad = AUSGABE / "analysemodell.json"
    modell = json.loads(pfad.read_text(encoding="utf-8"))
    bild = diagramm_pfad()
    print("Bild:", bild)
    if bild:
        pos = positionen_sicherstellen(modell, bild)
        print("Positionen:", pos)
        img, platz, fehlt = annotiere(bild, pos, marker_angriffsflaechen(modell))
        ziel = AUSGABE / "marker_angriffsflaechen.png"
        img.save(ziel)
        print("gespeichert:", ziel, "| platziert:", len(platz), "| ohne Position:", len(fehlt))
