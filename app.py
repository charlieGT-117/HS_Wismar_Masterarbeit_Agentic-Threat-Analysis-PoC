"""Frontend (Streamlit) fuer den Threat-Analyse-Prototyp.

Bindet die Pipeline in eine Oberflaeche: Eingabe -> Systemmodell -> HITL-Freigabe
-> Angriffsflaechen -> TI -> Bedrohungen -> Bewertung -> priorisierte Liste + Bericht.
Die Oberflaeche enthaelt KEINE eigene Logik: sie ruft dieselben Funktionen wie die
Skripte und zeigt das wachsende Analysemodell.

Starten:  streamlit run app.py
"""

import json
import re
from pathlib import Path

import pandas as pd
import streamlit as st

from Agent_CISO import entwickle_systemmodell, ueberarbeite_mit_antworten
from Agent_Pruefer import pruefe_systemmodell
from CISO_Angriffsflaechen import ableite_angriffsflaechen
from Agent_TI import recherchiere, lade_quellen, speichere_ti_befunde
from CISO_Bedrohungen import bedrohungen_je_flaeche, lade_methodik
from CISO_Bewertung import bewerte, lade_scoring, priorisierte_liste
from CISO_Bericht import erzeuge_bericht
from Wissensbasis import frage_wissensbasis
from Bild_Marker import (diagramm_pfad, positionen_sicherstellen, annotiere,
                         marker_angriffsflaechen, marker_bedrohungen, marker_bewertung)
from ausgabe import AUSGABE
import metriken

ORDNER = Path(__file__).resolve().parent
INPUT = ORDNER / "Input"
INPUT.mkdir(exist_ok=True)

st.set_page_config(page_title="Threat Analyse - Prototyp", layout="wide")


def speichere_modell():
    (AUSGABE / "analysemodell.json").write_text(
        json.dumps(st.session_state.modell, ensure_ascii=False, indent=2), encoding="utf-8")


for schluessel, wert in {"modell": None, "pruefbericht": None, "freigegeben": False}.items():
    st.session_state.setdefault(schluessel, wert)


def hat(schluessel: str) -> bool:
    return bool(st.session_state.modell and st.session_state.modell.get(schluessel))


def _dot(text: str) -> str:
    return (text or "").replace('"', "'").replace("\n", " ")


def zeige_findings_im_bild(marker: list, titel: str):
    """Zeigt das hochgeladene Architektur-Bild mit Markern der Findings plus Legende."""
    if not marker:
        return
    m = st.session_state.modell
    st.markdown(f"**{titel}**")
    bild = diagramm_pfad()
    if not bild:
        st.caption("Kein Architektur-Bild hochgeladen – Findings werden nur als Liste gezeigt.")
    else:
        try:
            if not m.get("element_positionen"):
                with st.spinner("Positionen der Elemente im Bild werden bestimmt (einmalig) ..."):
                    positionen_sicherstellen(m, bild)
                    speichere_modell()
            pos = m.get("element_positionen", {})
            quelle = m.get("_pos_quelle", "vision")
            img, platziert, fehlende = annotiere(bild, pos, marker)
            hinweis = ("exakt aus draw.io-Quelle" if quelle == "drawio"
                       else "automatisch aus dem Bild erkannt (Näherung)")
            st.image(img, use_container_width=True,
                     caption=f"Positionsquelle: {hinweis} – Zuordnung über die Kennungen eindeutig (Legende).")
            cols = st.columns([1, 3])
            if cols[0].button("🔄 Positionen neu bestimmen", key=f"repos_{titel}"):
                m.pop("element_positionen", None)
                m.pop("_pos_quelle", None)
                speichere_modell()
                st.rerun()
            if fehlende:
                cols[1].caption("Ohne erkannte Position (nur in der Legende): "
                                + ", ".join(sorted({f["id"] for f in fehlende})))
        except Exception as e:
            st.warning(f"Marker-Bild nicht möglich ({e}). Findings folgen als Liste.")
    # Legende (dedupliziert nach ID)
    gesehen, zeilen = set(), []
    for mk in marker:
        if mk["id"] in gesehen:
            continue
        gesehen.add(mk["id"])
        zeilen.append({"ID": mk["id"], "Element": mk["element_ref"],
                       "Titel": mk.get("titel", ""), "Detail": mk.get("extra", "")})
    if zeilen:
        st.dataframe(zeilen, use_container_width=True, hide_index=True)


def systemmodell_als_dot(m: dict) -> str:
    formen = {"process": "box", "datastore": "cylinder", "external_entity": "component"}
    zeilen = ["digraph Systemmodell {", "  rankdir=LR;",
              '  node [style=filled, fillcolor="#eef2ff", fontname="Helvetica"];']
    for e in m.get("elemente", []):
        form = formen.get(e.get("art", ""), "box")
        zeilen.append(f'  "{e.get("id")}" [label="{_dot(e.get("id"))}\\n{_dot(e.get("name"))}", shape={form}];')
    for df in m.get("datenfluesse", []):
        stil = 'color="#dc2626", style=dashed, penwidth=2' if df.get("ueberschreitet_grenze") else 'color="#475569"'
        zeilen.append(f'  "{_dot(df.get("quelle"))}" -> "{_dot(df.get("ziel"))}" '
                      f'[label="{_dot(df.get("daten"))}", fontsize=9, {stil}];')
    zeilen.append("}")
    return "\n".join(zeilen)


st.title("Threat Analyse - Prototyp")
st.caption("Ein CISO-Agent orchestriert Architekt, SW-Engineer, TI-Agent und Prüf-Agent. "
           "Das gemeinsame Analysemodell wächst über die Schritte.")

# --- Eingabe (Sidebar) -----------------------------------------------------
with st.sidebar:
    st.header("Eingabe")
    diagramm = st.file_uploader("Architekturdiagramm (PNG/JPG)", type=["png", "jpg", "jpeg"])
    if diagramm:
        (INPUT / diagramm.name).write_bytes(diagramm.getbuffer())
        st.success(f"Diagramm gespeichert: {diagramm.name}")
    drawio = st.file_uploader("Architektur als draw.io/XML (für exakte Marker-Positionen)",
                              type=["drawio", "xml"])
    if drawio:
        (INPUT / drawio.name).write_bytes(drawio.getbuffer())
        st.success(f"draw.io-Quelle gespeichert: {drawio.name} – Marker werden exakt gesetzt.")
        if st.session_state.get("modell"):
            st.session_state.modell.pop("element_positionen", None)
            st.session_state.modell.pop("_pos_quelle", None)
    beschreibung = st.file_uploader("Systembeschreibung (optional, .md)", type=["md"])
    if beschreibung:
        (INPUT / "Systembeschreibung.md").write_bytes(beschreibung.getbuffer())
        st.success("Systembeschreibung gespeichert")
    st.divider()
    st.caption("Ablauf: Systemmodell → Freigabe → Angriffsflächen → TI → "
               "Bedrohungen → Bewertung → Bericht")


# --- Schritt 1: Systemmodell + Prüfung -------------------------------------
st.subheader("1 · Systemmodell entwickeln")
if st.button("Systemmodell entwickeln", type="primary"):
    with st.spinner("CISO analysiert das Diagramm, befragt die Fachagenten ..."):
        metriken.starte_lauf()                          # neuer Lauf: Zeit/Token-Zähler zurücksetzen
        modell = entwickle_systemmodell()
        st.session_state.modell = modell
        speichere_modell()                              # Analysemodell schreiben ...
        st.session_state.pruefbericht = pruefe_systemmodell()   # ... der Prüfer liest es
        st.session_state.freigegeben = False
        metriken.stufe("Stufe 1 – Systemmodell + Prüfung")
    st.rerun()

if st.session_state.modell:
    m = st.session_state.modell
    c1, c2, c3 = st.columns(3)
    c1.metric("Elemente", len(m.get("elemente", [])))
    c2.metric("Datenflüsse", len(m.get("datenfluesse", [])))
    c3.metric("Assets", len(m.get("assets", [])))

    st.markdown("**Systemmodell als Diagramm** (rot gestrichelt = grenzüberschreitender Datenfluss)")
    if m.get("elemente"):
        st.graphviz_chart(systemmodell_als_dot(m), use_container_width=True)
    if m.get("vertrauensgrenzen"):
        st.caption("Vertrauensgrenzen: " + " · ".join(
            f"{v.get('id')} {v.get('name','')}" for v in m["vertrauensgrenzen"]))

    dialog = m.get("fachagenten_dialog", [])
    if dialog:
        with st.expander(f"Rückfragen des CISO an die Fachagenten ({len(dialog)})"):
            for k in dialog:
                st.markdown(f"**CISO → {k.get('gefragt_wen','')}**: {k.get('frage','')}")
                antw = k.get("antwort")
                if isinstance(antw, dict):
                    st.caption("Antwort: " + (antw.get("antwort") or antw.get("luecke") or "—"))
                    if antw.get("beleg"):
                        st.caption(f"Beleg: „{antw['beleg']}“")
                    if antw.get("rueckfrage"):
                        st.caption(f"↳ Rückfrage an den Nutzer: {antw['rueckfrage']}")
                else:
                    st.caption(f"Antwort: {antw}")

    with st.expander("Systemmodell (JSON)"):
        st.json({k: m[k] for k in ("elemente", "datenfluesse", "vertrauensgrenzen",
                                    "assets", "annahmen") if k in m})

    if st.session_state.pruefbericht:
        pb = st.session_state.pruefbericht
        st.markdown("**Prüfbericht des unabhängigen Prüf-Agenten**")
        st.write("Ergebnis:", "✅ bestanden" if pb.get("bestanden") else "⚠️ nicht bestanden")
        for mg in pb.get("maengel", []):
            st.write(f"- [{mg.get('schwere','?')}] {mg.get('bezug','')}: {mg.get('problem','')}")

    if not st.session_state.freigegeben:
        st.markdown("#### Human-in-the-Loop: prüfen und entscheiden")
        offene = m.get("rueckfragen_nutzer", [])
        antworten = {}
        if offene:
            st.caption("Offene Rückfragen des CISO – du kannst sie beantworten (optional):")
            for i, f in enumerate(offene):
                antworten[f] = st.text_input(f, key=f"rf_{i}")
        anmerkung = st.text_area("Weitere Anmerkung an den CISO (optional)", key="hitl_note")

        cA, cB, cC = st.columns(3)
        if cA.button("↻ Antworten einarbeiten & erneut prüfen"):
            eingaben = {f: a for f, a in antworten.items() if a and a.strip()}
            if anmerkung.strip():
                eingaben["Weitere Anmerkung des Nutzers"] = anmerkung
            if eingaben:
                with st.spinner("CISO arbeitet deine Antworten ein und prüft erneut ..."):
                    neu = ueberarbeite_mit_antworten(m, eingaben)
                    st.session_state.modell = neu
                    speichere_modell()
                    st.session_state.pruefbericht = pruefe_systemmodell()
                st.rerun()
            else:
                st.info("Bitte zuerst eine Antwort oder Anmerkung eingeben.")
        if cB.button("✔ Modell genehmigen", type="primary"):
            st.session_state.freigegeben = True
            st.rerun()
        if cC.button("✖ Abbrechen"):
            st.session_state.modell = None
            st.session_state.pruefbericht = None
            st.session_state.freigegeben = False
            st.rerun()
    else:
        st.success("Systemmodell genehmigt.")

st.divider()

# --- Schritt 2: Angriffsflächen --------------------------------------------
st.subheader("2 · Angriffsflächen ableiten")
if st.button("Angriffsflächen ableiten", disabled=not st.session_state.freigegeben):
    with st.spinner("CISO leitet Angriffsflächen ab ..."):
        st.session_state.modell["angriffsflaechen"] = ableite_angriffsflaechen(st.session_state.modell)
        speichere_modell()
        metriken.stufe("Stufe 2 – Angriffsflächen")
    st.rerun()
if hat("angriffsflaechen"):
    st.metric("Angriffsflächen", len(st.session_state.modell["angriffsflaechen"]))
    zeige_findings_im_bild(
        marker_angriffsflaechen(st.session_state.modell),
        "Angriffsflächen im Architekturbild")
    with st.expander("Angriffsflächen (JSON)"):
        st.json(st.session_state.modell["angriffsflaechen"])

st.divider()

# --- Schritt 3: TI-Recherche -----------------------------------------------
st.subheader("3 · Threat-Intelligence recherchieren (live)")
if not hat("angriffsflaechen"):
    st.button("TI-Recherche starten", disabled=True)
    st.caption("Erst Schritt 2 (Angriffsflächen) ausführen.")
else:
    optionen = {f"{f.get('id')} – {f.get('name','')}": f.get("id")
                for f in st.session_state.modell["angriffsflaechen"]}
    auswahl = st.multiselect(
        "Welche Angriffsflächen soll der TI-Agent recherchieren? (je Fläche ein Web-Such-Aufruf)",
        list(optionen.keys()), default=list(optionen.keys())[:1],
        help="Zum Token-Sparen wenige auswählen.")
    if st.button("TI-Recherche starten", disabled=not auswahl):
        ids = [optionen[a] for a in auswahl]
        with st.spinner(f"TI-Agent recherchiert live für {len(ids)} Angriffsfläche(n) ..."):
            st.session_state.modell["ti_befunde"] = recherchiere(
                st.session_state.modell, lade_quellen(), nur_ids=ids)
            speichere_modell()
            speichere_ti_befunde(st.session_state.modell["ti_befunde"],
                                 st.session_state.modell.get("ti_diagnose"))
            metriken.stufe("Stufe 3 – Threat-Intelligence (Websuche)")
        st.rerun()
if hat("ti_befunde"):
    st.metric("TI-Befunde", len(st.session_state.modell["ti_befunde"]))
    _ti_datei = AUSGABE / "ti_befunde.json"
    if _ti_datei.exists():
        st.download_button("⬇ TI-Befunde (ti_befunde.json)", _ti_datei.read_text(encoding="utf-8"),
                           file_name="ti_befunde.json")
    with st.expander("TI-Befunde (mit Belegen)"):
        for a in st.session_state.modell["ti_befunde"]:
            st.write(f"**{a.get('identifier','')}** [{a.get('klasse','')}] → {a.get('surface_ref','')}")
            st.caption(f"{a.get('summary','')}  \nBeleg: {a.get('source_url','')}")
elif st.session_state.modell and st.session_state.modell.get("ti_diagnose"):
    diag = st.session_state.modell["ti_diagnose"]
    st.warning("Es wurden **keine belegten TI-Befunde** gespeichert. Grund je Angriffsfläche:")
    for d in diag:
        st.write(f"- **{d.get('surface_ref','?')}** [{d.get('status','?')}]: {d.get('hinweis','')}")
    if any(d.get("status") == "fehler" for d in diag):
        st.info("Häufigste Ursache: Die **Websuche** ist für den API-Key nicht aktiviert oder "
                "es fehlt Guthaben. Prüfe im Anthropic-Konto, dass *Web Search* aktiviert und "
                "genügend Guthaben vorhanden ist.")
    with st.expander("Roh-Auszug der Modellantwort (zur Fehlersuche)"):
        for d in diag:
            if d.get("roh_auszug"):
                st.caption(f"{d.get('surface_ref','?')}:")
                st.code(d["roh_auszug"])

st.divider()

# --- Schritt 4: Bedrohungen identifizieren und analysieren -----------------
st.subheader("4 · Bedrohungen identifizieren und analysieren")
if not hat("angriffsflaechen"):
    st.button("Bedrohungen identifizieren und analysieren", disabled=True)
    st.caption("Erst Schritt 2 (Angriffsflächen) ausführen.")
else:
    m = st.session_state.modell
    analysiert = {a.get("surface_ref") for a in m.get("abdeckung", [])}
    offen = [f for f in m["angriffsflaechen"] if f.get("id") not in analysiert]
    optionen = {f"{f.get('id')} – {f.get('name','')}": f.get("id") for f in offen}

    if m.get("bedrohungen"):
        st.metric("Bedrohungen bisher", len(m["bedrohungen"]))

    if optionen:
        auswahl = st.multiselect(
            "Welche Angriffsflächen analysieren? (inkrementell, je Fläche ein Aufruf)",
            list(optionen.keys()), default=list(optionen.keys())[:1], key="threat_select")
        if st.button("Bedrohungen identifizieren und analysieren", disabled=not auswahl):
            ids = [optionen[a] for a in auswahl]
            with st.spinner(f"CISO analysiert {len(ids)} Angriffsfläche(n) ..."):
                vorhanden = m.get("bedrohungen", [])
                neu_b, neu_abd = bedrohungen_je_flaeche(
                    m, lade_methodik(), nur_ids=ids, start_index=len(vorhanden))
                m["bedrohungen"] = vorhanden + neu_b
                m["abdeckung"] = m.get("abdeckung", []) + neu_abd
                m["bedrohungen_freigegeben"] = False   # nach Änderung erneut freigeben (FA-17)
                m["bewertungen"] = []                  # geänderter Umfang → alte Bewertung verwerfen
                speichere_modell()
                metriken.stufe("Stufe 4 – Bedrohungen identifizieren/analysieren")
            st.rerun()
    else:
        st.success("Alle Angriffsflächen analysiert.")

    if m.get("bedrohungen"):
        zeige_findings_im_bild(
            marker_bedrohungen(m), "Identifizierte Bedrohungen im Architekturbild")
        with st.expander(f"Bedrohungsanalyse – Szenario, Voraussetzungen, Auswirkung ({len(m['bedrohungen'])})"):
            for t in m["bedrohungen"]:
                st.markdown(f"**`{t.get('id','')}` {t.get('titel','')}**  ·  {t.get('stride','')} "
                            f"· {t.get('element_ref','')} / {t.get('surface_ref','')}")
                if t.get("szenario"):
                    st.caption(f"Angriffsszenario: {t['szenario']}")
                if t.get("voraussetzungen"):
                    vor = t["voraussetzungen"]
                    vor = "; ".join(map(str, vor)) if isinstance(vor, list) else vor
                    st.caption(f"Voraussetzungen: {vor}")
                if t.get("auswirkung"):
                    st.caption(f"Auswirkung: {t['auswirkung']}")

st.divider()

# --- Schritt 4b: HITL – Bedrohungen prüfen, korrigieren, freigeben (FA-17) --
st.subheader("4b · Bedrohungen prüfen und freigeben (Human-in-the-Loop)")
if not hat("bedrohungen"):
    st.caption("Erst Schritt 4 (Bedrohungen identifizieren) ausführen.")
else:
    m = st.session_state.modell
    st.caption("Häkchen in **übernehmen** = diese Bedrohung wird bewertet. "
               "Häkchen entfernen = verwerfen. Zellen bearbeiten = korrigieren, "
               "neue Zeile = ergänzen. **Nur angehakte Bedrohungen** gehen in Schritt 5.")
    orig_by_id = {t.get("id"): t for t in m["bedrohungen"]}

    def _txt(v):
        return "; ".join(map(str, v)) if isinstance(v, list) else (v or "")

    rows = [{"uebernehmen": True, "id": t.get("id", ""), "titel": t.get("titel", ""),
             "stride": t.get("stride", ""), "element_ref": t.get("element_ref", ""),
             "surface_ref": t.get("surface_ref", ""), "szenario": _txt(t.get("szenario")),
             "voraussetzungen": _txt(t.get("voraussetzungen")),
             "auswirkung": _txt(t.get("auswirkung")), "beschreibung": t.get("beschreibung", "")}
            for t in m["bedrohungen"]]
    edited = st.data_editor(
        pd.DataFrame(rows), num_rows="dynamic", use_container_width=True, hide_index=True,
        column_config={"uebernehmen": st.column_config.CheckboxColumn(
                           "übernehmen", help="Angehakt = wird bewertet", width="small"),
                       "id": st.column_config.TextColumn("ID", disabled=True)},
        key="threat_editor")

    _ausgewaehlt = int(edited["uebernehmen"].fillna(False).sum()) if "uebernehmen" in edited else 0
    st.caption(f"Ausgewählt: **{_ausgewaehlt}** Bedrohung(en) werden bewertet.")

    def _uebernehmen_aus_tabelle():
        """Baut die Bedrohungsliste aus dem aktuellen Tabellenstand neu auf: Es bleiben
        NUR die angehakten (übernehmen) Zeilen; alte Bewertungen werden verworfen."""
        nums = [int(re.sub(r"\D", "", str(i)) or 0) for i in orig_by_id]
        naechste = max(nums or [0])
        neu = []
        for _, r in edited.iterrows():
            if not bool(r.get("uebernehmen")):
                continue   # nicht angehakt -> nicht übernehmen
            if not str(r.get("titel") or "").strip():
                continue   # leere neue Zeile ignorieren
            tid = str(r.get("id") or "").strip()
            if tid and tid in orig_by_id:
                base = dict(orig_by_id[tid])
            else:
                naechste += 1
                tid = f"T-{naechste:02d}"
                base = {"id": tid, "ti_refs": [], "methodik": "manuell", "begruendung": ""}
            base.update({"id": tid, "titel": r.get("titel", ""), "stride": r.get("stride", ""),
                         "element_ref": r.get("element_ref", ""), "surface_ref": r.get("surface_ref", ""),
                         "szenario": r.get("szenario", ""), "voraussetzungen": r.get("voraussetzungen", ""),
                         "auswirkung": r.get("auswirkung", ""), "beschreibung": r.get("beschreibung", "")})
            neu.append(base)
        m["bedrohungen"] = neu
        m["bewertungen"] = []          # geänderter Umfang → alte Bewertung verwerfen
        return len(neu)

    if st.button("✔ Auswahl freigeben → Bewertung", type="primary"):
        anzahl = _uebernehmen_aus_tabelle()   # übernimmt den aktuellen Tabellenstand
        m["bedrohungen_freigegeben"] = True
        speichere_modell()
        st.success(f"{anzahl} Bedrohung(en) freigegeben – nur diese werden in Schritt 5 bewertet.")
        st.rerun()

    if m.get("bedrohungen_freigegeben"):
        st.success("Bedrohungen freigegeben – die Bewertung ist freigeschaltet.")
    else:
        st.info("Bitte die Bedrohungen prüfen und freigeben, bevor bewertet wird.")

st.divider()

# --- Schritt 5: Bewertung + Priorisierung ----------------------------------
st.subheader("5 · Bewerten und priorisieren")
_bedrohungen_bereit = hat("bedrohungen") and st.session_state.modell.get("bedrohungen_freigegeben")
if not _bedrohungen_bereit and hat("bedrohungen"):
    st.caption("Erst in Schritt 4b die Bedrohungen freigeben.")
if st.button("Bewerten & priorisieren", disabled=not _bedrohungen_bereit):
    with st.spinner("CISO bewertet und priorisiert ..."):
        scoring = lade_scoring()
        st.session_state.modell["bewertungen"] = bewerte(st.session_state.modell, scoring)
        st.session_state.modell["scoring_schema"] = scoring
        metriken.stufe("Stufe 5 – Bewertung/Priorisierung")
        st.session_state.modell["laufmetriken"] = metriken.schnappschuss()  # Zeit/Token je Lauf
        metriken.schreibe()                                                 # Output/lauf_metriken.json
        speichere_modell()
    st.rerun()

if hat("bewertungen"):
    liste = priorisierte_liste(st.session_state.modell)
    st.markdown("### Priorisierte Bedrohungsliste")
    st.dataframe(
        [{"ID": r["id"], "Priorität": r["prioritaet"], "Score": r["score"],
          "STRIDE": r["stride"], "Titel": r["titel"], "Fläche": r["surface_ref"]} for r in liste],
        use_container_width=True, hide_index=True)

    st.caption("Marker-Farben nach Priorität: kritisch (dunkelrot) · hoch (rot) · "
               "mittel (orange) · niedrig (grün)")
    zeige_findings_im_bild(
        marker_bewertung(st.session_state.modell),
        "Priorisierte Bedrohungen im Architekturbild (Farbe = Priorität)")

    bericht = erzeuge_bericht(st.session_state.modell)
    (AUSGABE / "bericht.md").write_text(bericht, encoding="utf-8")
    c1, c2, c3 = st.columns(3)
    c1.download_button("⬇ Bericht (Markdown)", bericht, file_name="bericht.md")
    c2.download_button("⬇ Analysemodell (JSON)",
                       json.dumps(st.session_state.modell, ensure_ascii=False, indent=2),
                       file_name="analysemodell.json")
    _metriken = st.session_state.modell.get("laufmetriken", metriken.schnappschuss())
    c3.download_button("⬇ Laufmetriken (JSON)",
                       json.dumps(_metriken, ensure_ascii=False, indent=2),
                       file_name="lauf_metriken.json")
    with st.expander("⏱ Laufmetriken – Zeit & Tokenverbrauch"):
        _t = _metriken.get("tokens", {})
        k1, k2, k3 = st.columns(3)
        k1.metric("Tokens gesamt", f"{_t.get('gesamt', 0):,}".replace(",", "."))
        k2.metric("Aktive Modellzeit", f"{_metriken.get('aktive_modellzeit_s', 0)} s")
        k3.metric("Modellaufrufe", _metriken.get("aufrufe", 0))
        if _metriken.get("je_modell"):
            st.caption("Je Modell")
            st.dataframe(
                [{"Modell": m, "Aufrufe": e["aufrufe"], "Input": e["input_tokens"],
                  "Output": e["output_tokens"], "Gesamt": e["gesamt_tokens"],
                  "Modellzeit (s)": e["modellzeit_s"]}
                 for m, e in _metriken["je_modell"].items()],
                use_container_width=True, hide_index=True)
        if _metriken.get("phasen"):
            st.caption("Je Stufe")
            st.dataframe(
                [{"Stufe": p["name"], "Aufrufe": p["aufrufe"], "Input": p["input_tokens"],
                  "Output": p["output_tokens"], "Modellzeit (s)": p.get("modellzeit_s", 0)}
                 for p in _metriken["phasen"]],
                use_container_width=True, hide_index=True)
    with st.expander("Bericht ansehen"):
        st.markdown(bericht)

# --- Wissensbasis: Expertenfrage an den CISO -------------------------------
st.divider()
st.subheader("Wissensbasis · Frage an den CISO")
st.caption("Der Output-Ordner ist die Wissensbasis. Der CISO beantwortet Fragen auf "
           "Basis der gespeicherten Analyse und verweist auf Kennungen und TI-Belege.")
frage = st.text_input("Frage eines Experten zur Analyse",
                      placeholder="z. B. Welche Bedrohungen betreffen die Zahlungsdaten?")
if st.button("CISO fragen", disabled=not frage):
    with st.spinner("CISO durchsucht die gespeicherte Analyse ..."):
        try:
            st.markdown(frage_wissensbasis(frage))
        except FileNotFoundError:
            st.warning("Noch keine gespeicherte Analyse - bitte zuerst die Schritte 1–5 durchlaufen.")
