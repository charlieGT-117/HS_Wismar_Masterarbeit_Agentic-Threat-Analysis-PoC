# PoC – Agentische Threat Analyse

Prototyp zur Masterarbeit: Ein **CISO-Agent** orchestriert mehrere spezialisierte
LLM-Agenten (Architekt, Software-Engineer, Threat-Intelligence, Prüfer) und führt eine
nachvollziehbare Threat Analyse durch – vom Systemmodell über Angriffsflächen und
Threat Intelligence bis zu bewerteten, priorisierten Bedrohungen. Bedienung über eine
Streamlit-Oberfläche.

---

## 1. Voraussetzungen

- **Python 3.11+** (Prüfen: `python --version`)
- **Anthropic API-Key** mit
  - aktivierter **Web Search** (für die Threat-Intelligence-Recherche) und
  - vorhandenem **Guthaben**.
- Internetzugang (für die Live-Recherche).

---

## 2. Installation (Windows / PowerShell)

Im entpackten Projektordner (`PoC_final`):

```powershell
# 1) Virtuelle Umgebung anlegen und aktivieren
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2) Abhängigkeiten installieren
pip install -r requirements.txt
```

> macOS/Linux: `source .venv/bin/activate` statt Zeile 2.

---

## 3. API-Key hinterlegen (.env)

Eine Datei **`.env`** im Projektordner anlegen mit genau dieser Zeile:

```
ANTHROPIC_API_KEY=sk-ant-...dein-key...
```

**Wichtig:** Der Key ist wie ein Passwort. Nicht weitergeben, nicht in Screenshots
zeigen, nicht in Git einchecken. Die `.env` bleibt lokal.

---

## 4. Eingaben ablegen (Ordner `Input/`)

Der Prototyp arbeitet mit **einer** Haupteingabe; ergänzende Angaben holt der CISO bei
den Fachagenten oder beim Nutzer ein.

- **Architekturdiagramm**: `Input/…​.png` oder `.jpg` (wird per Bild-Eingabe gelesen).
- **Systembeschreibung** (optional): `Input/Systembeschreibung.md` (Fließtext oder
  strukturiert) – nur der Software-Engineer-Agent kennt diese Datei.
- **draw.io-Quelle** (optional): `Input/…​.drawio` – nur nötig, wenn die Marker im Bild
  *pixelgenau* sitzen sollen (sonst werden die Positionen automatisch aus dem Bild erkannt).

Die Dateien lassen sich auch direkt in der Oberfläche (Seitenleiste) hochladen.

---

## 5. Starten

```powershell
python -m streamlit run app.py
```

Der Browser öffnet die Oberfläche automatisch (sonst die angezeigte lokale Adresse
öffnen). Beim ersten Start ggf. mit **Enter** durch die E-Mail-Abfrage von Streamlit.

---

## 6. Ablauf in der Oberfläche

| Schritt | Was passiert | Kontrolle (Human-in-the-Loop) |
|---|---|---|
| **1 · Systemmodell** | CISO analysiert die Eingabe, befragt Architekt/SW-Engineer/Nutzer zu Lücken, entwickelt das Systemmodell. Der **Prüf-Agent** begutachtet es unabhängig (Prüfbericht). | **Freigabepunkt 1:** offene Fragen beantworten · genehmigen · abbrechen |
| **2 · Angriffsflächen** | Ableitung der Angriffsflächen inkl. Bezug zu Elementen und Assets. | – |
| **3 · Threat Intelligence** | Der TI-Agent recherchiert **live** je gewählter Angriffsfläche (OWASP, MITRE ATT&CK, CWE, CAPEC, CVE) und belegt jeden Befund mit Quell-URL. | Auswahl der Angriffsfläche(n) |
| **4 · Bedrohungen** | Identifikation je Fläche (STRIDE) **und Analyse** (Szenario, Voraussetzungen, Auswirkung). | Auswahl der Fläche(n) |
| **4b · Bedrohungen freigeben** | Bedrohungen prüfen, bearbeiten, ergänzen oder verwerfen. | **Freigabepunkt 2:** erst nach Freigabe wird bewertet |
| **5 · Bewertung** | Bewertung (Eintrittswahrscheinlichkeit × Auswirkung) und Priorisierung; Bericht + Export. | Downloads (Bericht, Analysemodell) |
| **Wissensbasis** | Expertenfragen werden aus der gespeicherten Analyse beantwortet – mit Kennungen und TI-Belegen. | – |

In den Schritten 2, 4 und 5 werden die Findings zusätzlich als **Marker im
Architekturbild** angezeigt (in Schritt 5 nach Priorität eingefärbt: kritisch = dunkelrot,
hoch = rot, mittel = orange, niedrig = grün). Sitzt ein Marker falsch, hilft der Button
**„Positionen neu bestimmen"**.

---

## 7. Projektstruktur

```
PoC_final/
├─ app.py                     Streamlit-Oberfläche (Ablaufsteuerung, HITL)
├─ Agent_CISO.py              Orchestrator: Systemmodell + gesamte Kette
├─ Agent_Architekt.py         liest das Architekturdiagramm (Bild)
├─ Agent_Software_Engineer.py hält die Systembeschreibung, beantwortet Rückfragen
├─ Agent_TI.py                Threat-Intelligence-Agent (Live-Websuche + Beleg)
├─ Agent_Pruefer.py           unabhängige Prüfung des Systemmodells (nur lesend)
├─ CISO_Angriffsflaechen.py   Stufe 2: Angriffsflächen
├─ CISO_Bedrohungen.py        Stufe 3/4: Bedrohungen identifizieren + analysieren
├─ CISO_Bewertung.py          Stufe 5: Bewertung + Priorisierung
├─ CISO_Bericht.py            Bericht (bericht.md) + Export
├─ Wissensbasis.py            Expertenfragen aus der gespeicherten Analyse
├─ Bild_Marker.py             Marker der Findings im Architekturbild
├─ Drawio_Positionen.py       exakte Marker-Positionen aus draw.io (optional)
├─ llm.py                     zentraler Modell-Adapter (Text, Bild, Websuche)
├─ modelle.py                 lädt die Rolle→Modell-Zuordnung
├─ ausgabe.py                 Pfade für Input/Output/Config
├─ Test_Websuche.py           Selbsttest der Websuche
├─ requirements.txt           Abhängigkeiten
├─ Config/                    konfigurierbar OHNE Code (siehe unten)
├─ Input/                     Eingaben (Bild, Systembeschreibung, optional draw.io)
└─ Output/                    Ergebnisse (wird automatisch angelegt)
```

---

## 8. Konfiguration (Ordner `Config/`, ohne Code änderbar)

- **`modelle.json`** – welche Rolle welches Modell nutzt. Standard: CISO =
  `claude-opus-4-8` (Reasoning-Kern), Architekt/SW-Engineer = Haiku, TI/Prüfer = Sonnet.
- **`methodik.json`** – Methodikbausteine (STRIDE). Der CISO wählt je Fläche einen Baustein.
- **`quellen.json`** – Menü der TI-Quellen (Klasse, Abstraktionsebene). Der TI-Agent wählt
  selbst die passende Quelle; die Daten kommen live aus dem Internet.
- **`scoring.json`** – Bewertungsschema (Eintrittswahrscheinlichkeit × Auswirkung) und
  Prioritätsklassen (kritisch/hoch/mittel/niedrig).

---

## 9. Ergebnisse (Ordner `Output/`)

- **`analysemodell.json`** – das über die Schritte wachsende Analysemodell (Wissensbasis).
- **`ti_befunde.json`** – die recherchierten Threat-Intelligence-Befunde als eigenes Beleg-Artefakt.
- **`bericht.md`** – lesbarer Abschlussbericht (Systemmodell, Angriffsflächen, TI-Befunde,
  Bedrohungen inkl. Analyse und Bewertung, Annahmen, offene Punkte, Quellenverzeichnis).

---

