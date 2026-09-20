# Threat Analyse ShopFlow - Bericht

*Erzeugt am 20.09.2026 16:30 aus dem Analysemodell.*

## Überblick
- Modellelemente: 26
- Angriffsflächen: 16
- TI-Befunde: 0
- Bedrohungen: 3

## 1 Systemmodell

**Elemente**

- `E-01` Kunde (Browser) (Externer Akteur) - Endkunde greift per Browser auf den Shop zu.
- `E-02` Shop-Administrator (Externer Akteur) - Administrator zur Shop-Konfiguration und Authentifizierung.
- `E-03` User-Bereich (Frontend-Komponente) - Frontend für Bestellungen, Kundenkonto und Kreditkarte (eingebettetes Zahlungsformular des Zahlungsdienstleisters).
- `E-04` Admin-Bereich (Frontend-Komponente) - Frontend für Shop-Konfiguration und Authentifizierung.
- `E-05` Authentication (Dienst) - Zentraler Authentifizierungsdienst; stellt Token aus, die das API Gateway prüft.
- `E-06` API Gateway (REST) (Gateway) - REST-Schnittstelle zwischen Frontend und Middleware; prüft die ausgestellten Token.
- `E-07` Monitoring für Frontend (Überwachungskomponente) - Überwacht die Frontend-Schicht.
- `E-08` Middleware (Integrationskomponente) - Alle Aufrufe laufen synchron über die Middleware.
- `E-09` Backend (Anwendungskomponente) - Backend-Dienst der Anwendungsschicht (Shop-Service).
- `E-10` Bestellung (Anwendungskomponente) - Dienst zur Bestellverarbeitung.
- `E-11` Logistik (Anwendungskomponente) - Dienst für Logistikfunktionen.
- `E-12` Suche (Anwendungskomponente) - Eigenständiger Suchdienst der Anwendungsschicht mit eigener Datenbank; wird direkt von der Middleware angesprochen.
- `E-13` Mailserver Gateway (Gateway) - Schnittstelle zum Mailserver.
- `E-14` Mailserver (Infrastrukturkomponente) - Mailserver zum E-Mail-Versand.
- `E-15` Datenbank (User) (Datenbank) - Datenbank für Benutzerdaten (Konten, hinterlegte Zahlungsmittel).
- `E-16` Datenbank (Bestellung) (Datenbank) - Datenbank für Bestelldaten.
- `E-17` Datenbank (Logistik) (Datenbank) - Datenbank für Logistikdaten (Labels, Sendungsverfolgung).
- `E-18` Monitoring (Überwachungskomponente) - Zentrales Monitoring im Betrieb.
- `E-19` Log Server DB (Datenbank) - Speichert Protokolle aller Dienste.
- `E-20` 3rd Party Provider (Externes System) - Fremdbetriebener Drittanbieterdienst; liefert Produktstammdaten und Verfügbarkeiten.
- `E-21` Faktur SaaS (Externes System) - Fremdbetriebener Fakturierungsdienst; erzeugt Rechnungen. Anbindung technisch nicht spezifiziert (Luecke).
- `E-22` Zahlungsdienstleister (Externes System) - Kartenzahlung wird über eingebettetes Formular außerhalb des Systems verarbeitet.
- `E-23` Werbung / Affiliate (Externes System) - Werbe-/Affiliate-Partnerdienst; bindet Anzeigen ein und meldet Konversionen zurück (REST).
- `E-24` Ereignisbus (Integrationskomponente) - Nachrichten-/Ereignisbus, über den Bestell-, Logistik- und Shop-Service Ereignisse austauschen. Produkt/Version und Verschlüsselung nicht dokumentiert (Luecke).
- `E-25` Sitzungs-/Warenkorb-Zwischenspeicher (Datenspeicher) - Eigener Zwischenspeicher für Sitzungsdaten und Warenkörbe nicht angemeldeter Besucher.
- `E-26` Datenbank (Suche) (Datenbank) - Eigene Datenbank des Suchdienstes.

**Vertrauensgrenzen**

- `VG-1` Zugangskanäle ↔ Frontend - Übergang externer Akteure via HTTPS in die Frontend-/Zugriffsschicht.
- `VG-2` Frontend-/Zugriffsschicht ↔ Integrationsschicht - Übergang vom API Gateway zur Middleware.
- `VG-3` Integrationsschicht ↔ Anwendungs-/Datenschicht - Übergang von der Middleware zu den Anwendungsdiensten.
- `VG-4` System ↔ Externe Systeme und Partner - Übergang zu fremdbetriebenen Systemen via REST (3rd Party, Werbung/Affiliate; Faktur SaaS und Zahlungsdienstleister-Anbindung nicht spezifiziert).

## 2 Assets und Schutzziele
- `A-01` Kundendaten/Kundenkonto (Element E-15, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Datenbank (User) enthält Kundenkonten und hinterlegte Zahlungsmittel; personenbezogene Daten.
- `A-02` Kreditkartendaten (Element E-03, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Kartenzahlung über eingebettetes Formular des Zahlungsdienstleisters; besonders schützenswert. Ob im System nur Token oder Kartendaten gespeichert werden, ist offen (Luecke).
- `A-03` Bestelldaten (Element E-16, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Bestelldaten sind geschäftskritisch für den Shop-Betrieb.
- `A-04` Logistikdaten (Element E-17, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Logistikdaten (Labels, Sendungsverfolgung) steuern Versandprozesse.
- `A-05` Admin-Zugang/Shop-Konfiguration (Element E-04, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Admin-Bereich erlaubt Konfigurationsänderungen mit weitreichender Wirkung.
- `A-06` Authentifizierungsdaten (Element E-05, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Authentication-Dienst stellt Token aus und verwaltet Zugangsberechtigungen.
- `A-07` Protokoll-/Log-Daten (Element E-19, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Logs aller Dienste sind für Nachvollziehbarkeit relevant.
- `A-08` Sitzungsdaten und Warenkörbe (Element E-25, Kritikalität: mittel) - Schutzziele: Vertraulichkeit, Integrität. Sitzungsdaten und Warenkörbe nicht angemeldeter Besucher liegen in eigenem Zwischenspeicher; Session-Hijacking-relevant.
- `A-09` Such-/Suchindexdaten (Element E-26, Kritikalität: niedrig) - Schutzziele: Integrität, Verfügbarkeit. Suchdienst mit eigener Datenbank; primär geschäftliche Verfügbarkeit relevant. Kritikalität durch fehlende Geschäftsvorgaben vorläufig (Luecke).
- `A-10` Interne Ereignisdaten (Ereignisbus) (Element E-24, Kritikalität: mittel) - Schutzziele: Integrität, Vertraulichkeit. Bestell-, Logistik- und Shop-Ereignisse können personenbezogene bzw. geschäftskritische Inhalte transportieren; Verschlüsselung/Authentifizierung des Busses ist offen (Luecke).
- `A-11` Affiliate-/Konversionsdaten (Element E-23, Kritikalität: mittel) - Schutzziele: Vertraulichkeit, Integrität. Affiliate-Partner erhalten Konversionsdaten; möglicher Personenbezug (Tracking-IDs) ist nicht geklärt (Luecke).

## 3 Angriffsflächen
- `AF-01` Kunden-Zugang User-Bereich (HTTPS) - Elemente: E-01, E-03 | erreichbare Assets: A-02, A-08, A-01, A-03. DF-01 ueberschreitet VG-1 und bringt externen Kunden-Input in den User-Bereich, ueber den Karten-, Sitzungs- und Kundendaten erreichbar werden.
- `AF-02` Admin-Zugang Admin-Bereich (HTTPS) - Elemente: E-02, E-04 | erreichbare Assets: A-05, A-06. DF-02 ueberschreitet VG-1 und ermoeglicht externem Administrator Zugriff auf Admin-/Konfigurations- und nachgelagerte Authentifizierungsfunktionen.
- `AF-03` Externer Kunden-Akteur (Browser) - Elemente: E-01 | erreichbare Assets: A-02, A-08. E-01 ist ein externer, aus dem Internet agierender Akteur und damit unmittelbare Angriffsflaeche in Richtung Frontend.
- `AF-04` Externer Admin-Akteur - Elemente: E-02 | erreichbare Assets: A-05, A-06. E-02 ist ein externer Akteur mit weitreichenden Admin-Rechten und daher ein besonders kritischer Angriffsvektor.
- `AF-05` Gateway zur Middleware (VG-2) - Elemente: E-06, E-08 | erreichbare Assets: A-01, A-03, A-04, A-09, A-10. DF-06 ueberschreitet VG-2 vom Gateway zur Middleware, ueber die nachgelagert alle Fachdienste und deren Assets erreichbar sind.
- `AF-06` Middleware zu Backend/Shop-Service (VG-3) - Elemente: E-08, E-09 | erreichbare Assets: A-01, A-10. DF-07 ueberschreitet VG-3 und erlaubt Zugriff auf das Backend, das Benutzerdaten schreibt und Ereignisse einstellt.
- `AF-07` Middleware zu Bestelldienst (VG-3) - Elemente: E-08, E-10 | erreichbare Assets: A-03, A-10. DF-08 ueberschreitet VG-3 und macht den Bestelldienst samt Bestelldaten und Ereignisbus-Anbindung angreifbar.
- `AF-08` Middleware zu Logistikdienst (VG-3) - Elemente: E-08, E-11 | erreichbare Assets: A-04, A-10. DF-09 ueberschreitet VG-3 und erschliesst den Logistikdienst mit Logistikdaten und Ereignisbus-Anbindung.
- `AF-09` Middleware zu Suchdienst (VG-3) - Elemente: E-08, E-12 | erreichbare Assets: A-09. DF-10 ueberschreitet VG-3 und ermoeglicht Zugriff auf den Suchdienst und dessen Suchindexdaten.
- `AF-10` Middleware zu Mailserver-Gateway (VG-3) - Elemente: E-08, E-13 | erreichbare Assets: -. DF-11 ueberschreitet VG-3 und bildet einen Eingang zum Mailserver-Gateway (E-Mail-Ausloeser), das den Mailversand steuert.
- `AF-11` Anbindung 3rd Party Provider (VG-4, REST) - Elemente: E-08, E-20 | erreichbare Assets: -. DF-12 ueberschreitet VG-4 zu einem fremdbetriebenen REST-System mit unbekannter Auth/Verschluesselung und ist damit externe Angriffsflaeche.
- `AF-12` Anbindung Werbung/Affiliate (VG-4, REST) - Elemente: E-08, E-23 | erreichbare Assets: A-11. DF-24 ueberschreitet VG-4 zu einem externen Affiliate-System (REST) mit unklarem Datenumfang und moeglichem Personenbezug.
- `AF-13` Externes System 3rd Party Provider - Elemente: E-20 | erreichbare Assets: -. E-20 ist ein fremdbetriebenes, nicht kontrolliertes System und damit ein extern erreichbarer Angriffspunkt (z.B. manipulierte Stammdaten).
- `AF-14` Externes System Werbung/Affiliate - Elemente: E-23 | erreichbare Assets: A-11. E-23 ist ein fremdbetriebenes REST-System, das Anzeigen einbindet und Konversionen zurueckmeldet, und stellt damit eine externe Angriffsflaeche dar.
- `AF-15` Externes System Zahlungsdienstleister (eingebettetes Formular) - Elemente: E-22 | erreichbare Assets: A-02. E-22 verarbeitet Kartenzahlungen ueber ein in den User-Bereich eingebettetes Forma und ist als externes System mit direktem Bezug zu Kartendaten angreifbar.
- `AF-16` Externes System Faktur SaaS - Elemente: E-21 | erreichbare Assets: -. E-21 ist ein fremdbetriebener Fakturierungsdienst mit technisch unspezifizierter Anbindung (Luecke) und daher eine ungeklaerte externe Angriffsflaeche.

## 4 Threat-Intelligence-Befunde
- keine TI-Befunde erfasst

## 5 Bedrohungsverzeichnis mit Bewertung und Priorisierung

### `T-03` Abgreifen von Kreditkarten-/Kundendaten im Frontend  —  Priorität: **hoch** (Score 15)
- STRIDE: Information Disclosure | Element: E-03 | Angriffsfläche: AF-01 | Methodik: stride
- Vertrauliche Daten werden im User-Bereich unbefugt eingesehen oder abgefangen.
- Angriffsszenario: Ein Angreifer platziert per XSS oder kompromittiertem Third-Party-Skript einen Formjacking-Code, der Karten- und Kontoeingaben abgreift, bevor sie an den Zahlungsdienstleister gehen.
- Voraussetzungen: Fehlende Content-Security-Policy, unsichere Skripteinbindung oder unzureichende Isolierung des eingebetteten Zahlungsformulars.
- Auswirkung: Kompromittierung von Kreditkartendaten (A-02) und Kundendaten (A-01) mit Datenschutz- und Compliance-Verstoessen.
- Bewertung: Eintrittswahrscheinlichkeit 3 (Frontend-Angriffe auf Zahlungs-/Kundendaten sind mit oeffentlich verfuegbarem Wissen (z.B. Web-Skimming, XSS) ausfuehrbar, jedoch ohne konkreten TI-Beleg fuer aktive Ausnutzung.); Auswirkung 5 (Verletzt die Vertraulichkeit hochkritischer Kreditkarten- und Kundendaten (A-02, A-01).); Assets: A-02, A-01

### `T-04` Ueberlastung des User-Bereichs (DoS)  —  Priorität: **mittel** (Score 9)
- STRIDE: Denial of Service | Element: E-03 | Angriffsfläche: AF-01 | Methodik: stride
- Massenhafte Anfragen ueber den externen HTTPS-Zugang beeintraechtigen die Verfuegbarkeit.
- Angriffsszenario: Ein Angreifer sendet massenhaft ressourcenintensive Requests (z. B. Warenkorb-/Such-Operationen) gegen den User-Bereich und macht ihn fuer Kunden unerreichbar.
- Voraussetzungen: Fehlende Rate-Limits, kein DDoS-Schutz und keine Ressourcenbegrenzung am Frontend.
- Auswirkung: Ausfall des Bestellprozesses und Verlust der Verfuegbarkeit von Bestell- (A-03) und Sitzungsdaten (A-08).
- Bewertung: Eintrittswahrscheinlichkeit 3 (DoS gegen ein oeffentlich exponiertes Frontend ist mit gaengigen Mitteln ohne Spezialwissen moeglich.); Auswirkung 3 (Beeintraechtigt die Verfuegbarkeit des User-Bereichs und der Sitzungsdaten (A-08), Kernschutzziel der betroffenen Assets ist jedoch primaer Vertraulichkeit/Integritaet.); Assets: A-01, A-08

### `T-05` Abstreiten getaetigter Bestellungen  —  Priorität: **mittel** (Score 6)
- STRIDE: Repudiation | Element: E-03 | Angriffsfläche: AF-01 | Methodik: stride
- Ein Kunde bestreitet eine getaetigte Aktion mangels belastbarer Nachweise.
- Angriffsszenario: Ein Kunde loest eine Bestellung aus und bestreitet diese spaeter, weil keine nachvollziehbare, manipulationssichere Aufzeichnung der Aktion existiert.
- Voraussetzungen: Fehlende oder luecke­nhafte Protokollierung der Frontend-Aktionen und keine sichere Zuordnung zur authentifizierten Sitzung.
- Auswirkung: Streitfaelle und finanzielle Verluste durch nicht nachweisbare Bestelldaten (A-03).
- Bewertung: Eintrittswahrscheinlichkeit 2 (Erfolgreiches Abstreiten setzt Luecken in Protokollierung/Nachweisfuehrung voraus und erfordert i.d.R. Insiderwissen oder erheblichen Aufwand.); Auswirkung 3 (Betrifft Integritaet mittelkritischer Bestell- und Log-Daten (A-03, A-07) mit spuerbaren geschaeftlichen Folgen.); Assets: A-03, A-07

## 6 Annahmen
- Durchgezogene Rahmen sind Komponenten aus der Skizze, gestrichelte sind fremdbetriebene Systeme.
- Alle Aufrufe zwischen den Schichten laufen synchron über die Middleware.
- Kartendaten werden laut Diagramm außerhalb des Systems beim Zahlungsdienstleister über ein eingebettetes Formular verarbeitet.
- Der Ereignisbus verbindet Bestell-, Logistik- und Shop-Service innerhalb der Anwendungs-/Datenschicht (keine Grenzüberschreitung angenommen).
- Die vier logischen Schichten des Diagramms werden mangels expliziter Netz-Topologie als Vertrauensgrenzen VG-1 bis VG-4 modelliert; ihre reale Netz-Isolation ist unbestätigt (siehe Luecken).

## 7 Offene Rückfragen an den Nutzer
- Welche Schutzanforderungen und Kritikalität gelten aus Geschäftssicht für die einzelnen Datenbestände (Kundendaten, Bestell-, Logistik-, Such-, Sitzungs-/Warenkorb-, Log-Daten)?

## 8 Quellenverzeichnis (Threat Intelligence)
- keine