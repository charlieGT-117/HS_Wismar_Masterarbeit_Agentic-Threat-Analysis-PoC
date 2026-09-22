# Threat Analyse ShopFlow - Bericht

*Erzeugt am 22.09.2026 13:44 aus dem Analysemodell.*

## Überblick
- Modellelemente: 23
- Angriffsflächen: 11
- TI-Befunde: 3
- Bedrohungen: 7

## 1 Systemmodell

**Elemente**

- `E-01` Kunde (Externer Akteur) - Nutzer über Browser, registriert oder als Gast.
- `E-02` Shop-Administrator (Externer Akteur) - Verwaltet Sortiment, Preise und Konfiguration.
- `E-03` User-Bereich (Frontend-Komponente) - SPA-Bereich für Bestellungen, Kundenkonto und Zahlung. Karteneingabe erfolgt im eingebetteten iframe des Zahlungsdienstleisters; im System wird nur ein Zahlungsmittel-Token gehalten.
- `E-04` Admin-Bereich (Frontend-Komponente) - SPA-Bereich für Sortiment, Preise, Shop-Konfiguration, Benutzerverwaltung, Kundenkonten und Bestellstornierungen.
- `E-05` Authentication (Dienst) - Keycloak 18.0.0; OIDC/OAuth 2.0 (Authorization Code Flow), RS256-signierte JWT; stellt Zugriffstoken (8 h gültig, keine Rücknahme) und Aktualisierungstoken aus.
- `E-06` API Gateway (REST) (Dienst) - Routing, Token-Prüfung über JWKS von Keycloak, Rollenprüfung je Route, Ratenbegrenzung.
- `E-07` Monitoring für Frontend (Dienst) - Sentry; erfasst JavaScript-Fehler und Nutzersitzungen des Frontends. Datenfluss vom Frontend überschreitet die Frontend-/Zugriffsschicht-Grenze.
- `E-08` Middleware Service (Integrationsdienst) - Vermittelt zwischen API-Gateway und Fachdiensten, führt Formatumsetzungen durch und hält die Anbindungen nach außen.
- `E-09` Backend (Anwendungsdienst) - Shop-Service, Katalog und Warenkorb. Anonyme Warenkörbe über Redis.
- `E-10` Bestellung (Anwendungsdienst) - Annahme, Status und Storno von Bestellungen; stößt Zahlung per REST-API an und empfängt HMAC-signierte Webhooks vom Zahlungsdienstleister.
- `E-11` Logistik (Anwendungsdienst) - Sendungsverfolgung.
- `E-12` Suche (Anwendungsdienst) - Produktsuche.
- `E-13` Mailserver Gateway (Anwendungsdienst) - Postfix / Mailversand.
- `E-14` Datenbank (User) (Datenbank) - PostgreSQL 13.4; Zugriff per JDBC, TLS optional und derzeit deaktiviert. Speichert Kundendaten und Zahlungsmittel-Token.
- `E-15` Datenbank Bestellungen (Datenbank) - PostgreSQL 13.4; JDBC ohne TLS. Speichert Bestellungen.
- `E-16` Datenbank Versandaufträge (Datenbank) - MySQL 8.0.28 (Logistik); JDBC ohne TLS. Speichert Versandaufträge.
- `E-17` Mailserver (Dienst) - SMTP-Relay.
- `E-18` Monitoring (Betriebsdienst) - Grafana / Prometheus.
- `E-19` Log Server DB (Datenbank) - OpenSearch / Protokolle.
- `E-20` Google Analytics (Externes System) - Google Analytics 4; Web-Analyse des Nutzerverhaltens (Seitenaufrufe, Conversion-Trichter); Datenübermittlung direkt aus dem Browser an Google.
- `E-21` Faktur SaaS (Externes System) - Rechnungserstellung und Archivierung; erhält Kunden- und Bestelldaten vom Middleware Service.
- `E-22` Zahlungsdienstleister (Externes System) - Wickelt Kartenzahlung über eingebettetes iframe ab; Kartendaten berühren ShopFlow nicht. Meldet Zahlungsausgang per HMAC-signierten Webhooks.
- `E-23` Werbung und Affiliate Marketing (Externes System) - Node.js-Dienst; Erfassung von Klicks und Konversionen sowie Provisionsabrechnung gegenüber Partnern.

**Vertrauensgrenzen**

- `VG-1` Externer Zugriff / Zugangskanäle - Grenze zwischen externen Akteuren/Browser und dem Frontend bzw. direkt angebundenen externen Diensten (Google Analytics).
- `VG-2` Frontend zu Zugriffsschicht - Grenze zwischen SPA-Frontend und Authentication/API Gateway/Frontend-Monitoring.
- `VG-3` Zugriffsschicht zu Integrationsschicht - Grenze zwischen API Gateway und Middleware.
- `VG-4` Systemgrenze zu externen Partnern - Grenze zwischen Middleware/Backend und externen Systemen/Partnern.
- `VG-5` Betrieb und Überwachung - Grenze der Betriebs-/Monitoring-Zone.

## 2 Assets und Schutzziele
- `A-01` Kundendaten (Element E-14, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Personenbezogene Daten unterliegen Datenschutzanforderungen; DB-Verbindung ohne TLS erhöht Risiko.
- `A-02` Bestelldaten (Element E-15, Kritikalität: hoch) - Schutzziele: Integrität, Verfügbarkeit. Kern des Geschäftsbetriebs des Shops.
- `A-03` Versandaufträge (Element E-16, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Notwendig für korrekte Auslieferung.
- `A-04` Zahlungsmittel-Token (Element E-14, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Kartendaten selbst fließen nicht durch das System (iframe des Dienstleisters). Es wird nur ein Zahlungsmittel-Token in der User-DB gespeichert; dessen Missbrauch ermöglicht Zahlungen. DB-TLS deaktiviert erhöht Risiko.
- `A-05` Authentifizierungs-Token (JWT) (Element E-05, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. RS256-JWT von Keycloak steuern Zugriffskontrolle; Zugriffstoken 8 h gültig ohne Rücknahmemöglichkeit, wodurch kompromittierte Token lange nutzbar bleiben.
- `A-06` Shop-Konfiguration/Preise (Element E-04, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Manipulation von Preisen/Konfiguration schädigt Geschäft.
- `A-07` Protokolldaten (Element E-19, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Wichtig für Nachvollziehbarkeit und Vorfallanalyse.
- `A-08` Aktualisierungstoken (Refresh-Cookie) (Element E-03, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Aktualisierungstoken im Cookie (HttpOnly, Secure, ohne SameSite); fehlendes SameSite kann CSRF-Risiken begünstigen.
- `A-09` An Faktur SaaS übermittelte Kunden-/Bestelldaten (Element E-21, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Personenbezogene Kunden- und Bestelldaten verlassen die Systemgrenze zu einem externen Partner (DSGVO-relevant).

## 3 Angriffsflächen
- `AF-01` Kundenzugang Browser zu User-Bereich - Elemente: E-01, E-03 | erreichbare Assets: A-08, A-04, A-05, A-01, A-02. Der Kunde greift als externer Akteur ueber VG-1 auf das Frontend zu (DF-01), wodurch ueber die Zugriffskette Bestell-, Kundenkonto- und Zahlungsmittel-Token-Daten erreichbar werden.
- `AF-02` Admin-Zugang Browser zu Admin-Bereich - Elemente: E-02, E-04 | erreichbare Assets: A-06, A-01, A-02, A-05. Der Shop-Administrator greift als externer Akteur ueber VG-1 auf den Admin-Bereich zu (DF-02) und erreicht darueber privilegierte Funktionen wie Preise/Konfiguration und Benutzerverwaltung.
- `AF-03` Direkte Browser-Uebermittlung an Google Analytics - Elemente: E-01, E-20 | erreichbare Assets: -. Web-Analyse-Daten fliessen direkt aus dem Browser des Kunden ueber VG-1 an ein externes System (DF-13), mit unklarem Personenbezug.
- `AF-04` Frontend zu Authentication (OIDC) - Elemente: E-03, E-04, E-05 | erreichbare Assets: A-05, A-08. Der Authentifizierungsfluss vom Frontend zu Keycloak ueberschreitet VG-2 (DF-03, DF-03b) und macht die JWT-/Refresh-Token direkt angreifbar.
- `AF-05` Frontend zu API Gateway - Elemente: E-03, E-04, E-06 | erreichbare Assets: A-01, A-02, A-04, A-05, A-06. API-Anfragen inkl. JWT-Zugriffstoken und Geschaeftsdaten ueberschreiten VG-2 (DF-04, DF-04b, DF-05) und bilden den zentralen Eingang zu Fach- und Kundendaten.
- `AF-06` Frontend zu Frontend-Monitoring (Sentry) - Elemente: E-03, E-07 | erreichbare Assets: -. JavaScript-Fehler und Nutzersitzungen fliessen vom Frontend ueber VG-2 an das Monitoring (DF-06), das potenziell sensible Sitzungsdaten aufnimmt.
- `AF-07` API Gateway zu Middleware - Elemente: E-06, E-08 | erreichbare Assets: A-01, A-02, A-04. Routing-Anfragen mit Geschaeftsdaten und JWT-Kontext ueberschreiten VG-3 (DF-07) und vermitteln zu allen Fachdiensten.
- `AF-08` Middleware zu Faktur SaaS - Elemente: E-08, E-21 | erreichbare Assets: A-09, A-01, A-02. Personenbezogene Kunden- und Bestelldaten verlassen ueber VG-4 die Systemgrenze an einen externen SaaS-Partner (DF-14).
- `AF-09` Bestellung zu/von Zahlungsdienstleister - Elemente: E-10, E-22 | erreichbare Assets: A-04, A-02. Der Zahlungsanstoss und die eingehenden HMAC-signierten Webhooks ueberschreiten VG-4 (DF-15, DF-15b), wobei der Webhook einen von aussen erreichbaren Eingang darstellt.
- `AF-10` Middleware zu Werbung/Affiliate Marketing - Elemente: E-08, E-23 | erreichbare Assets: -. Klick-/Konversions- und Abrechnungsdaten verlassen ueber VG-4 die Systemgrenze an ein externes System (DF-16) mit undokumentiertem Personenbezug.
- `AF-11` Protokollsammlung aller Dienste zum Monitoring - Elemente: E-18 | erreichbare Assets: A-07. Protokolle aller Dienste ueberschreiten VG-5 zur Betriebs-/Monitoring-Zone (DF-21) und aggregieren potenziell sensible Betriebsdaten.

## 4 Threat-Intelligence-Befunde
- `TI-01` A01:2021 [OWASP] zu AF-01 - Broken Access Control: Fehler bei der Durchsetzung von Zugriffsrechten im Web-Frontend ermöglichen das unbefugte Einsehen oder Manipulieren fremder Bestellungen, Konten und Zahlungsmittel-Token über IDOR, URL-Tampering oder JWT-Manipulation.
    Beleg: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/ (abgerufen 2026-09-22T11:42:50+00:00, Ausnutzung: Häufigste Schwachstellenkategorie laut OWASP; in 94 % aller getesteten Anwendungen nachweisbar)
- `TI-02` CAPEC-63 [K2] zu AF-01 - Cross-Site Scripting (XSS): Ein Angreifer injiziert bösartige Skripte in die SPA-Oberfläche des User-Bereichs; der Browser des Opfers führt das Skript aus und ermöglicht so Session-Hijacking, Token-Diebstahl oder Manipulation der Zahlungsseite (inkl. iframe-Kontext).
    Beleg: https://capec.mitre.org/data/definitions/63.html (abgerufen 2026-09-22T11:42:50+00:00, Ausnutzung: unbekannt)
- `TI-03` T1185 [K3] zu AF-01 - Browser Session Hijacking: Reale Angreifer stehlen authentifizierte Browser-Sessions (Cookies, Session-Token) des Kunden, um sich als legitimer Nutzer auszugeben und auf Bestelldaten, Kundenkonto und Zahlungsmittel-Token zuzugreifen, ohne Anmeldedaten zu kennen.
    Beleg: https://attack.mitre.org/techniques/T1185/ (abgerufen 2026-09-22T11:42:50+00:00, Ausnutzung: Beobachtetes Angreifer-TTP; in ATT&CK Enterprise dokumentiert)

## 5 Bedrohungsverzeichnis mit Bewertung und Priorisierung

### `T-01` Broken Access Control / IDOR auf fremde Bestellungen und Konten  —  Priorität: **kritisch** (Score 20)
- STRIDE: Elevation of Privilege | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-01
- Fehlende oder unzureichende Durchsetzung von Zugriffsrechten im User-Bereich erlaubt Zugriff auf fremde Bestell-, Konto- und Zahlungsmittel-Token-Daten.
- Angriffsszenario: Ein registrierter Kunde manipuliert eine Bestell-ID oder Konto-ID in einem API-Request des User-Bereichs und ruft so Daten anderer Kunden ab oder storniert deren Bestellungen.
- Voraussetzungen: Das API-Gateway prueft zwar das JWT und die Rolle, aber die Objekt-Ebene (Ownership) wird nicht serverseitig verifiziert.
- Auswirkung: Unbefugtes Einsehen/Manipulieren von Kundendaten (A-01), Bestelldaten (A-02) und Zahlungsmittel-Token (A-04) mit Datenschutz- und Geschaeftsschaden.
- Bewertung: Eintrittswahrscheinlichkeit 4 (Broken Access Control ist laut OWASP A01:2021 die haeufigste Kategorie und mit oeffentlichem Wissen leicht ausnutzbar.); Auswirkung 5 (IDOR erlaubt Zugriff auf fremde Kundendaten, Bestellungen und Zahlungsmittel-Token, also mehrere hochkritische Assets.); Assets: A-01, A-02, A-04

### `T-03` Browser Session Hijacking (Session-/Token-Diebstahl)  —  Priorität: **kritisch** (Score 20)
- STRIDE: Spoofing | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-03, TI-02
- Angreifer uebernehmen authentifizierte Browser-Sessions des Kunden und agieren als legitimer Nutzer, ohne Zugangsdaten zu kennen.
- Angriffsszenario: Nach erfolgreichem XSS oder Malware im Browser entwendet der Angreifer das Access-Token/Refresh-Cookie und nutzt die uebernommene Session bis zu 8h fuer Bestellungen und Kontozugriffe.
- Voraussetzungen: Erlangter Zugriff auf Session-Token/Cookie und fehlende serverseitige Token-Ruecknahme.
- Auswirkung: Identitaetsuebernahme mit Zugriff auf A-01, A-02, A-04, A-05 und A-08 sowie Auslosen von Zahlungen ueber den Token.
- Bewertung: Eintrittswahrscheinlichkeit 4 (Session Hijacking (T1185) ist ein dokumentiertes, beobachtetes Angreifer-TTP.); Auswirkung 5 (Gestohlene 8h-gueltige JWT/Refresh-Token ermoeglichen faktische Kontouebernahme und Zugriff auf hochkritische Assets.); Assets: A-05, A-08

### `T-02` Cross-Site Scripting (XSS) im SPA-User-Bereich  —  Priorität: **hoch** (Score 12)
- STRIDE: Tampering | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-02
- Injektion boesartiger Skripte in die SPA-Oberflaeche fuehrt zu Skriptausfuehrung im Kundenbrowser und ermoeglicht Token-Diebstahl bzw. Manipulation der Zahlungsseite.
- Angriffsszenario: Ein Angreifer platziert ueber ein ungefiltertes Eingabefeld (z. B. Kommentar-/Profilfeld) ein Skript, das beim Aufruf durch andere Kunden im DOM ausgefuehrt wird und Session-Daten exfiltriert.
- Voraussetzungen: Unzureichende Ein-/Ausgabekodierung oder fehlende Content-Security-Policy im User-Bereich.
- Auswirkung: Diebstahl von Auth-Token (A-05) und Refresh-Cookie (A-08), Manipulation der Zahlungsseite und Zugriff auf Kunden-/Bestelldaten (A-01, A-02, A-04).
- Bewertung: Eintrittswahrscheinlichkeit 3 (XSS (CAPEC-63) ist mit oeffentlich verfuegbarem Wissen ausfuehrbar, Ausnutzungsstatus jedoch unbekannt.); Auswirkung 4 (Skriptinjektion im User-Bereich kann Auth- und Refresh-Token kompromittieren (hochkritische Assets).); Assets: A-05, A-08

### `T-04` CSRF gegen den User-Bereich durch fehlendes SameSite  —  Priorität: **hoch** (Score 12)
- STRIDE: Tampering | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Ein bereits angemeldeter Kunde wird auf einer fremden Seite dazu gebracht, ungewollt zustandsaendernde Aktionen im Shop auszuloesen.
- Angriffsszenario: Der Kunde besucht eine praeparierte Webseite, die im Hintergrund einen Request an den User-Bereich stellt (z. B. Bestellung/Kontoaenderung), wobei das Cookie automatisch mitgeschickt wird.
- Voraussetzungen: Aktive Session des Kunden, fehlender CSRF-Schutz (kein Token/Origin-Pruefung) und fehlendes SameSite-Attribut.
- Auswirkung: Ungewollte Aenderungen an Bestellungen (A-02) oder Kundendaten (A-01) im Namen des Opfers.
- Bewertung: Eintrittswahrscheinlichkeit 3 (Fehlendes SameSite-Attribut macht CSRF mit oeffentlichem Wissen ausfuehrbar, aber ohne aktiven TI-Beleg.); Auswirkung 4 (Ungewollte Aktionen im User-Bereich koennen Zahlungsmittel-Token und Refresh-Cookie missbrauchen (hochkritisch).); Assets: A-08, A-04

### `T-05` Preisgabe sensibler Daten ueber Client-Fehler und Monitoring  —  Priorität: **hoch** (Score 12)
- STRIDE: Information Disclosure | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-01
- Sensible Daten koennen ueber Fehlermeldungen, URL-Parameter oder Frontend-Monitoring unbeabsichtigt offengelegt werden.
- Angriffsszenario: Ein Angreifer nutzt uebermaessig detaillierte JavaScript-Fehler oder in URLs/Client-Speicher abgelegte Token-Fragmente, um Session- oder Kontoinformationen abzugreifen.
- Voraussetzungen: Unzureichende Datenminimierung/Redaktion bei Frontend-Fehlermeldungen und Token-Handhabung.
- Auswirkung: Offenlegung von Auth-Token (A-05), Refresh-Cookie (A-08) oder Kundendaten (A-01).
- Bewertung: Eintrittswahrscheinlichkeit 3 (Datenpreisgabe ueber Client-Fehler und Monitoring ist mit oeffentlichem Wissen moeglich (A01:2021).); Auswirkung 4 (Betrifft Vertraulichkeit von personenbezogenen Kundendaten und Zahlungsmittel-Token (hochkritisch).); Assets: A-01, A-04

### `T-07` Denial of Service durch missbraeuchliche Frontend-Requests  —  Priorität: **mittel** (Score 9)
- STRIDE: Denial of Service | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Massenhafte oder ressourcenintensive Anfragen ueber den Kundenzugang beeintraechtigen die Verfuegbarkeit der nachgelagerten Dienste.
- Angriffsszenario: Ein Angreifer generiert ueber den User-Bereich sehr viele Anfragen (z. B. anonyme Warenkoerbe, Suchanfragen), um Backend- und Redis-Ressourcen zu erschoepfen.
- Voraussetzungen: Unzureichend dimensionierte Ratenbegrenzung/Quotierung fuer anonyme oder automatisierte Requests.
- Auswirkung: Beeintraechtigung der Verfuegbarkeit des Shops und der Bestellverarbeitung (A-02).
- Bewertung: Eintrittswahrscheinlichkeit 3 (DoS durch missbraeuchliche Frontend-Requests ist mit oeffentlichem Wissen moeglich, ohne aktiven TI-Beleg.); Auswirkung 3 (Beeintraechtigt die Verfuegbarkeit des Shopbetriebs und der Bestellabwicklung.); Assets: A-02

### `T-06` Abstreitbarkeit kundenseitiger Aktionen  —  Priorität: **mittel** (Score 6)
- STRIDE: Repudiation | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Aktionen aus dem User-Bereich lassen sich mangels belastbarer Nachweise nachtraeglich abstreiten.
- Angriffsszenario: Ein Kunde bestreitet eine ueber seine Session ausgeloeste Bestellung oder Kontoaenderung, waehrend keine ausreichend detaillierten und manipulationssicheren Logs vorliegen.
- Voraussetzungen: Fehlende oder unvollstaendige, nicht integritaetsgesicherte Protokollierung der Kundenaktionen.
- Auswirkung: Streitige Bestellungen/Stornos (A-02) und erschwerte Vorfallanalyse (Bezug zu A-07).
- Bewertung: Eintrittswahrscheinlichkeit 2 (Abstreitbarkeit setzt Luecken in der Protokollierung voraus und erfordert erheblichen Aufwand ohne TI-Beleg.); Auswirkung 3 (Beeintraechtigt Nachvollziehbarkeit ueber die Protokolldaten mittlerer Kritikalitaet.); Assets: A-07

## 6 Annahmen
- Kunde und Admin greifen laut Diagramm per HTTPS auf das Frontend zu.
- Kartendaten werden im iframe des Zahlungsdienstleisters erfasst und berühren ShopFlow nicht; im System liegt nur ein Zahlungsmittel-Token.
- Alle Dienste senden Protokolle an das Monitoring/Log-System.
- Frontend authentifiziert über OIDC/OAuth 2.0 Authorization Code Flow gegen Keycloak; RS256-JWT (Zugriffstoken 8 h ohne Rücknahme, Aktualisierungstoken im HttpOnly/Secure-Cookie ohne SameSite).
- Google-Analytics-Tracking erfolgt direkt aus dem Browser (Datenfluss VG-1, nicht über die Middleware).
- Zahlungsanstoß erfolgt per REST-API durch den Bestellservice; Bestätigung per HMAC-signierten Webhooks.

## 7 Offene Rückfragen an den Nutzer
- Welche Compliance-/Schutzanforderungen (z. B. DSGVO, PCI-DSS) gelten für das System?
- Welche Assets sind aus Geschäftssicht am kritischsten und welche Ausfallzeiten sind tolerierbar?
- Werden mit den externen Partnern (Google Analytics, Faktur SaaS, Werbung/Affiliate) Datenverarbeitungsverträge (DPA) geführt, und erfolgt eine Anonymisierung/Pseudonymisierung vor Übermittlung?

## 8 Quellenverzeichnis (Threat Intelligence)
- CAPEC (Common Attack Pattern Enumeration): https://capec.mitre.org/data/definitions/63.html
- MITRE ATT&CK (Enterprise): https://attack.mitre.org/techniques/T1185/
- OWASP Top 10 (Web, 2021): https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/