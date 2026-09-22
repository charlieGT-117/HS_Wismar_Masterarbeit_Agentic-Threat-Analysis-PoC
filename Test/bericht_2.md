# Threat Analyse ShopFlow - Bericht

*Erzeugt am 22.09.2026 13:35 aus dem Analysemodell.*

## Überblick
- Modellelemente: 27
- Angriffsflächen: 22
- TI-Befunde: 3
- Bedrohungen: 8

## 1 Systemmodell

**Elemente**

- `E-01` Kunde (externer Akteur) - Nutzer per Browser, registriert oder als Gast.
- `E-02` Shop-Administrator (externer Akteur) - Verwaltet Sortiment, Preise und Konfiguration. RBAC ueber Rollen shop-admin und shop-support.
- `E-03` User-Bereich (Frontend-Komponente) - SPA-Bereich fuer Bestellungen und Kundenkonto. Karteneingabe erfolgt im eingebetteten iframe des Zahlungsdienstleisters; Kartendaten beruehren ShopFlow nicht.
- `E-04` Admin-Bereich (Frontend-Komponente) - SPA-Bereich fuer Sortiment, Preise, Shop-Konfiguration.
- `E-05` Authentication (Dienst) - Keycloak 18.0.0; OIDC/OAuth 2.0 (Authorization Code Flow), RS256-signierte JWT; Zugriffstoken 8h gueltig ohne Revocation; Refresh-Token; Passwortzuruecksetzung; TOTP optional.
- `E-06` API Gateway (REST) (Gateway) - Routing und Token-Pruefung; setzt RBAC (shop-admin/shop-support) durch.
- `E-07` Monitoring fuer Frontend (Dienst) - Ueberwacht Verfuegbarkeit und Fehler des Frontends.
- `E-08` Middleware Service (Integrationsdienst) - Vermittelt zwischen API-Gateway und Fachdiensten, fuehrt Formatumsetzungen durch und haelt die Anbindungen nach aussen (Google Analytics, Faktur SaaS, Zahlungsdienstleister, Werbung/Affiliate).
- `E-09` Backend (Anwendungsdienst) - Shop-Service, Katalog, Warenkorb; nutzt Redis.
- `E-10` Bestellung (Anwendungsdienst) - Annahme, Status, Storno von Bestellungen; nutzt Kafka.
- `E-11` Logistik (Anwendungsdienst) - Sendungsverfolgung; Anbindung an Versanddienstleister-REST-API.
- `E-12` Suche (Anwendungsdienst) - Produktsuche ueber Elasticsearch-Adapter.
- `E-13` Mailserver Gateway (Dienst) - Postfix / Mailversand; dedizierte Gateway-Komponente fuer den Mailserver.
- `E-14` Datenbank (User) (Datenspeicher) - PostgreSQL 13.4; Kundendaten und Zahlungsmittel-Token des PSP; Zugriff per JDBC, TLS optional und derzeit deaktiviert.
- `E-15` Datenbank Bestellungen (Datenspeicher) - PostgreSQL 13.4; Bestelldaten; JDBC ohne TLS.
- `E-16` Datenbank Versandauftraege (Datenspeicher) - MySQL 8.0.28; Versandauftraege; JDBC ohne TLS.
- `E-17` Mailserver (Dienst) - SMTP-Relay.
- `E-18` Monitoring (Betriebsdienst) - Grafana, Prometheus.
- `E-19` Log Server DB (Datenspeicher) - OpenSearch 1.2; Protokolle aller Dienste; HTTP mit Basisauthentifizierung.
- `E-20` Google Analytics (externes System) - Google Analytics 4, eingebunden per gtag.js im Frontend; Web-Analyse (Seitenaufrufe, Conversion-Trichter); Datenuebermittlung direkt aus dem Browser.
- `E-21` Faktur SaaS (externes System) - Rechnungserstellung; erhaelt Kunden- und Bestelldaten vom Middleware Service.
- `E-22` Zahlungsdienstleister (externes System) - PCI-DSS-zertifiziert; Karteneingabe im eingebetteten iframe; Kartendaten liegen nicht im System; ShopFlow speichert nur einen Token.
- `E-23` Werbung und Affiliate Marketing (externes System) - Partnerskript im Browser des Kunden; Erfassung von Klicks und Konversionen, Provisionsabrechnung.
- `E-24` Redis (Datenspeicher) - Cache/Datenspeicher fuer Shop-Service.
- `E-25` Kafka (Messaging) - Event-/Nachrichtenbus fuer Bestellungen.
- `E-26` Versanddienstleister-API (externes System) - Externe REST-API fuer Versand/Sendungsverfolgung.
- `E-27` Elasticsearch (Datenspeicher) - Suchindex, angebunden ueber Suche-Adapter.

**Vertrauensgrenzen**

- `VG-1` Externe Zugangsgrenze - Grenze zwischen externen Akteuren und Frontend-Schicht (HTTPS).
- `VG-2` Frontend/Zugriffsschicht - Grenze zwischen Frontend und Zugriffsdiensten (Auth, Gateway).
- `VG-3` Integrationsschicht - Grenze zwischen Zugriffsschicht und Middleware.
- `VG-4` Anwendungs-/Datenschicht - Grenze zwischen Middleware und Anwendungsdiensten/Datenbanken.
- `VG-5` Externe Systeme/Partner - Grenze zu externen Systemen und Partnern (PSP, Faktur SaaS, Analytics, Affiliate, Versanddienstleister).
- `VG-6` Betrieb und Ueberwachung - Grenze der Monitoring- und Log-Zone.

## 2 Assets und Schutzziele
- `A-01` Kundendaten (Element E-14, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integritaet, Verfuegbarkeit. Personenbezogene Daten mit hohem Schutzbedarf; DB per JDBC ohne aktives TLS gespeichert/uebertragen.
- `A-02` Bestelldaten (Element E-15, Kritikalität: hoch) - Schutzziele: Integritaet, Verfuegbarkeit, Vertraulichkeit. Geschaeftskritische Transaktionsdaten; JDBC ohne TLS.
- `A-03` Versandauftraege (Element E-16, Kritikalität: mittel) - Schutzziele: Integritaet, Verfuegbarkeit. Notwendig fuer Logistikprozesse; JDBC ohne TLS.
- `A-04` Zahlungsmittel-Token (PSP) (Element E-14, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integritaet. Kartendaten liegen nicht im System, jedoch wird ein PSP-Token in der User-DB gespeichert; Missbrauch bei Folgezahlungen moeglich. Schutzmechanismen des Tokens unklar (Luecke).
- `A-05` Authentifizierungs-Token (JWT/Refresh) (Element E-05, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integritaet. RS256-JWT, 8h gueltig ohne Revocation; kompromittierte Token bleiben lange nutzbar. Schutz der Refresh-Token unklar (Luecke).
- `A-06` Protokolldaten (Element E-19, Kritikalität: mittel) - Schutzziele: Integritaet, Vertraulichkeit. Protokolle aller Dienste, relevant fuer Forensik; Transport per HTTP mit Basisauthentifizierung ohne TLS.
- `A-07` Shop-Konfiguration/Sortiment/Preise (Element E-09, Kritikalität: mittel) - Schutzziele: Integritaet, Verfuegbarkeit. Manipulation beeintraechtigt Geschaeftsbetrieb.
- `A-08` Warenkorb-/Cachedaten (Element E-24, Kritikalität: mittel) - Schutzziele: Integritaet, Verfuegbarkeit. Redis haelt Warenkorb-/Cachedaten; Authentifizierung/Verschluesselung unklar (Luecke).
- `A-09` Bestell-Events (Kafka) (Element E-25, Kritikalität: mittel) - Schutzziele: Integritaet, Verfuegbarkeit, Vertraulichkeit. Bestellprozess-Events; interne Authentifizierung unklar (Luecke).

## 3 Angriffsflächen
- `AF-01` Kunden-Zugang zum User-Bereich (VG-1) - Elemente: E-01, E-03 | erreichbare Assets: A-01, A-02, A-04, A-05, A-07, A-08. DF-01 ueberschreitet die externe Zugangsgrenze VG-1 und ist der primaere von aussen erreichbare Einstieg fuer Kunden ins Frontend.
- `AF-02` Admin-Zugang zum Admin-Bereich (VG-1) - Elemente: E-02, E-04 | erreichbare Assets: A-07, A-01, A-02, A-05. DF-02 ueberschreitet VG-1 und erlaubt externen Administratoren privilegierten Zugriff auf Sortiment, Preise und Konfiguration.
- `AF-03` Direkte Browser-Anbindung an Zahlungsdienstleister (VG-5) - Elemente: E-01, E-22 | erreichbare Assets: A-04. DF-02b ueberschreitet die Grenze zu externen Systemen (VG-5) via PSP-iframe direkt aus dem Browser.
- `AF-04` Direkte Browser-Anbindung an Google Analytics (VG-5) - Elemente: E-01, E-20 | erreichbare Assets: A-01. DF-02c ueberschreitet VG-5 mit direkter Datenuebermittlung aus dem Browser an Google (uebermittelte Felder unbekannt/Luecke).
- `AF-05` Direkte Browser-Anbindung an Werbung/Affiliate (VG-5) - Elemente: E-01, E-23 | erreichbare Assets: A-01. DF-02d ueberschreitet VG-5 ueber ein Partnerskript im Browser (uebermittelte Felder unbekannt/Luecke).
- `AF-06` Auth-Anfragen Admin-Bereich zu Keycloak (VG-2) - Elemente: E-04, E-05 | erreichbare Assets: A-05. DF-03 ueberschreitet VG-2 und exponiert den Authentifizierungsflow des Admin-Bereichs.
- `AF-07` Auth-Anfragen User-Bereich zu Keycloak (VG-2) - Elemente: E-03, E-05 | erreichbare Assets: A-05. DF-03b ueberschreitet VG-2 und exponiert den Authentifizierungsflow des User-Bereichs.
- `AF-08` REST-Aufrufe Admin-Bereich zum API-Gateway (VG-2) - Elemente: E-04, E-06 | erreichbare Assets: A-01, A-02, A-07, A-05. DF-04 ueberschreitet VG-2 und stellt den API-Einstieg mit RBAC-Durchsetzung fuer administrative Datenzugriffe dar.
- `AF-09` REST-Aufrufe User-Bereich zum API-Gateway (VG-2) - Elemente: E-03, E-06 | erreichbare Assets: A-01, A-02, A-04, A-05. DF-04b ueberschreitet VG-2 und transportiert Kundenstammdaten, Bestelldaten und Zahlungsmittel-Token ueber das Gateway.
- `AF-10` REST-Antworten Gateway zum Admin-Bereich (VG-2) - Elemente: E-06, E-04 | erreichbare Assets: A-01, A-02, A-07. DF-05 ueberschreitet VG-2 und gibt Antwortinhalte je Endpunkt zurueck (Payloads Luecke).
- `AF-11` Gateway zu Middleware Service (VG-3) - Elemente: E-06, E-08 | erreichbare Assets: A-01, A-02, A-04, A-07. DF-07 ueberschreitet die Integrationsschicht VG-3 und buendelt saemtliche Fach- und Zahlungsmittel-Token-Fluesse.
- `AF-12` Middleware zu Backend (VG-4) - Elemente: E-08, E-09 | erreichbare Assets: A-07, A-08. DF-08 ueberschreitet VG-4 zu Katalog-/Warenkorbdaten bei unbekannter Transportsicherung (Luecke).
- `AF-13` Middleware zu Bestellung (VG-4) - Elemente: E-08, E-10 | erreichbare Assets: A-02, A-09. DF-09 ueberschreitet VG-4 zu Bestelldaten bei unbekannter Transportsicherung (Luecke).
- `AF-14` Middleware zu Logistik (VG-4) - Elemente: E-08, E-11 | erreichbare Assets: A-03. DF-10 ueberschreitet VG-4 zu Versand-/Logistikdaten bei unbekannter Transportsicherung (Luecke).
- `AF-15` Middleware zu Suche (VG-4) - Elemente: E-08, E-12 | erreichbare Assets: A-07. DF-11 ueberschreitet VG-4 zu Suchanfragen/Produktdaten bei unbekannter Transportsicherung (Luecke).
- `AF-16` Middleware zu Mailserver Gateway (VG-4) - Elemente: E-08, E-13 | erreichbare Assets: A-01. DF-12 ueberschreitet VG-4 mit Mailinhalten/Benachrichtigungen bei unbekannter Transportsicherung (Luecke).
- `AF-17` Middleware zu Zahlungsdienstleister (VG-5) - Elemente: E-08, E-22 | erreichbare Assets: A-04. DF-13 ueberschreitet VG-5 und uebermittelt Zahlungsmittel-Token bei Folgezahlungen (Nutzung/Weiterleitung Luecke).
- `AF-18` Middleware zu Faktur SaaS (VG-5) - Elemente: E-08, E-21 | erreichbare Assets: A-01, A-02. DF-13b ueberschreitet VG-5 und uebertraegt Kunden- und Bestelldaten an ein externes SaaS (konkrete Felder Luecke).
- `AF-19` Logistik zu Versanddienstleister-API (VG-5) - Elemente: E-11, E-26 | erreichbare Assets: A-03. DF-16b ueberschreitet VG-5 zur externen REST-API bei unbekannter Authentifizierung (Luecke).
- `AF-20` Anwendungsschicht zu Log Server (VG-6) - Elemente: E-19 | erreichbare Assets: A-06. DF-19 ueberschreitet VG-6 und uebertraegt Protokolle aller Dienste per HTTP mit Basisauthentifizierung ohne TLS.
- `AF-21` Externer Akteur Kunde - Elemente: E-01 | erreichbare Assets: A-01, A-02, A-04, A-05, A-08. Der Kunde agiert von aussen ueber Browser und ist damit selbst eine externe Angriffsflaeche (auch fuer Konto-/Session-Missbrauch).
- `AF-22` Externer Akteur Shop-Administrator - Elemente: E-02 | erreichbare Assets: A-07, A-01, A-02, A-05. Der Administrator greift von aussen zu und stellt aufgrund hoher Privilegien eine besonders kritische externe Angriffsflaeche dar (MFA-Pflicht Luecke).

## 4 Threat-Intelligence-Befunde
- `TI-01` A07:2021 [OWASP] zu AF-01 - Identification and Authentication Failures: Der externe Kunden-Zugang (Login, Session-Management, Passwort-Reset) ist der klassische Angriffspunkt für Credential Stuffing, Brute Force und Session-Fixation. Bei einer SPA ohne robuste serverseitige Session-Kontrolle können Angreifer Kundenkonten übernehmen und auf Bestelldaten, Kontodaten sowie gespeicherte Zahlungsmethoden (A-01, A-02, A-04, A-05) zugreifen.
    Beleg: https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/ (abgerufen 2026-09-22T11:32:21+00:00, Ausnutzung: unbekannt)
- `TI-02` CAPEC-62 [K2] zu AF-01 - Cross-Site Request Forgery (Session Riding): Angreifer platzieren präparierte Links oder iframes, die im Browser eines authentifizierten Kunden unbeabsichtigt Aktionen (z. B. Bestellabbruch, Adressänderung) im Namen des Opfers auslösen. SPAs sind besonders exponiert, weil CSRF-Token im JavaScript-Speicher gehalten werden und bei XSS-Schwächen gestohlen werden können.
    Beleg: https://cvefeed.io/capec/detail/capec-62-cross-site-request-forgery (abgerufen 2026-09-22T11:32:21+00:00, Ausnutzung: unbekannt)
- `TI-03` T1190 [K3] zu AF-01 - Exploit Public-Facing Application: Reale Angreifer (u. a. APT41, BlackByte-Ransomware-Gruppe) nutzen Schwachstellen in internet-exponierten Webanwendungen als initialen Zugangspunkt. Laut Verizon DBIR 2025 ist T1190 der zweithäufigste Initial-Access-Vektor nach Phishing; die Zeit zwischen Vulnerability-Disclosure und Massenausnutzung beträgt oft nur Stunden.
    Beleg: https://attack.mitre.org/techniques/T1190/ (abgerufen 2026-09-22T11:32:21+00:00, Ausnutzung: aktiv ausgenutzt durch mehrere APT- und Ransomware-Gruppen (z. B. APT41, BlackByte); laut DBIR 2025 zweithäufigster Initial-Access-Vektor)

## 5 Bedrohungsverzeichnis mit Bewertung und Priorisierung

### `T-04` Ausnutzung des extern exponierten Web-Frontends  —  Priorität: **kritisch** (Score 25)
- STRIDE: Elevation of Privilege | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-03
- Angreifer nutzen Schwachstellen im internet-exponierten User-Bereich als initialen Zugang.
- Angriffsszenario: Ein Angreifer scannt das Frontend, findet eine bekannte oder neu offengelegte Schwachstelle und erlangt darueber erweiterten Zugriff auf nachgelagerte Assets.
- Voraussetzungen: Ungepatchte/verwundbare Komponente im Frontend-Pfad und kurzes Patchfenster gegenueber schneller Massenausnutzung.
- Auswirkung: Initialer Zugang mit moeglicher Ausweitung auf Kundendaten, Bestelldaten und Konfiguration (A-01, A-02, A-07).
- Bewertung: Eintrittswahrscheinlichkeit 5 (T1190 wird laut TI aktiv von mehreren APT-/Ransomware-Gruppen ausgenutzt und ist zweithaeufigster Initial-Access-Vektor.); Auswirkung 5 (Kompromittierung des exponierten Frontends kann zur Systemuebernahme und Zugriff auf mehrere hochkritische Assets fuehren.); Assets: A-01, A-05, A-04

### `T-01` Kontouebernahme durch Credential Stuffing / Brute Force  —  Priorität: **hoch** (Score 16)
- STRIDE: Spoofing | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-01
- Angreifer uebernehmen Kundenkonten ueber schwache Login-/Session-Kontrolle im SPA-User-Bereich.
- Angriffsszenario: Ein Angreifer spielt geleakte Zugangsdaten automatisiert gegen die Login-Funktion des User-Bereichs, findet gueltige Kombinationen und meldet sich als Kunde an.
- Voraussetzungen: Fehlende Rate-Limits/Bot-Schutz/MFA-Pflicht (TOTP nur optional) und wiederverwendete Kundenpasswoerter.
- Auswirkung: Zugriff auf Kundendaten (A-01), Bestelldaten (A-02) und gespeicherte Zahlungsmittel-Token (A-04) sowie Missbrauch bei Folgezahlungen.
- Bewertung: Eintrittswahrscheinlichkeit 4 (Credential Stuffing ist mit oeffentlich verfuegbaren Tools und Leak-Listen ein bekannter, breit genutzter Angriffsweg gegen exponierte Login-Endpunkte.); Auswirkung 4 (Kontouebernahme erlaubt Zugriff auf hochkritische Kundendaten und den gespeicherten PSP-Token.); Assets: A-01, A-04

### `T-02` Langlebige Session-/Token-Nutzung nach Kompromittierung  —  Priorität: **hoch** (Score 12)
- STRIDE: Spoofing | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-01
- Gestohlene JWT/Refresh-Token bleiben wegen fehlender Revocation und 8h-Gueltigkeit lange nutzbar.
- Angriffsszenario: Ein Angreifer entwendet ein Access-/Refresh-Token aus dem SPA-Speicher und nutzt es fuer viele Stunden im Namen des Kunden, ohne dass ein Widerruf greift.
- Voraussetzungen: Tokenzugriff (z. B. via XSS oder unsicherer Speicherung) und fehlende serverseitige Revocation.
- Auswirkung: Andauernder unbefugter Zugriff auf A-01, A-02, A-04, A-05 waehrend der gesamten Token-Gueltigkeit.
- Bewertung: Eintrittswahrscheinlichkeit 3 (8h-JWT ohne Revocation macht die Weiternutzung kompromittierter Token nach Diebstahl leicht ausnutzbar.); Auswirkung 4 (Langlebige Auth-Token (hoch) ermoeglichen dauerhaften Zugriff auf hochkritische Kundendaten.); Assets: A-05, A-01

### `T-05` Cross-Site Scripting im User-Bereich  —  Priorität: **hoch** (Score 12)
- STRIDE: Information Disclosure | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Einschleusen von Skripten in die SPA zum Diebstahl von Session-/CSRF-Token oder Manipulation der Darstellung.
- Angriffsszenario: Ein Angreifer platziert einen manipulierten Eingabewert (z. B. in Profil-/Suchfeldern), der im Browser anderer Kunden als Skript ausgefuehrt wird und Token exfiltriert.
- Voraussetzungen: Unzureichende Ein-/Ausgabevalidierung und fehlende restriktive CSP im User-Bereich.
- Auswirkung: Diebstahl von Auth-Token (A-05) und Kontodaten (A-01), Folgeuebernahme von Konten.
- Bewertung: Eintrittswahrscheinlichkeit 3 (XSS im Nutzerbereich ist ein gaengiger, mit oeffentlichem Wissen ausfuehrbarer Angriff bei unzureichender Ausgabekodierung.); Auswirkung 4 (Skriptausfuehrung erlaubt Diebstahl von Auth-Token und Zugriff auf hochkritische Kundendaten.); Assets: A-05, A-01

### `T-06` Missbrauch der Passwortzuruecksetzung  —  Priorität: **hoch** (Score 12)
- STRIDE: Spoofing | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-01
- Angreifer setzen ueber die Reset-Funktion Passwoerter fremder Konten zurueck.
- Angriffsszenario: Ein Angreifer nutzt vorhersehbare/nicht abgelaufene Reset-Token oder Kontoenumeration, um einen Reset fuer ein fremdes Konto zu erzwingen.
- Voraussetzungen: Schwache Reset-Token, fehlende Ratenbegrenzung oder Kontoenumeration ueber unterschiedliche Antworten.
- Auswirkung: Vollstaendige Uebernahme des Kundenkontos mit Zugriff auf A-01, A-02, A-04.
- Bewertung: Eintrittswahrscheinlichkeit 3 (Schwaechen in Passwort-Reset-Flows (Token-Vorhersage, Enumeration) sind oeffentlich bekannt und regelmaessig ausnutzbar.); Auswirkung 4 (Erfolgreicher Missbrauch fuehrt zur Kontouebernahme mit Zugriff auf hochkritische Kundendaten und PSP-Token.); Assets: A-01, A-04

### `T-08` Denial of Service gegen den Kunden-Zugang  —  Priorität: **hoch** (Score 12)
- STRIDE: Denial of Service | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Ueberlastung des Login-/Frontend-Einstiegs macht den User-Bereich fuer Kunden unerreichbar.
- Angriffsszenario: Ein Angreifer flutet Login-/API-Endpunkte des User-Bereichs mit Anfragen und ueberlastet vorgelagerte Dienste.
- Voraussetzungen: Fehlende Rate-Limits, WAF oder Skalierungs-/Schutzmassnahmen am Zugang.
- Auswirkung: Ausfall des Kundenzugangs und damit Beeintraechtigung der Verfuegbarkeit von A-02 und A-07 aus Kundensicht.
- Bewertung: Eintrittswahrscheinlichkeit 4 (DoS gegen extern exponierte Kundenzugaenge ist mit oeffentlich verfuegbaren Mitteln leicht durchfuehrbar.); Auswirkung 3 (Beeintraechtigt die Verfuegbarkeit des Kundenzugangs, ohne unmittelbare Kompromittierung mehrerer Assets.); Assets: A-01

### `T-03` Cross-Site Request Forgery (Session Riding)  —  Priorität: **mittel** (Score 9)
- STRIDE: Tampering | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-02
- Praeparierte Links/iframes loesen im Browser eines eingeloggten Kunden ungewollte Aktionen aus.
- Angriffsszenario: Das Opfer besucht eine praeparierte Seite, die im Hintergrund eine Adressaenderung oder einen Bestellabbruch im User-Bereich ausloest.
- Voraussetzungen: Aktive Kunden-Session und fehlende/umgehbare CSRF-Schutzmechanismen (z. B. SameSite, Token-Bindung).
- Auswirkung: Manipulation von Konto-/Bestelldaten (A-01, A-02) im Namen des Kunden ohne dessen Wissen.
- Bewertung: Eintrittswahrscheinlichkeit 3 (CSRF (CAPEC-62) ist mit oeffentlichem Wissen umsetzbar, sofern kein wirksamer CSRF-Schutz besteht.); Auswirkung 3 (Ungewollte Aktionen im Namen des Nutzers koennen Bestell- und Kundendaten manipulieren.); Assets: A-02, A-01

### `T-07` Fehlende Nachweisbarkeit von Kundenaktionen  —  Priorität: **mittel** (Score 9)
- STRIDE: Repudiation | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Kundenaktionen (z. B. Bestellung, Aenderung) koennen mangels belastbarer Protokollierung abgestritten werden.
- Angriffsszenario: Ein Kunde oder ein Angreifer mit uebernommenem Konto bestreitet eine durchgefuehrte Aktion, ohne dass ausreichende Belege vorliegen.
- Voraussetzungen: Unvollstaendige clientseitige/serverseitige Protokollierung von Kundenaktionen.
- Auswirkung: Streitfaelle und Betrug bei Bestellungen (A-02) sind nicht aufloesbar; erschwerte Forensik.
- Bewertung: Eintrittswahrscheinlichkeit 3 (Fehlende oder manipulierbare Protokollierung (Transport per HTTP ohne TLS) macht Abstreitbarkeit realistisch.); Auswirkung 3 (Mangelnde Nachweisbarkeit beeintraechtigt die forensisch relevanten Protokolldaten mittlerer Kritikalitaet.); Assets: A-06

## 6 Annahmen
- Kunden- und Admin-Zugriff erfolgt ueber HTTPS (im Diagramm markiert).
- Das API Gateway prueft JWT-Token und setzt RBAC (shop-admin/shop-support) fuer den Zugriff auf Backend-Dienste durch.
- Kartendaten werden ausschliesslich im PSP-iframe erfasst und beruehren ShopFlow nicht; nur ein PSP-Token wird in der User-DB gespeichert.
- Die Anwendungsdienste protokollieren zum zentralen Log Server (OpenSearch) via HTTP mit Basisauthentifizierung.
- Interne DB-Verbindungen (User, Bestellung, Logistik) laufen per JDBC ohne aktives TLS.
- Externe Systeme (Google Analytics, Faktur SaaS, Zahlungsdienstleister, Werbung/Affiliate) werden ueber die Middleware Service bzw. direkt aus dem Browser angebunden; der Mailserver ueber ein dediziertes Gateway.
- Netzwerk-/Vertrauensgrenzen sind logisch aus der Schichtung abgeleitet, aber im Diagramm nicht explizit gekennzeichnet (keine bestaetigte Netzsegmentierung/DMZ).

## 7 Offene Rückfragen an den Nutzer
- Welche Schutzbedarfe und Kritikalitaeten gelten aus Geschaeftssicht fuer die einzelnen Datenkategorien?
- Welche gesetzlichen/vertraglichen Anforderungen (z.B. PCI-DSS, DSGVO) sind fuer das System relevant?
- Liegen Datenverarbeitungsvereinbarungen (AV) mit Google und dem Affiliate-Partner vor und wie ist die Rechtsgrundlage (Einwilligung/berechtigtes Interesse) dokumentiert? Wie wird Nutzerconsent vor der Datenuebermittlung eingeholt?

## 8 Quellenverzeichnis (Threat Intelligence)
- CAPEC (Common Attack Pattern Enumeration): https://cvefeed.io/capec/detail/capec-62-cross-site-request-forgery
- MITRE ATT&CK (Enterprise): https://attack.mitre.org/techniques/T1190/
- OWASP Top 10 (Web, 2021): https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/