# Threat Analyse ShopFlow - Bericht

*Erzeugt am 22.09.2026 13:22 aus dem Analysemodell.*

## Überblick
- Modellelemente: 23
- Angriffsflächen: 18
- TI-Befunde: 3
- Bedrohungen: 6

## 1 Systemmodell

**Elemente**

- `E-01` Kunde (Externer Akteur) - Endnutzer via Browser, registriert oder als Gast.
- `E-02` Shop-Administrator (Externer Akteur) - Verwaltet Sortiment, Preise und Konfiguration.
- `E-03` User-Bereich (Frontend-Komponente) - SPA-Bereich für Bestellungen, Kundenkonto, Kreditkarte. Karteneingabe erfolgt in eingebettetem iframe des Zahlungsdienstleisters; Kartendaten berühren ShopFlow nicht.
- `E-04` Admin-Bereich (Frontend-Komponente) - SPA-Bereich für Sortiment, Preise, Shop-Konfiguration.
- `E-05` Authentication (Dienst) - Keycloak 18.0.0, OIDC/OAuth 2.0 (Authorization Code Flow), RS256-signierte JWT, Zugriffstoken 8h gültig ohne Rücknahme, TOTP optional.
- `E-06` API Gateway (REST) (Gateway) - Routing und Token-Prüfung (JWT mit Rolleninformationen).
- `E-07` Monitoring für Frontend (Dienst) - Überwacht Verfügbarkeit und Fehler des Frontends (Sentry: JavaScript-Fehler, Ladezeiten, Nutzersitzungen).
- `E-08` Middleware Service (Integrationsdienst) - Anbindung an Backend-Services und externe Systeme, Formatumsetzungen, hält Anbindungen nach außen.
- `E-09` Backend (Anwendungsdienst) - Shop-Service, Katalog, Warenkorb.
- `E-10` Bestellung (Anwendungsdienst) - Annahme, Status, Storno von Bestellungen. Publiziert Kafka-Ereignis 'Bestellung angelegt'; empfängt HMAC-signierten Webhook vom Zahlungsdienstleister.
- `E-11` Logistik (Anwendungsdienst) - Sendungsverfolgung.
- `E-12` Suche (Anwendungsdienst) - Produktsuche.
- `E-13` Mailserver Gateway (Dienst) - Postfix, Mailversand von Bestellbestätigungen und Marketing-E-Mails.
- `E-14` Datenbank (User) (Datenspeicher) - PostgreSQL 13.4, Kundendaten und Zahlungsmittel-Token; Zugriff per JDBC, TLS optional und derzeit deaktiviert.
- `E-15` Datenbank Bestellungen (Datenspeicher) - MySQL, Bestelldaten, Zugriff ohne TLS.
- `E-16` Datenbank Versandaufträge (Datenspeicher) - Versandauftragsdaten.
- `E-17` Mailserver (Dienst) - SMTP-Relay, TLS erwähnt (Implementierungsdetail unbekannt).
- `E-18` Monitoring (Betriebsdienst) - Grafana, Prometheus.
- `E-19` Log Server DB (Datenspeicher) - OpenSearch, Protokolle aller Dienste; Einträge enthalten u.a. User-Agent und E-Mail-Adresse angemeldeter Nutzer.
- `E-20` Google Analytics (Externes System) - Externer Analysedienst; erhält Seitenaufrufe und Conversion-Trichter-Daten vom Frontend.
- `E-21` Faktur SaaS (Externes System) - Rechnungserstellung; erhält Kunden- und Bestelldaten vom Middleware Service; Anbindung per OAuth 2.0.
- `E-22` Zahlungsdienstleister (Externes System) - PCI-DSS-zertifiziert, Kartendaten außerhalb des Systems; stellt iframe und Zahlungsmittel-Token bereit, meldet Zahlungsstatus per HMAC-signiertem Webhook.
- `E-23` Werbung und Affiliate Marketing (Externes System) - Externer Werbe-/Marketingpartner; Werbepartner-Skript erhält Klicks und Konversionen vom Frontend.

**Vertrauensgrenzen**

- `VG-1` Externe Zugangsgrenze - Grenze zwischen externen Akteuren und Frontend über HTTPS.
- `VG-2` Frontend-/Zugriffsschicht - Grenze der Frontend- und Zugriffskomponenten.
- `VG-3` Integrationsschicht - Grenze um den Middleware Service.
- `VG-4` Anwendungs- und Datenschicht - Grenze um Backend-Dienste und Datenbanken. Hinweis: technische Durchsetzung (Segmentierung/Firewalls) nicht dokumentiert.
- `VG-5` Externe Systeme und Partner - Grenze zu Drittsystemen außerhalb des eigenen Systems.

## 2 Assets und Schutzziele
- `A-01` Kundendaten (Element E-14, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Personenbezogene Daten unterliegen Schutzanforderungen. DB-Zugriff per JDBC mit deaktiviertem TLS erhöht Risiko.
- `A-02` Zahlungsmittel-Token (Element E-14, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. Kartendaten selbst verlassen das System nicht (iframe des PCI-DSS-zertifizierten Zahlungsdienstleisters), aber der in der User-DB gespeicherte Zahlungsmittel-Token ist missbrauchsrelevant. Verschlüsselung des Tokens at rest nicht dokumentiert.
- `A-03` Bestelldaten (Element E-15, Kritikalität: hoch) - Schutzziele: Integrität, Verfügbarkeit. Bestellungen sind geschäftskritisch. DB-Zugriff ohne TLS erhöht Risiko.
- `A-04` Versandauftragsdaten (Element E-16, Kritikalität: mittel) - Schutzziele: Integrität, Verfügbarkeit. Für Logistikabwicklung erforderlich.
- `A-05` Shop-Konfiguration/Sortiment/Preise (Element E-04, Kritikalität: hoch) - Schutzziele: Integrität. Manipulation beeinflusst Geschäftsbetrieb direkt.
- `A-06` Authentifizierungs-Token (JWT) (Element E-05, Kritikalität: hoch) - Schutzziele: Vertraulichkeit, Integrität. RS256-signierte JWT mit 8h Gültigkeit ohne Rücknahmemöglichkeit; kompromittierte Token bleiben lange gültig. Token-Prüfung sichert Zugriffskontrolle.
- `A-07` Protokolldaten (Element E-19, Kritikalität: mittel) - Schutzziele: Integrität, Vertraulichkeit. Protokolle enthalten personenbezogene Daten (E-Mail-Adressen, User-Agent) und sind für Nachvollziehbarkeit und Forensik relevant. Zugriffskontrolle nicht dokumentiert.

## 3 Angriffsflächen
- `AF-01` Kundenzugang zum User-Bereich - Elemente: E-01, E-03 | erreichbare Assets: A-01, A-02, A-03. Der externe Kunde greift ueber HTTPS (DF-01) ueber die externe Zugangsgrenze auf den User-Bereich zu, der Bestell- und Kundenfunktionen bereitstellt.
- `AF-02` Administratorzugang zum Admin-Bereich - Elemente: E-02, E-04 | erreichbare Assets: A-05. Der externe Shop-Administrator greift ueber HTTPS (DF-02) ueber die externe Zugangsgrenze auf den Admin-Bereich mit Sortiment-/Preis-/Konfigurationshoheit zu.
- `AF-03` Authentifizierung Admin-Bereich zu Keycloak - Elemente: E-04, E-05 | erreichbare Assets: A-06. Der OIDC/OAuth-Fluss (DF-03) ueberschreitet die Frontend-/Zugriffsschicht und exponiert die Ausstellung der JWT-Authentifizierungstoken.
- `AF-04` API-Aufrufe Admin-Bereich zu API Gateway - Elemente: E-04, E-06 | erreichbare Assets: A-05, A-06. Die API-Aufrufe mit JWT (DF-04) und die API-Antworten (DF-05) ueberschreiten die Frontend-/Zugriffsschicht und exponieren Routing und Token-Pruefung.
- `AF-05` API Gateway zu Middleware Service - Elemente: E-06, E-08 | erreichbare Assets: A-06. Der Routing-Fluss mit JWT-Token (DF-07) ueberschreitet die Integrationsschicht, wobei Verschluesselung/Authentifizierung nicht dokumentiert sind.
- `AF-06` Admin-Bereich zu Middleware Service - Elemente: E-04, E-08 | erreichbare Assets: A-05. Der Datenfluss vom Admin-Bereich zur Middleware (DF-08) ueberschreitet die Integrationsschicht mit unbekanntem Inhalt und Schutz.
- `AF-07` Middleware Service zu Backend - Elemente: E-08, E-09 | erreichbare Assets: A-01, A-02. Der Fluss Middleware zu Backend (DF-09) ueberschreitet die Anwendungs-/Datenschicht ohne dokumentierte Verschluesselung/Authentifizierung und erreicht ueber das Backend die User-DB.
- `AF-08` Middleware Service zu Bestellung - Elemente: E-08, E-10 | erreichbare Assets: A-03. Der Fluss Middleware zu Bestellservice (DF-10) ueberschreitet die Anwendungs-/Datenschicht ohne dokumentierte Sicherung und erreicht Bestelldaten.
- `AF-09` Middleware Service zu Logistik - Elemente: E-08, E-11 | erreichbare Assets: A-04. Der Fluss Middleware zu Logistik (DF-11) ueberschreitet die Anwendungs-/Datenschicht ohne dokumentierte Sicherung und erreicht Versandauftragsdaten.
- `AF-10` Middleware Service zu Suche - Elemente: E-08, E-12 | erreichbare Assets: -. Der Fluss Middleware zu Suche (DF-12) ueberschreitet die Anwendungs-/Datenschicht ohne dokumentierte Verschluesselung/Authentifizierung.
- `AF-11` Middleware Service zu Mailserver Gateway - Elemente: E-08, E-13 | erreichbare Assets: -. Der Fluss Middleware zu Mailserver Gateway (DF-13) mit Bestellbestaetigungen/Marketing-E-Mails ueberschreitet die Anwendungs-/Datenschicht.
- `AF-12` Middleware Service zu Faktur SaaS - Elemente: E-08, E-21 | erreichbare Assets: A-01, A-03. Der Fluss Middleware zu Faktur SaaS (DF-14) uebermittelt Kunden- und Bestelldaten ueber die Grenze zu Drittsystemen.
- `AF-13` Bestellung zu Zahlungsdienstleister - Elemente: E-10, E-22 | erreichbare Assets: A-03. Der Fluss Bestellung zum Zahlungsdienstleister (DF-20) mit Bestelldaten zur Zahlungsausloesung ueberschreitet die Grenze zu externen Systemen.
- `AF-14` Webhook Zahlungsdienstleister zu Bestellung - Elemente: E-22, E-10 | erreichbare Assets: A-03. Der HMAC-signierte Webhook (DF-21) ist ein von aussen eingehender Aufruf ueber die externe Systemgrenze, der Bestellstatus manipulieren koennte.
- `AF-15` User-Bereich zu Zahlungsdienstleister (iframe/Tokenisierung) - Elemente: E-03, E-22 | erreichbare Assets: A-02. Der Fluss aus dem Browser zum Zahlungsdienstleister (DF-22) mit Kartendaten via iframe und Token-Rueckgabe ueberschreitet die externe Systemgrenze.
- `AF-16` Frontend zu Google Analytics - Elemente: E-03, E-20 | erreichbare Assets: -. Der Fluss aus dem Browser zu Google Analytics (DF-23) mit Seitenaufrufen und Conversion-Daten ueberschreitet die Grenze zu Drittsystemen (Konsent offen).
- `AF-17` Frontend zu Werbung/Affiliate Marketing - Elemente: E-03, E-23 | erreichbare Assets: -. Der Fluss aus dem Browser zum Werbepartner-Skript (DF-24) mit Klicks und Konversionen ueberschreitet die Grenze zu Drittsystemen (Konsent offen).
- `AF-18` Zahlungsdienstleister als eingebundenes externes System (iframe/Webhook) - Elemente: E-22 | erreichbare Assets: A-02, A-03. Der Zahlungsdienstleister ist ein extern gesteuertes System, das ueber iframe und Webhook direkt in Frontend und Bestellservice eingreift und damit eine externe Angriffsflaeche bildet.

## 4 Threat-Intelligence-Befunde
- `TI-01` A01:2021 [OWASP] zu AF-01 - Broken Access Control ist das kritischste Web-Anwendungsrisiko laut OWASP 2021: 94 % der getesteten Anwendungen weisen eine Form von Zugriffskontroll-Schwäche auf. Angreifer können URL-Parameter manipulieren, fremde Konten einsehen oder Privilege Escalation durchführen – direkt relevant für den Kundenkonto- und Bestellbereich der SPA.
    Beleg: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/ (abgerufen 2026-09-22T11:20:56+00:00, Ausnutzung: unbekannt)
- `TI-02` A07:2021 [OWASP] zu AF-01 - Identification and Authentication Failures (ehem. Broken Authentication): Die Kategorie umfasst Credential Stuffing, Brute-Force-Angriffe, schwache Passwörter, unsichere Session-IDs und JWT-Missbrauch. Für einen über HTTPS erreichbaren Registrierungs-/Login-Bereich (registrierte Kunden und Gäste) ist dies ein zentrales Risiko.
    Beleg: https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/ (abgerufen 2026-09-22T11:20:56+00:00, Ausnutzung: unbekannt)
- `TI-03` T1190 [K3] zu AF-01 - Exploit Public-Facing Application: Reale Angreifer nutzen Schwachstellen (Bugs, Fehlkonfigurationen) in internetexponierter Software, um initialen Zugang zu erlangen – ohne Nutzerinteraktion. Laut Verizon DBIR 2025 ist dies der zweithäufigste Initial-Access-Vektor; die Zeit von Disclosure bis Massenausnutzung beträgt nur noch Stunden.
    Beleg: https://attack.mitre.org/techniques/T1190/ (abgerufen 2026-09-22T11:20:56+00:00, Ausnutzung: aktiv und weit verbreitet – zweithäufigster Initial-Access-Vektor laut Verizon DBIR 2025)

## 5 Bedrohungsverzeichnis mit Bewertung und Priorisierung

### `T-03` Ausnutzung öffentlich erreichbarer SPA/Endpunkte für Erstzugang  —  Priorität: **kritisch** (Score 25)
- STRIDE: Tampering | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-03
- Angreifer nutzen Schwachstellen oder Fehlkonfigurationen der internetexponierten SPA bzw. der dahinterliegenden Endpunkte, um ohne Nutzerinteraktion initialen Zugang zu erlangen.
- Angriffsszenario: Ein Angreifer scannt die exponierte SPA/API, findet eine bekannte Schwachstelle oder Fehlkonfiguration und exploited einen Endpunkt für Codeausführung oder Datenmanipulation.
- Voraussetzungen: Verwundbare oder ungepatchte Frontend-/API-Komponente ist von außen erreichbar und ungenügend gehärtet.
- Auswirkung: Kompromittierung des User-Bereichs als Einstiegspunkt, potenziell mit Zugriff auf nachgelagerte Assets (A-01, A-02, A-03) und Manipulation von Daten.
- Bewertung: Eintrittswahrscheinlichkeit 5 (T1190 ist laut DBIR 2025 aktiv und weit verbreitet als zweithäufigster Initial-Access-Vektor.); Auswirkung 5 (Erstzugang über öffentliche Endpunkte kann zur Systemübernahme und Zugriff auf mehrere hochkritische Assets führen.); Assets: A-01, A-03, A-06

### `T-01` Broken Access Control / IDOR im Kundenkonto- und Bestellbereich  —  Priorität: **hoch** (Score 16)
- STRIDE: Elevation of Privilege | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-01
- Fehlende oder fehlerhafte serverseitige Autorisierung erlaubt Zugriff auf fremde Konto- und Bestelldaten durch Manipulation von Objekt-Referenzen (z.B. order_id, customer_id).
- Angriffsszenario: Ein registrierter Kunde ändert im API-Aufruf des User-Bereichs die order_id/customer_id auf fremde Werte und ruft darüber Bestell- und Kundendaten anderer Nutzer ab.
- Voraussetzungen: Autorisierungsprüfung erfolgt nur im Frontend oder das API Gateway/Backend prüft nicht, ob das JWT-Subjekt Eigentümer der referenzierten Ressource ist.
- Auswirkung: Unbefugte Einsicht/Änderung von Kundendaten (A-01), Zahlungsmittel-Token (A-02) und Bestelldaten (A-03) fremder Kunden mit Datenschutzverletzung.
- Bewertung: Eintrittswahrscheinlichkeit 4 (IDOR/Broken Access Control (A01:2021) ist eine weit verbreitete, mit öffentlichem Wissen ausnutzbare Schwäche, auch wenn kein aktiver Exploit-Status vorliegt.); Auswirkung 4 (Unautorisierter Zugriff auf hochkritische Kunden-, Token- und Bestelldaten verletzt Vertraulichkeit und Integrität.); Assets: A-01, A-02, A-03

### `T-02` Credential Stuffing / Brute-Force gegen Kunden-Login  —  Priorität: **hoch** (Score 16)
- STRIDE: Spoofing | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- TI-Beleg: TI-02
- Schwache Authentifizierung ermöglicht automatisierte Anmeldeversuche mit geleakten Zugangsdaten oder Passwort-Erraten am externen Login des User-Bereichs.
- Angriffsszenario: Ein Angreifer spielt große Listen geleakter E-Mail/Passwort-Kombinationen automatisiert gegen den Login und übernimmt Konten ohne aktivierte TOTP.
- Voraussetzungen: Kein wirksames Rate-Limiting/Bot-Schutz, wiederverwendete Passwörter der Kunden und TOTP nicht erzwungen.
- Auswirkung: Kontoübernahme mit Zugriff auf Kundendaten (A-01), Zahlungsmittel-Token (A-02) und Bestellhistorie (A-03) betroffener Kunden.
- Bewertung: Eintrittswahrscheinlichkeit 4 (Credential Stuffing/Brute-Force (A07:2021) ist mit gängigen Tools und geleakten Zugangsdaten leicht durchführbar.); Auswirkung 4 (Kontoübernahme kompromittiert hochkritische Kundendaten und gültige JWT ohne Rücknahmemöglichkeit.); Assets: A-01, A-06

### `T-04` Abstreitbarkeit von Bestell- und Kontoaktionen (unzureichende Nachweisbarkeit)  —  Priorität: **mittel** (Score 9)
- STRIDE: Repudiation | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Handlungen des Kunden (Bestellung, Stornierung, Kontoänderung) können mangels belastbarer, integritätsgeschützter Protokollierung nachträglich abgestritten werden.
- Angriffsszenario: Ein Kunde bestreitet eine getätigte Bestellung oder Kontoänderung, und der Betreiber kann die Aktion mangels manipulationssicherer Protokolle nicht eindeutig zuordnen.
- Voraussetzungen: Aktionen werden nicht oder nur ungeschützt (manipulierbar, ohne starke Nutzerbindung) protokolliert.
- Auswirkung: Streitfälle über Bestellungen (A-03) und Kontoänderungen belasten Geschäftsbetrieb und erschweren Forensik/Abrechnung.
- Bewertung: Eintrittswahrscheinlichkeit 3 (Unzureichende Nachweisbarkeit ist ohne besonderes Wissen ausnutzbar, wenn Protokollierung lückenhaft ist.); Auswirkung 3 (Fehlende Nachvollziehbarkeit betrifft primär die mittelkritischen Protokolldaten und erschwert Forensik.); Assets: A-07, A-03

### `T-05` Denial of Service gegen den externen User-Bereich  —  Priorität: **mittel** (Score 9)
- STRIDE: Denial of Service | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Massenhafte Anfragen oder ressourcenintensive Aufrufe gegen die öffentlich erreichbare SPA/API beeinträchtigen die Verfügbarkeit der Kundenfunktionen.
- Angriffsszenario: Ein Angreifer flutet Login-, Such- oder Bestell-Endpunkte des User-Bereichs mit Anfragen und macht den Shop für legitime Kunden unerreichbar.
- Voraussetzungen: Fehlendes oder unzureichendes Rate-Limiting, Skalierungs- oder DDoS-Schutz am externen Zugangspunkt.
- Auswirkung: Ausfall der Kunden-/Bestellfunktionen mit Umsatzverlust und beeinträchtigter Verfügbarkeit bestellbezogener Prozesse (A-03).
- Bewertung: Eintrittswahrscheinlichkeit 3 (DoS gegen öffentlich erreichbare Bereiche ist mit verfügbaren Mitteln möglich, aber ohne konkreten TI-Beleg.); Auswirkung 3 (Verfügbarkeit des User-Bereichs und damit der Bestellabwicklung wird spürbar beeinträchtigt.); Assets: A-03

### `T-06` Abgriff von Kunden-/Bestelldaten bei der Übertragung  —  Priorität: **mittel** (Score 8)
- STRIDE: Information Disclosure | Element: E-03 | Angriffsfläche: AF-01 | Methodik: kombiniert
- Vertrauliche Kunden- und Bestelldaten könnten bei fehlerhafter Transportverschlüsselung oder über kompromittierte Frontend-Skripte an Dritte offengelegt werden.
- Angriffsszenario: Ein Angreifer erzwingt eine TLS-Downgrade-/MitM-Situation oder nutzt ein manipuliertes Drittanbieter-Skript im Frontend, um übertragene Kunden- und Bestelldaten mitzulesen.
- Voraussetzungen: Unzureichende TLS-/HSTS-Konfiguration am Zugang oder fehlende Content-Security-Policy/Integritätsprüfung für eingebundene externe Skripte.
- Auswirkung: Offenlegung von Kundendaten (A-01) und Bestelldaten (A-03) mit Datenschutz- und Reputationsschaden.
- Bewertung: Eintrittswahrscheinlichkeit 2 (Abgriff bei der Übertragung erfordert eine Man-in-the-Middle-Position; intern erhöht deaktiviertes JDBC-TLS jedoch die Machbarkeit.); Auswirkung 4 (Kompromittierung der Übertragung hochkritischer Kundendaten und Zahlungsmittel-Token verletzt die Vertraulichkeit.); Assets: A-01, A-02

## 6 Annahmen
- HTTPS wird nur für Zugangskanäle explizit genannt; interne Kommunikation ist überwiegend unspezifiziert, TLS zu den Datenbanken ist deaktiviert bzw. nicht vorhanden.
- Zahlungskartendaten verbleiben laut Systembeschreibung außerhalb des Systems beim PCI-DSS-zertifizierten Zahlungsdienstleister (iframe); ShopFlow speichert nur einen Zahlungsmittel-Token.
- Der Middleware Service ist zentraler Integrationspunkt zu allen Backend- und Externsystemen (Faktur SaaS per OAuth 2.0).
- Frontend-seitige Drittanbieter-Skripte (Google Analytics, Werbepartner) senden Daten direkt aus dem Browser an die externen Systeme, nicht über das Backend.
- Der Zahlungsdienstleister kommuniziert direkt mit dem Bestellservice (Webhook) und mit dem User-Bereich (iframe/Tokenisierung).

## 7 Offene Rückfragen an den Nutzer
- Welche Daten werden an Google Analytics, Faktur SaaS und Werbung/Affiliate übermittelt und mit welcher Rechtsgrundlage (Konsent gemäß Datenschutzerklärung)?

## 8 Quellenverzeichnis (Threat Intelligence)
- MITRE ATT&CK (Enterprise): https://attack.mitre.org/techniques/T1190/
- OWASP Top 10 (Web, 2021): https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
- OWASP Top 10 (Web, 2021): https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/