# Referenzsystem ShopFlow – Komponentenbeschreibung zur Systemarchitektur

## 1 Zugangskanäle

### Kunde
- **Technologie:** Webbrowser; HTTPS mit TLS 1.2/1.3
- **Beschreibung:** Registrierter oder als Gast auftretender Endkunde; ruft den User-Bereich der Single-Page-Anwendung auf, bestellt Waren und verwaltet Konto und Zahlungsmittel.

### Shop-Administrator
- **Technologie:** Webbrowser; HTTPS über das öffentliche Internet
- **Beschreibung:** Fachlicher Betreiber des Shops; pflegt Sortiment, Preise und Shop-Konfiguration im Admin-Bereich. Anmeldung per Benutzername/Passwort.

---

## 2 Frontend- und Zugriffsschicht

### Frontend
- **Technologie:** React 17 (Single-Page-Anwendung), statisch ausgeliefert über nginx 1.20.1 mit ModSecurity 3.0.4 / OWASP CRS 3.3
- **Beschreibung:** Gemeinsame Webanwendung für Kunden- und Administrationsbereich unter derselben Domäne; Trennung nur über den Pfad `/admin`.

### User-Bereich
- **Technologie:** React 17, Modul der SPA; Zugriffstoken im Speicher, Aktualisierungstoken im Cookie (`HttpOnly`, `Secure`, ohne `SameSite`)
- **Beschreibung:** Kundenfunktionen: Bestellungen, Kundenkonto und Zahlungsmittel (im Frontend als „Kreditkarte“ geführt). Die eigentliche Karteneingabe erfolgt im eingebetteten iframe des Zahlungsdienstleisters; Kartendaten liegen nicht im System.

### Admin-Bereich
- **Technologie:** React 17, Modul der SPA; Rollen `shop-admin`, `shop-support`
- **Beschreibung:** Pflege von Sortiment, Preisen, Shop-Konfiguration und Benutzern; wird auch vom Support zum Einsehen von Kundenkonten und Stornieren von Bestellungen genutzt.

### Authentication
- **Technologie:** Keycloak 18.0.0; OIDC/OAuth 2.0 (Authorization Code Flow), RS256-signierte JWT
- **Beschreibung:** Zentrale Anmeldung für Kunden, Administratoren und Support; stellt Zugriffs- (8 h gültig, keine Rücknahme) und Aktualisierungstoken aus; Passwortzurücksetzung; TOTP optional.

### API Gateway (REST)
- **Technologie:** Kong Gateway 2.8; REST/JSON
- **Beschreibung:** Einziger Eintrittspunkt zu den Backend-Diensten; Routing, Token-Prüfung über JWKS von Keycloak, Rollenprüfung je Route, Ratenbegrenzung.

### Monitoring für Frontend
- **Technologie:** ⚠ Sentry 9.1.2 (self-hosted) mit `@sentry/browser` 5.15.0
- **Beschreibung:** Erfassung von JavaScript-Fehlern, Ladezeiten und Nutzersitzungen im Browser; liefert Fehlerberichte an das Entwicklungsteam. *(Ergänzung ggü. der vollständigen Fassung, s. Abschnitt „Abgleich“.)*

---

## 3 Integrationsschicht

### Middleware Service
- **Technologie:** Java 11, Spring Boot 2.6.3, Spring Framework 5.3.15
- **Beschreibung:** Vermittelt zwischen API-Gateway und Fachdiensten, führt Formatumsetzungen durch und hält die Anbindungen nach außen (Faktur-SaaS per REST/OAuth Client Credentials, SAP per SOAP, Drittanbieter per REST und nächtlichem SFTP-Import). Prüft die Rolle aus dem Token nicht erneut.

---

## 4 Anwendungs- und Datenschicht

### Backend (Shop-Service)
- **Technologie:** Java 11, Spring Boot 2.6.3; Logging über Apache Log4j 2.14.1
- **Beschreibung:** Katalog, Warenkorb, Kundenkonto und Preisberechnung; nutzt den Sitzungsspeicher Redis 6.2 für anonyme Warenkörbe.

### Bestellung
- **Technologie:** Java 11, Spring Boot 2.6.3; Apache Kafka 3.1 mit Avro / Confluent Schema Registry 7.0
- **Beschreibung:** Bestellannahme, Statusverwaltung und Stornierung; stößt die Zahlung beim Zahlungsdienstleister an und empfängt dessen HMAC-signierten Webhook; publiziert das Ereignis „Bestellung angelegt“.

### Logistik
- **Technologie:** Java 11, Spring Boot 2.6.3; Kafka-Consumer
- **Beschreibung:** Versandaufträge, Labelerzeugung und Sendungsverfolgung über die REST-API des Versanddienstleisters.

### Suche
- **Technologie:** Elasticsearch 7.10.2 hinter eigenem Java-Adapter
- **Beschreibung:** Produktsuche, Autovervollständigung und Filter; betrieben ohne Sicherheits-Plugin, d. h. ohne Authentifizierung.

### Mailserver Gateway
- **Technologie:** Postfix 3.5 als Relay-Vorschaltung; SMTP intern
- **Beschreibung:** Nimmt Mailaufträge der Fachdienste (Bestellbestätigungen, Marketing) entgegen; intern als offenes Relay ohne Authentifizierung erreichbar.

### Mailserver
- **Technologie:** Externes SMTP-Relay; SMTP über TLS, Port 587, Benutzername/Passwort
- **Beschreibung:** Eigentlicher Versand der E-Mails an die Empfänger; wird vom Mailserver Gateway beliefert. Im Diagramm innerhalb der Schicht dargestellt, fachlich ein externer Dienst.

### Datenbank (User)
- **Technologie:** PostgreSQL 13.4; Zugriff per JDBC, TLS optional und derzeit deaktiviert
- **Beschreibung:** Kundenstammdaten, Anschriften, Passwort-Hashes (bcrypt) und Zahlungsmittel-Token des Zahlungsdienstleisters.

### Datenbank Bestellung
- **Technologie:** PostgreSQL 13.4; JDBC ohne TLS
- **Beschreibung:** Bestellungen, Positionen, Preise, Rechnungsbezüge und Stornierungen.

### Datenbank Logistik
- **Technologie:** MySQL 8.0.28; JDBC ohne TLS
- **Beschreibung:** Versandaufträge, Sendungsnummern und Empfängeranschriften.

---

## 5 Betrieb und Überwachung

### Monitoring
- **Technologie:** Grafana 8.3.0, Prometheus 2.32; Protokollsammlung über Logstash, Log4j-Appender per TCP
- **Beschreibung:** Metriken, Dashboards und Alarmierung sowie das Einsammeln der Protokolle aller Dienste; Zugang für den Betrieb über VPN mit lokalen, teils geteilten Grafana-Konten.

### Log Server DB
- **Technologie:** OpenSearch 1.2; HTTP mit Basisauthentifizierung
- **Beschreibung:** Zentrale Ablage der Anwendungs- und Zugriffsprotokolle; die Einträge enthalten u. a. `User-Agent` und E-Mail-Adresse angemeldeter Nutzer.

---

## 6 Externe Systeme und Partner

### Google Analytics
- **Technologie:** Google Analytics 4, eingebunden per `gtag.js` im Frontend
- **Beschreibung:** Web-Analyse des Nutzerverhaltens (Seitenaufrufe, Conversion-Trichter); Datenübermittlung direkt aus dem Browser an Google. 

### Faktur SaaS
- **Technologie:** Cloud-Dienst; HTTPS, REST, OAuth 2.0 Client Credentials
- **Beschreibung:** Erstellung und Archivierung der Rechnungen; erhält Kunden- und Bestelldaten vom Middleware Service.

### Zahlungsdienstleister
- **Technologie:** PCI-DSS-zertifizierter PSP; HTTPS/REST, eingebettetes iframe, HMAC-signierte Webhooks
- **Beschreibung:** Wickelt die Kartenzahlung ab; Kartendaten werden nur im Formular des Dienstleisters erfasst und berühren ShopFlow nicht. Meldet den Zahlungsausgang an den Bestellservice zurück.

### Werbung und Affiliate Marketing
- **Technologie:** Eigener Dienst: Node.js 16 (EOL), Express 4.17.1; Partneranbindung per HTTPS/REST mit statischem API-Schlüssel
- **Beschreibung:** Auslieferung von Anzeigen (Partnerskript im Browser des Kunden), Erfassung von Klicks und Konversionen sowie Provisionsabrechnung gegenüber den Partnern.

---

