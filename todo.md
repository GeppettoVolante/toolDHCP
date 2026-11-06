# Todo

## Punti aperti
- [ ] BLOCCANTE: creare il repo GitHub `toolDHCP` (origin punta all'archivio read-only), poi push, tag v1.2 e release
- [ ] Pubblicare v1.2 (exe gia' ricostruito, SHA-256 fa239d80...cb75): commit/push, tag, release con exe e note
- [ ] Occhiata visiva alla GUI in inglese (il layout e' gia' verificato via Tk)
- [ ] Decidere lease: ora infinito (0xFFFFFFFF); valutare lease finito lungo
- [ ] Fase 2 (futura): riparametrazione via CIP, aggiunta MAC manuale

## Work in progress
- (nessuno)

## Chiusi
- [x] Commenti/docstring, GUI, messaggi e help CLI tradotti in inglese, test 40/40 OK (2026-11-07, da committare)
- [x] History ripulita in locale (2026-11-06). Il repo GitHub pulito pero' non esiste (vedi Punti aperti)
- [x] Release v1.1 con tabella OUI completa (2026-11-06)
- [x] OUI dal registro IEEE (40455 voci) + script di aggiornamento (2026-11-06)
- [x] Licenza MIT, README inglese, pulizia note interne (2026-11-06)
- [x] Release v1.0 su GitHub con exe allegato (2026-11-06), SHA-256 50f5538da728f82f9120764954e2a1c21cb8169ebd85c43facd3789e55da5f90
- [x] Test su banco (2026-11-06): funziona tutto (exe, scelta interfaccia, assegnazione IP)
- [x] GUI Tkinter: scelta interfaccia all'avvio, lista MAC visti, arma/disarma, log (src/gui.py)
- [x] Elenco interfacce IPv4 via ctypes/GetAdaptersAddresses (src/netif.py), filtro /32 e link-local
- [x] Più MAC armati insieme, scan passivo con stato per MAC (Responder.arm/disarm/seen)
- [x] Riconoscimento costruttore da OUI (src/oui.py)
- [x] Exe portable con PyInstaller onefile (build_exe.ps1), 9,7 MB, avvio verificato
- [x] Lease infinito 0xFFFFFFFF verificato: RFC 2131 par. 3.3
- [x] Serve robusto: ignora WSAECONNRESET (10054), non muore su errori di invio
- [x] PoC da riga di comando, parse/build BOOTP/DHCP, test unitari + loopback
