# Log

Voci in ordine cronologico inverso.

## 2026-11-07 (pubblicazione + commenti in inglese)
- ATTENZIONE: su GitHub esiste solo `toolDHCP-archivio` (privato, archiviato, sola lettura); il repo `toolDHCP` pulito NON risulta esistere (verificato con `gh repo list`). Il remote `origin` punta all'archivio per redirect: il push da 403. Commit locale `b2f8543` non pubblicato. La nota "repo reso pubblico" nel todo era inesatta.
- Commenti e docstring tradotti in inglese in `src/` (bootp, server, gui, netif), nei test e in `tools/`. Stringhe dell'interfaccia e messaggi d'errore lasciati in italiano. Corretto in `bootp.py` il commento sul lease infinito (era ancora "da verificare", ma e' RFC 2131 par. 3.3).
- Anche GUI, messaggi di log/errore, help della CLI e stati (`seen`, `BOOTP replied`, `waiting`...) ora in inglese. Due test confrontavano il testo italiano (`test_port_busy_message`, `test_arm_after_seen_then_reply`): allineati.
- Layout GUI verificato via Tk (schermata 2: 780x489 richiesti su 860x560, nessun taglio). Provato solo programmaticamente, non a occhio.
- Exe v1.2 ricostruito in `build-out/dist` (10,4 MB, SHA-256 fa239d807d99397998ab6be6cf809ae66e6e9f3d3255444bf12cc7ba195fcb75), si avvia e resta vivo, nessun percorso personale. NON ancora pubblicato: serve commit/push, tag `v1.2` e release.
- `build_exe.ps1` corretto: con `Stop` PowerShell 5.1 abortiva sugli INFO di PyInstaller (stderr); ora controlla l'exit code.
- Test: 40/40 OK. Modifiche non ancora committate. Cambia il comportamento visibile: l'exe v1.1 e' obsoleto, serve ricostruire e rilasciare v1.2.

## 2026-11-06 (release 1.1)
- Release v1.1: exe ricostruito con la tabella OUI IEEE completa (10,4 MB, SHA-256 04574700d4ae5db04918d509387d5f68c9399eba5dd4a7913c7e93cadd6ad73e). Nessun percorso personale nell'exe.
- History Git ripulita dalle note interne: repo ricreato con un solo commit (il vecchio repo e' archiviato in privato come toolDHCP-archivio). Nessun force push.

## 2026-11-06 (OUI, licenza, pubblicazione)
- OUI: tabella completa dal registro IEEE MA-L (40455 voci) in `src/oui_data.py`, generata da `tools/update_oui.py`; `oui.py` ora legge da lì. I due prefissi usati finora (00:15:7B, 00:00:BC) confermati sul registro. Test 40/40 OK.
- Aggiunti `LICENSE` (MIT), README in inglese; ripulite le note interne in log e todo.

## 2026-11-06 (release 1.0)
- Tag `v1.0` e GitHub Release con `toolDHCP.exe` allegato (SHA-256 50f5538d...5f90, 9,7 MB, PyInstaller onefile). Note della release in inglese.
- Audit pre-pubblicazione: nessuna credenziale, nessun percorso personale nei sorgenti, nella history e nell'exe. Repo ancora privato. Da fare prima di renderlo pubblico: licenza, pulizia note interne, README in inglese.

## 2026-11-06 (test su banco)
- Provato su banco con dispositivi reali: funziona tutto. Chiusi i punti aperti su bind/broadcast/firewall/exe.

## 2026-11-06 (GUI + exe)
- Aggiunti `netif.py` (interfacce IPv4 via ctypes; rileva Ethernet, VPN e Bluetooth), `oui.py`, `gui.py` (Tkinter), `build_exe.ps1`, test `test_multi.py` e `test_gui.py`.
- `Responder` ora gestisce più MAC armati (arm/disarm), registra ogni MAC visto (`seen`) ed è thread-safe. API del PoC invariata, i 20 test originali passano.
- Scelta di design: bind sull'IP dell'interfaccia selezionata (non 0.0.0.0), così la risposta in broadcast esce dalla scheda giusta. [da verificare su banco]
- Windows: aggiunta gestione WSAECONNRESET (10054) nel loop di ricezione.
- Test: 40/40 OK (unit, loopback, validazione GUI, smoke Tk su 127.0.0.1 senza inviare nulla in rete). Mai eseguito su rete reale.
- Exe: PyInstaller 6.22.3 installato con pip; `toolDHCP.exe` onefile 9,7 MB, si avvia e resta vivo; la schermata di scelta non apre socket.
- Verificato: lease infinito 0xFFFFFFFF = RFC 2131 par. 3.3. OUI da siti terzi [poi verificati sul registro IEEE, vedi 2026-11-06 OUI].
- Non provato: invio/ricezione su rete reale, comportamento dell'exe con antivirus/SmartScreen.

## 2026-11-06 (PoC)
- Scritto PoC in `src/`: `bootp.py` (parse/build), `server.py` (listener, un solo MAC armato), `tests/test_bootp.py`.
- Test: 20/20 OK (unit + loopback 127.0.0.1 su porta effimera). Mai eseguito su rete reale.
- Scelte: risposta sempre in broadcast 255.255.255.255:68 (o giaddr:67 se relay); BOOTP puro = options in vend senza tipo DHCP; DHCP REQUEST con IP diverso dall'armato -> NAK; REQUEST con server-id altrui -> ignorata; INFORM/DECLINE/RELEASE ignorati.
- Verificato su RFC 951/2131/2132: layout header 236 B + cookie 99.130.83.99, bit broadcast, indirizzamento risposta, codici option, 300 B BOOTP. Non confermato: valore lease infinito 0xFFFFFFFF [da verificare].
- Decisioni: BOOTP e DHCP, dispositivi vergini, solo stdlib Python 3, niente CIP per ora.

## 2026-11-06
- Creata la cartella progetto dal template.
