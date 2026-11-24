# Phylax Genitore (web)

App web del genitore per ricevere, cifrati, gli avvisi dall'app Android «Phylax» installata sul telefono del figlio. Prototipo: solo prove con messaggi inventati.

- Nessuna libreria, nessun CDN, nessun tracciamento: solo i file di questa cartella (anche il QR, `qr.js`, è scritto da zero).
- Cifratura end-to-end nel browser (WebCrypto): ECDH P-256, HKDF-SHA256, AES-256-GCM. La chiave privata non lascia il telefono e non è esportabile.
- Consegna tramite la nostra casella cifrata su Cloudflare (0.16, messaggi tenuti 7 giorni, codice in `worker/` del progetto) e, per una versione ancora, [ntfy.sh](https://ntfy.sh). I server vedono solo testo cifrato.
- Avvisi, segnalazioni e archivio restano salvati **cifrati** sul telefono (0.15, IndexedDB, AES-256-GCM): la chiave dei dati è protetta dal PIN (PBKDF2, 310.000 iterazioni) e, se attivo, da Face ID. Il PIN non viene mai salvato in chiaro. Chiudere o riavviare l'app non li perde; un nuovo abbinamento li cancella.
- Tre livelli di avviso (0.12): **Rischio alto** (rosso), **Da verificare** (ambra), **Dubbio · da guardare** (viola: segnale incerto, mandato per sicurezza).
- «Lingua o codice non riconosciuto» (0.13): se Phylax non capisce una chat (almeno 8 messaggi in 10 minuti, più della metà non riconosciuti) avvisa in viola. Nella segnalazione, «Questa lingua va bene» smette di avvisare per la lingua di quella chat.
- «Possibile foto intima» (0.14): avviso solo testo (cartella e ora). L'immagine resta sul telefono del figlio e non viene mai inviata.
- QR di abbinamento (0.15): la pagina *Abbina* mostra il codice anche come QR; sul telefono del figlio «Fotografa il QR del genitore». Copia e incolla resta possibile.

## Su iPhone
1. Apri il sito in Safari › Condividi › **Aggiungi alla schermata Home**.
2. Scegli un PIN e tocca **Abbina**: compare un QR. Nell'app Phylax del figlio (Telefono del genitore) tocca «Fotografa il QR del genitore» (oppure copia e incolla il codice). Confrontate il codice di verifica a 6 cifre.
3. Apri *Notifiche* › **Attiva notifiche** › Consenti. Riceverai solo «Nuovo avviso da Phylax: apri l'app», mai il contenuto.
4. (Facoltativo) Nella pagina principale, sezione *Sicurezza* › **Sblocca con Face ID** › conferma con Face ID. All'apertura l'app chiede subito Face ID; il PIN resta sempre valido. Il PIN si sblocca da solo all'ultima cifra.

## In locale
```bash
python3 -m http.server 8765 --bind 127.0.0.1
```
e apri http://127.0.0.1:8765/
