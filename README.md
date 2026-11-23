# Phylax Genitore (web)

App web del genitore per ricevere, cifrati, gli avvisi dall'app Android «Phylax» installata sul telefono del figlio. Prototipo: solo prove con messaggi inventati.

- Nessuna libreria, nessun CDN, nessun tracciamento: solo i file di questa cartella.
- Cifratura end-to-end nel browser (WebCrypto): ECDH P-256, HKDF-SHA256, AES-256-GCM. La chiave privata non lascia il telefono e non è esportabile.
- Consegna tramite [ntfy.sh](https://ntfy.sh) (gratuito, senza account): il server vede solo testo cifrato.
- Sul telefono restano solo chiavi, contatori e l'impronta del PIN; gli avvisi non vengono salvati.

## Su iPhone
1. Apri il sito in Safari › Condividi › **Aggiungi alla schermata Home**.
2. Scegli un PIN, tocca **Abbina** e incolla il codice nell'app Phylax del figlio (Telefono del genitore). Confrontate il codice di verifica a 6 cifre.
3. Apri *Notifiche* › **Attiva notifiche** › Consenti. Riceverai solo «Nuovo avviso da Phylax: apri l'app», mai il contenuto.
4. (Facoltativo) Nella pagina principale, sezione *Sicurezza* › **Sblocca con Face ID** › conferma con Face ID. All'apertura l'app chiede subito Face ID; il PIN resta sempre valido. Il PIN si sblocca da solo all'ultima cifra.

## In locale
```bash
python3 -m http.server 8765 --bind 127.0.0.1
```
e apri http://127.0.0.1:8765/
