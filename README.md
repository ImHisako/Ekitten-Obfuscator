# Ekitten Final

Ekitten Final è un obfuscator Python a file singolo, progettato con un approccio **compatibility-first**. Trasforma in modo conservativo il sorgente quando il profilo lo permette, comprime il risultato e lo protegge con più round autenticati del cifrario sperimentale BlazingOpossum presente nel repository.

Il progetto non usa AES. Il loader generato dipende esclusivamente dalla libreria standard Python e contiene un port memory-safe dello schema MARX-P/CTR di `Python Obfuscators/BlazingOpossum-main`.

> L’obfuscation aumenta costo e tempo necessari per analizzare un programma, ma non rende il codice “impossibile da recuperare”. Un programma Python autonomo deve contenere codice, dati e materiale necessario all’esecuzione: un analista che controlla il runtime può quindi osservare il payload dopo la decodifica.

## Funzionalità principali

- Tre profili di protezione: `compatible`, `balanced` e `maximum`.
- Da 1 a 12 round BlazingOpossum configurabili.
- Tag di integrità verificato prima di decifrare ogni round.
- `IntObfuscator` AST polimorfico con sei strategie aritmetiche e bitwise.
- `StringObfuscator` UTF-8 polimorfico con sei strategie byte-safe.
- Rinomina selettiva delle variabili locali nei soli scope considerati sicuri.
- Compressione del payload con `zlib`.
- Chiavi mascherate e suddivise in componenti separate nel loader.
- Cifrato frammentato, codificato Base85, permutato e mescolato con chunk esca.
- Identificatori del loader differenti per ogni build.
- Loader isolato in una funzione bootstrap che rimuove il proprio nome prima di eseguire il payload.
- Il bootstrap non chiama `exec()` e avvia il code object tramite `FunctionType`.
- Runtime guard contro monkey-patch Python di `compile`, `zlib.decompress` e, in modalità hardened, `marshal.loads`.
- Modalità opzionale `--runtime-hardening` senza ricostruzione del sorgente a runtime.
- Modalità `--code-object-hardening` per ridurre metadata e costanti leggibili nei dump.
- VM stack-based con opcode casuali per virtualizzare espressioni aritmetiche sicure.
- Sigillo SHA-256 canonico dell’intero artefatto verificato prima della decifratura.
- Azzeramento best-effort dei buffer mutabili contenenti chiavi, payload compresso e dati serializzati.
- Build casuali per impostazione predefinita o riproducibili tramite `--seed`.
- Manifest JSON opzionale senza plaintext o chiavi ricostruite.
- Verifica differenziale automatica tra programma originale e programma protetto.
- Nessuna dipendenza Python esterna.

## Requisiti

- CPython 3.10 o successivo è raccomandato.
- Lo sviluppo corrente è stato verificato con CPython 3.10 e 3.13.
- Il file da proteggere deve essere sintatticamente valido per la versione Python usata durante la build.

Ekitten Final protegge un file Python alla volta. Non è ancora un packager ricorsivo di interi package con risorse, estensioni native e metadata di distribuzione.

## Utilizzo rapido

Il nome del programma contiene uno spazio, quindi in PowerShell va racchiuso tra virgolette:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py"
```

Senza `--output`, il risultato viene scritto accanto all’input come `programma-ekitten.py`.

Protezione massima con otto round e verifica automatica:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py" `
  --output ".\programma-protetto.py" `
  --profile maximum `
  --layers 8 `
  --verify
```

Build riproducibile con manifest:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py" `
  --profile balanced `
  --seed 2026 `
  --manifest ".\programma.manifest.json"
```

Protezione runtime rafforzata, vincolata alla minor version Python usata per la build:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py" `
  --output ".\programma-hardened.py" `
  --profile maximum `
  --runtime-hardening `
  --verify
```

Visualizzare tutti gli argomenti:

```powershell
py -3.13 ".\Ekitten Final.py" --help
```

## Profili

| Profilo | Trasformazione stringhe | Trasformazione interi | Rinomina locali | Round predefiniti | Chunk esca | Impiego consigliato |
|---|---:|---:|---:|---:|---:|---|
| `compatible` | No | No | No | 1 | 0 | Codice che usa reflection, testo del sorgente o framework molto dinamici |
| `balanced` | Sì | Sì | No | 3 | 2 | Applicazioni generiche e scelta predefinita |
| `maximum` | Sì | Sì | Conservativa | 5 | 5 | Script già coperti da test differenziali completi |

`--layers N` sostituisce il numero di round del profilo. Sono ammessi valori da 1 a 12. Un numero maggiore aumenta tempo di build, startup e dimensione del materiale inserito, ma non risolve il limite fondamentale della chiave presente nel loader.

## Pipeline completa di obfuscation

### 1. Parsing e compilazione preventiva

Il sorgente viene analizzato con `ast.parse()` e compilato prima di qualsiasi trasformazione. Input non valido, encoding non leggibile o sintassi incompatibile interrompono la build con un errore esplicito.

Questo gate impedisce di attribuire all’obfuscator un errore già presente nel programma originale.

### 2. Rinomina conservativa delle variabili locali

Attiva nel profilo `maximum`. La pass rinomina soltanto variabili locali di funzioni semplici e mantiene invariati:

- nomi di funzioni, classi, metodi e argomenti pubblici;
- attributi e dunder;
- scope con `global` o `nonlocal`;
- funzioni con closure o scope annidati;
- comprehension e lambda;
- funzioni che usano `eval`, `exec`, `locals`, `globals`, `vars`, `dir`, `inspect` o frame runtime;
- funzioni contenenti structural pattern matching.

Quando l’analisi non è sufficientemente sicura, la funzione viene lasciata intatta. La compatibilità ha priorità sul numero di nomi rinominati.

### 3. `StringObfuscator` polimorfico

Nei profili `balanced` e `maximum`, le stringhe utilizzabili come normali espressioni vengono codificate in byte UTF-8 e ricostruite da un helper con nome casuale. Ogni stringa sceglie separatamente una delle sei strategie:

- somma progressiva con chiave e indice;
- XOR progressivo con rolling key;
- inversione dell’ordine combinata con XOR;
- rotazione degli 8 bit combinata con XOR;
- trasformazione affine invertibile modulo 256;
- separazione byte pari/dispari con rolling XOR.

Ogni strategia usa un token casuale differente per build e l’ordine dei branch del decoder viene permutato. La trasformazione opera sui byte, quindi conserva Unicode, caratteri null, newline, tab, slash e stringhe molto lunghe.

Sono protetti dalla trasformazione i contesti che devono mantenere una struttura compile-time particolare:

- docstring di modulo, classe e funzione;
- annotation e return annotation;
- pattern di `match/case`;
- f-string complete;
- type alias supportati dall’AST in uso.

La trasformazione non viene presentata come cifratura crittografica: rende meno immediata l’analisi del sorgente interno. La protezione del payload completo è affidata ai round BlazingOpossum successivi.

### 4. `IntObfuscator` polimorfico

Nei profili `balanced` e `maximum`, ogni costante intera viene sostituita da una chiamata a un helper con nome casuale. La strategia è scelta separatamente per ogni valore tra:

- XOR con mask casuale a 64 bit;
- somma e sottrazione tramite delta;
- trasformazione affine con moltiplicatore e offset;
- complemento bitwise;
- combinazione XOR più offset;
- ricostruzione da quoziente e resto.

Ogni strategia riceve un token di dispatch casuale differente per build. Anche l’ordine dei branch dell’helper viene permutato, rendendo meno stabile la firma statica tra due output.

Sono supportati zero, valori negativi, interi oltre 64 bit e interi arbitrariamente grandi. `True` e `False` non vengono trasformati, perché in Python `bool` è una sottoclasse di `int` ma possiede una semantica osservabile distinta.

Come per le stringhe, annotation e pattern di matching non vengono alterati.

### VM Obfuscation opzionale

Con `--vm-obfuscation`, gli alberi aritmetici considerati sicuri vengono convertiti in programmi postfix per una stack VM inserita nel sorgente trasformato. Ogni programma contiene opcode numerici casuali e indici di thunk; l’interprete VM cambia token e ordine dei branch a ogni build.

La VM supporta:

- somma, sottrazione, moltiplicazione e divisione;
- floor division, modulo e potenza;
- shift sinistro e destro;
- OR, XOR, AND e inversione bitwise;
- operatori unari positivo, negativo e `not`;
- operatore matrix multiplication `@`.

Gli operandi vengono forniti come thunk senza argomenti e caricati dalla VM nell’ordine originale, limitando le differenze osservabili nella valutazione. La pass virtualizza soltanto alberi composti da nomi, costanti e operatori supportati. Call, attribute access, subscript, class body e costrutti con semantica dinamica non vengono forzati dentro la VM.

Non è una reimplementazione completa dell’interprete Python: è una virtualizzazione conservativa delle espressioni. Questa scelta mantiene compatibilità e permette al manifest di riportare espressioni, istruzioni e operatori realmente virtualizzati.

### 5. Normalizzazione AST

Dopo le trasformazioni, l’albero viene corretto con `ast.fix_missing_locations()`, rigenerato con `ast.unparse()` e compilato nuovamente.

Questa fase elimina commenti e formattazione originale nei profili che effettuano trasformazioni AST. Le docstring vengono invece conservate perché possono essere osservate dal programma.

### 6. Compressione Zlib

Il sorgente trasformato viene codificato UTF-8 e compresso con `zlib` al livello 9. La compressione:

- riduce la ridondanza prima della cifratura;
- nasconde ulteriormente pattern testuali semplici;
- limita l’aumento di dimensione causato dalle trasformazioni AST.

Zlib non è una protezione crittografica.

### 7. Digest SHA-256 del payload compresso

Prima della cifratura viene calcolato SHA-256 del blob compresso. Dopo aver decifrato tutti i round, il loader ricalcola il digest e lo confronta in constant-time.

Il digest è un controllo finale di consistenza. L’autenticazione primaria avviene comunque nel tag associato a ogni round BlazingOpossum.

### 8. Round BlazingOpossum MARX-P/CTR

Ogni round usa:

- chiave da 256 bit;
- IV da 128 bit;
- stato a parole da 32 bit;
- key expansion da 22 round key;
- 20 iterazioni MARX-P basate su multiply, add, rotate, XOR e lane permutation;
- generazione keystream in stile CTR;
- cifratura simmetrica tramite XOR tra payload e keystream.

L’output di un round diventa l’input del successivo. In decodifica i round vengono attraversati in ordine inverso.

Il prototipo C# originale inizializza il tag leggendo un vettore da 32 byte partendo da un IV di 16 byte. Il port Python elimina questo accesso fuori limite e definisce lo stato iniziale come `IV || IV`. Per questo il formato prodotto da Ekitten Final è internamente stabile, ma non è byte-compatible con output C# dipendente da memoria non definita.

### 9. Tag di integrità per ogni round

Il ciphertext di ogni round riceve un tag da 128 bit derivato dallo stato MARX-P, dalla chiave e dall’IV. Il loader:

1. separa ciphertext e tag;
2. ricalcola il tag;
3. usa `hmac.compare_digest()` per il confronto constant-time;
4. decifra soltanto se il controllo è valido.

Una modifica accidentale o intenzionale al payload causa l’arresto con `Ekitten integrity check failed`.

### 10. Key splitting mascherato

Ogni chiave viene combinata con una mask casuale e salvata come due componenti:

```text
masked_key = key XOR mask
key        = masked_key XOR mask
```

Questo evita una singola costante contenente la chiave in chiaro. Non crea segretezza assoluta: entrambe le componenti sono necessariamente disponibili al loader.

Se non viene fornito `--seed`, chiavi, IV e mask derivano da `secrets.token_bytes()`. Con `--seed` sono invece deterministici per consentire build byte-identiche; un seed noto rende prevedibile anche il materiale generato e va quindi usato per riproducibilità, non come segreto.

### 11. Frammentazione e permutazione Base85

Il ciphertext finale viene diviso in frammenti di dimensione variabile. Ogni frammento è codificato Base85 e inserito nel loader in ordine casuale insieme al proprio indice.

Il loader ordina gli indici, decodifica i frammenti e ricompone il blob originale. Base85 è un encoding, non una cifratura.

### 12. Chunk esca

I profili `balanced` e `maximum` inseriscono rispettivamente due e cinque frammenti casuali con indice negativo. Il loader li ignora durante la ricostruzione.

I decoy aumentano il rumore statico senza introdurre side effect o dead code eseguito.

### 13. Polimorfismo del loader

Funzioni, alias degli import e variabili del bootstrap ricevono identificatori casuali validi. Due build senza seed producono strutture e payload differenti; due build con stesso input, stessa versione, stesso profilo e stesso seed producono byte identici.

### 14. Bootstrap isolato, guard runtime ed esecuzione senza `exec`

Il loader esegue tutta la ricostruzione dentro una funzione. Poco prima di eseguire il programma originale rimuove il nome della funzione bootstrap dai global.

In modalità portabile il loader verifica che `builtins.compile` e `zlib.decompress` siano ancora funzioni native provenienti dai moduli attesi. Un monkey-patch Python ordinario interrompe il bootstrap prima che venga consegnato il payload in chiaro alla funzione modificata.

Il loader non usa `exec()`. Dopo aver ottenuto il code object, crea direttamente una funzione con `type(lambda: None)` e la invoca nello stesso namespace del modulo, preservando valori come `__name__`, `__package__` e `__spec__` forniti dall’interprete.

Questa strategia elimina il punto di hook Python più ovvio su `exec`, ma non può impedire tracing a livello C, interpreti modificati o instrumentation del sistema operativo.

### 15. Modalità `--runtime-hardening` e riduzione della finestra in memoria

Per impostazione predefinita Ekitten conserva il sorgente trasformato nel payload, così l’output può essere eseguito su minor version Python differenti compatibili con la sintassi.

Con `--runtime-hardening` il sorgente viene invece compilato durante la build e il code object viene serializzato con `marshal` prima di compressione e cifratura. A runtime il loader:

1. verifica che la minor version Python coincida con quella della build;
2. verifica che `marshal.loads` e `zlib.decompress` non siano stati sostituiti a livello Python;
3. decifra il blob autenticato senza ricostruire il testo del sorgente;
4. deserializza direttamente il code object;
5. azzera best-effort i `bytearray` che contenevano chiavi, payload e dati serializzati;
6. esegue il code object tramite `FunctionType`, senza `compile()` e senza `exec()`.

I buffer immutabili interni creati da CPython, le costanti del code object e le copie effettuate dall’allocatore non possono essere azzerati in modo garantito da puro Python. La modalità riduce esposizione e persistenza del plaintext, ma non impedisce un dump eseguito con privilegi sufficienti.

### 16. Modalità `--code-object-hardening`

Questa modalità richiede `--runtime-hardening` ed è destinata a build dove protezione e riduzione dei metadata hanno priorità sull’introspezione. Durante la build:

- rimuove docstring di modulo, classi e funzioni;
- trasforma anche le porzioni letterali delle f-string;
- applica ricorsivamente la sanitizzazione a tutti i code object annidati;
- sostituisce `co_filename` con `<ekitten-protected>`;
- porta `co_firstlineno` a `1`;
- azzera la line table quando la versione CPython lo permette;
- mantiene stringhe e interi generici dietro i decoder polimorfici;
- elimina il riferimento separato al code object appena viene creato l’entry point e lo rilascia dopo l’esecuzione.

Esempio:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py" `
  -o ".\programma-code-hardened.py" `
  --profile maximum `
  --runtime-hardening `
  --code-object-hardening
```

Combinazione massima con VM e sigillo completo:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py" `
  -o ".\programma-vm-sealed.py" `
  --profile maximum `
  --runtime-hardening `
  --code-object-hardening `
  --vm-obfuscation `
  --anti-tamper
```

Non è una barriera assoluta: le istruzioni e le costanti indispensabili devono essere presenti quando CPython esegue una funzione. Un analista con controllo dell’interprete può ancora accedere a frame e `function.__code__`. Per impedirlo realmente occorre non distribuire la logica oppure spostarla in un runtime nativo isolato.

### Anti-tamper dell’intero artefatto

Con `--anti-tamper`, Ekitten aggiunge un sigillo SHA-256 canonico all’intero file generato. Durante la build il campo del sigillo viene temporaneamente normalizzato a zero, viene calcolato l’hash di tutti gli altri byte e il digest viene scritto nell’header.

Prima di ricostruire chiavi o payload, il bootstrap:

1. verifica che `open` sia ancora la funzione nativa attesa;
2. legge il proprio `__file__` in modalità binaria;
3. normalizza soltanto la riga del sigillo;
4. ricalcola SHA-256 dell’intero artefatto;
5. usa un confronto constant-time;
6. interrompe l’esecuzione se qualsiasi byte, newline, chunk, record, loader o commento è cambiato.

Questo sigillo si aggiunge ai tag BlazingOpossum per round e al digest del payload compresso. Richiede esecuzione da un file reale: esecuzione da stringa, database o loader virtuale senza `__file__` viene rifiutata.

Come ogni controllo self-contained, un reverse engineer può rimuovere sia verifica sia errore modificando il bootstrap. Il sigillo rileva modifiche e patch non coordinate, ma non costituisce una root of trust esterna. Una firma digitale con chiave privata conservata fuori dalla build sarebbe il passo successivo per autenticare l’origine.

## Riepilogo del flusso

```text
Sorgente Python
    ↓ parse + compile
AST conservativo
    ↓ stringhe / interi / locali / VM secondo configurazione
Sorgente trasformato
    ↓ portabile: bytes UTF-8
    ↓ hardened: compile build-time + marshal, vincolo Python X.Y
    ↓ code-object hardened: strip docstring + sanitize metadata
    ↓ zlib level 9 + SHA-256
Payload compresso
    ↓ BlazingOpossum round 1 + tag
    ↓ BlazingOpossum round 2 + tag
    ↓ ...
Ciphertext finale
    ↓ key splitting + Base85 + permutazione + decoy
Loader Python autonomo
    ↓ sigillo completo anti-tamper opzionale
    ↓ guard runtime + buffer wipe best-effort
Code object eseguito via FunctionType, senza exec
```

## Riferimento CLI

```text
usage: Ekitten Final.py [-h] [-o OUTPUT]
                        [--profile {compatible,balanced,maximum}]
                        [--layers LAYERS] [--seed SEED]
                        [--runtime-hardening]
                        [--code-object-hardening]
                        [--vm-obfuscation] [--anti-tamper]
                        [--manifest MANIFEST] [--verify]
                        [--verify-arg VALUE] [--timeout SECONDS]
                        [--self-test] [--version]
                        [input]
```

### Argomenti principali

- `input`: file Python da proteggere.
- `-o`, `--output`: percorso del file generato.
- `--profile`: livello di trasformazione AST e valori predefiniti della protezione.
- `--layers`: numero di round BlazingOpossum, da 1 a 12.
- `--seed`: rende la build riproducibile.
- `--runtime-hardening`: usa un code object serializzato, evita sorgente/`compile` a runtime e vincola l’output alla minor version della build.
- `--code-object-hardening`: richiede runtime hardening; rimuove docstring, offusca literal delle f-string e sanitizza ricorsivamente filename e line table. Modifica introspezione e traceback.
- `--vm-obfuscation`: converte espressioni aritmetiche conservative in bytecode per una stack VM polimorfica.
- `--anti-tamper`: sigilla tutto il file generato e lo verifica prima della decifratura; richiede esecuzione file-backed.
- `--manifest`: scrive metadata e hash della build in JSON.
- `--verify`: esegue originale e output e confronta exit code, stdout e stderr.
- `--verify-arg`: argomento da passare a entrambi i programmi durante la verifica; può essere ripetuto.
- `--timeout`: timeout per ognuno dei due processi di verifica.
- `--self-test`: verifica cipher, tamper detection e loader per tutti i profili.

Per passare un argomento che inizia con `-` usare la forma con `=`:

```powershell
py -3.13 ".\Ekitten Final.py" ".\programma.py" `
  --verify `
  --verify-arg=--version
```

## Verifica differenziale

`--verify` avvia due subprocess separati con lo stesso interprete, working directory, argomenti e `PYTHONHASHSEED=0`. La verifica passa soltanto se coincidono:

- codice di uscita;
- stdout in byte;
- stderr in byte.

La verifica esegue realmente entrambi i file. Va usata esclusivamente con sorgenti fidati e può non essere adatta a programmi che modificano file, accedono alla rete, aspettano input o producono output non deterministico.

## Suite di compatibilità inclusa

Il repository contiene [test.py](./test.py), uno script auto-validante creato per essere protetto da Ekitten Final. Il test copre:

- docstring, annotation e Unicode;
- stringhe vuote, quote, slash, newline, null byte testuale e stringhe lunghe;
- interi zero/negativi, slice, shift, booleani e valori arbitrariamente grandi;
- argomenti positional-only, keyword-only, `*args` e `**kwargs`;
- decorator, closure e `nonlocal`;
- dataclass, enum, inheritance, `super()`, descriptor, property e name mangling;
- generatori, context manager e `try/finally`;
- coroutine, async generator e async context manager;
- structural pattern matching;
- comprehension, lambda e assignment expression;
- exception chaining;
- `eval`, `exec`, `locals` e `globals` in uno scope controllato;
- pickle, JSON, regex, hashing e introspezione delle annotation.
- operatori binari/unari supportati dalla VM, incluso `@` con overload controllato.

Eseguire l’originale:

```powershell
py -3.13 ".\test.py"
```

Offuscare e confrontare automaticamente:

```powershell
py -3.13 ".\Ekitten Final.py" ".\test.py" `
  -o ".\test-ekitten.py" `
  --profile maximum `
  --verify
```

Provare tutti i profili:

```powershell
py -3.13 ".\Ekitten Final.py" ".\test.py" -o ".\test-compatible.py" --profile compatible --verify
py -3.13 ".\Ekitten Final.py" ".\test.py" -o ".\test-balanced.py"   --profile balanced   --verify
py -3.13 ".\Ekitten Final.py" ".\test.py" -o ".\test-maximum.py"    --profile maximum    --verify
```

Provare la modalità code-object hardened escludendo soltanto il controllo delle docstring, che vengono rimosse intenzionalmente:

```powershell
py -3.13 ".\Ekitten Final.py" ".\test.py" `
  -o ".\test-code-hardened.py" `
  --profile maximum `
  --runtime-hardening `
  --code-object-hardening `
  --verify `
  --verify-arg=--allow-stripped-docstrings
```

I file `test-*.py` sono artefatti generati e possono essere eliminati dopo il test.

## Self-test dell’obfuscator

```powershell
py -3.13 ".\Ekitten Final.py" --self-test
```

Il self-test controlla:

- round-trip BlazingOpossum su payload di varie dimensioni;
- rifiuto di un ciphertext alterato;
- round-trip di tutte le sei strategie dell’`IntObfuscator`, inclusi valori negativi e interi da oltre 64 bit;
- round-trip di tutte le sei strategie dello `StringObfuscator` su ASCII, Unicode, null e stringhe lunghe;
- generazione ed esecuzione dei profili `compatible`, `balanced` e `maximum`.
- generazione ed esecuzione di un payload `maximum --runtime-hardening`.
- generazione ed esecuzione della modalità code-object hardened con docstring rimosse e metadata sanitizzati.
- esecuzione di espressioni virtualizzate e presenza del relativo report nel manifest;
- esecuzione di un artefatto sigillato e rifiuto dello stesso file dopo una modifica;
- rifiuto dei monkey-patch Python su `compile`, `zlib.decompress`, `marshal.loads` e `open`;
- conferma che il bootstrap hardened non invochi un `exec` monkey-patched.

## Compatibilità e limitazioni note

- `compatible` mantiene il testo originale dentro il payload portabile; frame e `inspect` possono comunque rendere osservabile il code object in esecuzione.
- `balanced` e `maximum` rigenerano il sorgente con `ast.unparse()`: commenti, whitespace, quote e numeri di riga possono cambiare.
- `inspect.getsource()`, coverage basata sulle righe originali e strumenti che richiedono il file sorgente in chiaro non sono pienamente preservabili.
- La rinomina non tenta di coprire ogni nome. Saltare uno scope ambiguo è una scelta deliberata di compatibilità.
- Il loader portabile usa `compile()` dopo averne verificato l’identità, ma non usa `exec()`.
- Il loader hardened non usa né `compile()` né `exec()` a runtime, ma `marshal` lo vincola esattamente alla minor version CPython della build.
- `--code-object-hardening` imposta `__doc__` a `None`, riduce le informazioni dei traceback e non è semanticamente trasparente per programmi che osservano questi metadata.
- La VM copre espressioni aritmetiche sicure, non ogni istruzione Python; aumenta dimensione e overhead runtime.
- Il sigillo anti-tamper considera anche newline e commenti: formatter, editor o sistemi che riscrivono il file ne causano correttamente il rifiuto.
- Moduli C, dipendenze esterne e file importati non vengono inclusi automaticamente.
- Codice che legge o modifica il proprio file vedrà il loader, non il sorgente originale.
- Programmi non deterministici possono fallire `--verify` anche se semanticamente corretti.
- Aumentare indiscriminatamente i round non equivale a una prova crittografica più forte.

## Modello di sicurezza

Ekitten Final è adatto a rendere più costose:

- lettura casuale del sorgente distribuito;
- ricerca statica di stringhe e costanti;
- estrazione diretta tramite semplici decoder Base64/Zlib;
- modifica non rilevata del payload;
- confronto superficiale tra build polimorfiche.
- monkey-patch Python ordinario di `compile`, `zlib.decompress` e `marshal.loads`;
- hook diretto su `exec`, che non viene usato dal bootstrap;
- recupero immediato del sorgente nella modalità hardened, dove il testo non viene ricostruito a runtime.
- dump immediatamente leggibili di docstring, filename, line table e literal di f-string nella modalità code-object hardened.
- patch non coordinate del loader o del payload quando il sigillo completo è attivo;
- riconoscimento statico immediato delle espressioni virtualizzate grazie agli opcode polimorfici.

Non garantisce protezione assoluta contro:

- debugger e tracer autorizzati;
- hooking nativo, tracing a livello C o sostituzione dell’interprete;
- dump del code object, delle istruzioni e delle costanti indispensabili dopo la decifratura;
- dump della memoria eseguito con privilegi sufficienti;
- interpreti modificati;
- analisi dinamica su una macchina controllata dall’avversario.
- rimozione deliberata del controllo anti-tamper da parte di chi può riscrivere ed eseguire il loader;

Segreti reali, credenziali e algoritmi che non devono essere mai recuperati non dovrebbero essere distribuiti nel client. La protezione più forte resta mantenerli su un servizio remoto fidato.

## Nota su BlazingOpossum

BlazingOpossum è un progetto sperimentale e non risulta sottoposto ad audit crittografico indipendente. Le descrizioni come “post-quantum” presenti nel prototipo non costituiscono una garanzia verificata.

Ekitten Final lo usa perché richiesto come fondamento specifico del layer di payload, correggendo l’accesso fuori limite del tag e usando confronti constant-time. Per dati che richiedono sicurezza crittografica reale è preferibile una costruzione standardizzata e mantenuta da una libreria crittografica riconosciuta.
