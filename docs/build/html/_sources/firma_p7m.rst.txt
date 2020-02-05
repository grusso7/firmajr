Firma P7M
=========
La gestione della firma in p7m avviene nel metodo **sign_p7m(*args*)** che si trova nel file *digiSign_lib.py* dei sorgenti.

Viene letto in bytes il file passato come parametro e la prima operazione che viene eseguita è verificare se il file è stato già firmato attraverso
il controllo del mimetype.
Se è un file già firmato, i bytes del file vengono letti attraverso una classe della libreria **asn1crypto** che restituisce un oggetto dal quale
vengono estratte le informazioni della firma o firme precedenti, come l'algoritmo crittografico utilizzato e i certificati.

I bytes del file da firmare viene quindi cifrato con l'algoritmo specificato nella smartcard, dalla quale vengono anche caricati il certificato e il
valore del certificato il quale viene anch'esso cifrato.
Viene fatto controllo dell'identità dell'utente con quella specificata nel certificato, opzionale in fase di test, e vengono quindi creati i
**signed_attributes** e i **bytes da firmare**.
I signed_attributes sono l'hash del file, del certificato e il l'ora di firma creati attraverso una specifica struttura crittografica
innestata a livelli ed identificatori nei metodi **encode_signed_attributes(*args*)** e **_get_signed_attributes(*args*)** della classe
**P7MEncoder**, i bytes da firmare sono essenzialmente uguali ai signed attributes ma hanno un identificatore iniziale differente.

Viene estratta la chiave privata dalla smartcard e i bytes vengono firmati con il Mechanism CKM_SHA256_RSA_PKCS nel metodo **signature(*args*)**
nella classe *SignatureUtils()*.

I bytes firmati vengono passati al metodo **encode_signer_info(*args*)**, insieme al Certificate Authority, il serial number (entrambi estratti
dalla smartcard), i signed_attributes ed eventuali firme precedenti per creare i **signer_info**, un oggetto crittografico strutturato con le
informazioni di firma.

Viene infine costruito il P7M, anch'esso in una specifica struttura crittografica, e la funzione restituisce il path del file firmato.