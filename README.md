Documentazione di FirmaJR!    [![Documentation Status](https://readthedocs.org/projects/firmajr/badge/?version=latest)][1]
====================================


FirmaJR è un'applicazione che permette di firmare digitalmente documenti.

Il software è scritto in Python 3 con lo scopo di sostituire il precedente scritto in Java. JR sta per Java Removed.
La scelta di svilupparla in python è dovuta soprattutto alla flessibilità del linguaggio, che permette di rendere il software indipendente
dal browser e compatibile con tutti i sistemi.

Caratteristiche
===============
* Firma di documenti PDF, visibile e invisibile
* Firma di documenti in P7M, parallelo e innestate

Installazione
=============
Per installare l'applicazione su sistemi Windows bisogna eseguire il setup il quale installerà le librerie necessarie per l'esecuzione su Windows ovvero
[Microsoft Visual C++ 2015 Redistributable Update 3][9] le quali permettono
al software di auto aggiornarsi nel caso vengano rilasciati nuovi aggiornamenti.
L'applicazione viene installata nella home dell'utente corrente (Current User) nella cartella **AppData/Roaming**, quindi un utente generico può
installarla. Durante il processo di installazione viene fatto un controllo per verificare la presenza delle Redistributable, se non sono presenti
viene chiesto di installarle ed in tal caso c'è bisogno che l'utente abbia i permessi di amministratore oppure fornirne le credenziali,
se invece sono già installate l'installazione si conclude normalmente.

L'installer crea un protocollo, un'associazione di un URL con un eseguibile che viene lanciato quando questo viene chiamato.
La creazione del protocollo avviene attraverso l'inserimento di una chiave nel registro di sistema per l'utente corrente.
Un esempio di chiamata dell'URL è il seguente:
`firmajr://<parametri>`

Utilizzo
========
Allo stato attuale FirmaJR agisce soltanto quando viene effettuata una richiesta da un'applicazione web,
è previsto in futuro l'utilizzo come client standalone con una propria GUI.

Per i dettagli di utilizzo visitare la sezione apposita. <inserire link>

Contenuti
=========

Per iniziare
------------

Per lo sviluppo dell'applicazioni sono state utilizzate diverse librerie, per la crittografia e manipolazione dei pdf in particolare. Per ricreare
l'ambiente di sviluppo è necessario che siano soddisfatti i seguenti prerequisiti:

1. Python 3
2. Tutte le librerie richieste, controllare il file `requirements.txt` per la lista completa [1][1]
3. Un editor di testo eg. PyCharm, VSCode

Per compilare l'eseguibile **DigitalSignature.exe** lanciare da cmd o powershell il seguente comando nella home del progetto:

.. code-block:: shell

   pyupdater build --app-version=0.0.4 --onefile --windowed --i="D:\Progetti New\Firma 2.0\firma2\Sorgenti\digital_signature\FirmaJR.ico" .\digiSign_server.py

tenendo coerente l'*app-version* con la versione dell'applicazione il cui parametro si trova nel file **__init__.py**


[1]: Per alcune librerie, come PyKCS11 ad esempio, è necessario che siano rispettati dei prerequisiti, quali l'installazione di "swig" e
  la Visual Studio 2010 SDK. Il link al repository per ulteriori informazioni: [PyKCS11][2]

[2]: https://github.com/LudovicRousseau/PyKCS11


Licenza
=======
This software is licensed under the GPLv3 License. See the LICENSE file in the top distribution directory for the full license text.

Requisiti
=========
* Python 3.*
* [cryptography][2]
* [asn1crypto][3]
* [pyfpdf][4]
* [pdfminer.six][5]
* [pykcs11][6]
* [PyUpdater][7]

Credits
=======
* [endesive][8] by [Grzegorz Makarewicz](https://github.com/m32)

[1]: https://firmajr.readthedocs.io/en/latest/?badge=latest
[2]: https://github.com/pyca/cryptography
[3]: https://github.com/wbond/asn1crypto
[4]: https://github.com/reingart/pyfpdf
[5]: https://pypi.org/project/pdfminer.six/
[6]: https://pypi.org/project/pykcs11/
[7]: https://github.com/Digital-Sapphire/PyUpdater
[8]: https://github.com/m32/endesive
[9]: https://www.microsoft.com/it-IT/download/details.aspx?id=53840

