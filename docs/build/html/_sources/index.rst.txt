Documentazione di FirmaJR!
==========================================

FirmaJR è un'applicazione che permette di firmare digitalmente documenti di tipo:
* PDF in modalità visibile e invisibile;
* P7M in modalità parallelo e innestate.

Il software è scritto in Python 3 con lo scopo di sostituire il precedente scritto in Java. JR sta per Java Removed.
La scelta di svilupparla in python è dovuta soprattutto alla flessibilità del linguaggio, che permette di rendere il software indipendente
dal browser e compatibile con tutti i sistemi.

Installazione del client per l'utente finale
============================================
Per installare l'applicazione su sistemi Windows bisogna eseguire il setup.
La procedura installerà `Microsoft Visual C++ 2015 Redistributable Update 3`_ per l'esecuzione su Windows,
che permette al software di auto aggiornarsi nel caso vengano rilasciati nuovi aggiornamenti.
L'applicazione viene installata nella home dell'utente corrente (Current User) nella cartella **AppData/Roaming**, quindi un utente generico può
installarla. Durante il processo di installazione viene fatto un controllo per verificare la presenza delle Redistributable, se non sono presenti
viene chiesto di installarle ed in tal caso c'è bisogno che l'utente abbia i permessi di amministratore oppure fornirne le credenziali,
se invece sono già installate l'installazione si conclude normalmente.

L'installer crea un protocollo, un'associazione di un URL con un eseguibile che viene lanciato quando questo viene chiamato.
La creazione del protocollo avviene attraverso l'inserimento di una chiave nel registro di sistema per l'utente corrente.
Un esempio di chiamata dell'URL è il seguente:
`firmajr://<parametri>`

.. toctree::
   :maxdepth: 3
   :caption: Contenuti:

   getting_started
   flusso
   digital_signature

Licenza
=======
This software is licensed under the GPLv3 License. See the LICENSE file in the top distribution directory for the full license text.

Requisiti
=========
* Python 3.*
* `cryptography`_
* `asn1crypto`_
* `pdfminer.six`_
* `pykcs11`_
* `PyUpdater`_

Credits
=======
* `endesive`_ by `Grzegorz Makarewicz <https://github.com/m32>`_

Indici
======

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _cryptography: https://github.com/pyca/cryptography
.. _asn1crypto: https://github.com/wbond/asn1crypto
.. _pyfpdf: https://github.com/reingart/pyfpdf
.. _pdfminer.six: https://pypi.org/project/pdfminer.six/
.. _pykcs11: https://pypi.org/project/pykcs11/
.. _PyUpdater: https://github.com/Digital-Sapphire/PyUpdater
.. _endesive: https://github.com/m32/endesive
.. _Microsoft Visual C++ 2015 Redistributable Update 3: https://www.microsoft.com/it-IT/download/details.aspx?id=53840