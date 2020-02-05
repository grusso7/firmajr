Per iniziare a sviluppare
=========================

Per lo sviluppo dell'applicazioni sono state utilizzate le librerie:
* Lib1 ->
* lib2
* lib3
* 1

per la crittografia e manipolazione dei pdf in particolare.

Per ricreare l'ambiente di sviluppo è necessario che siano soddisfatti i seguenti prerequisiti:

1. Python 3
2. Tutte le librerie richieste, controllare il file `requirements.txt` per la lista completa [#f1]_
3. Un editor di testo eg. PyCharm, VSCode

Per compilare l'eseguibile **DigitalSignature.exe** lanciare da cmd o powershell il seguente comando nella home del progetto:

.. code-block:: shell

   pyupdater build --app-version=0.0.4 --onefile --windowed --i="D:\Progetti New\Firma 2.0\firma2\Sorgenti\digital_signature\FirmaJR.ico" .\digiSign_server.py

tenendo coerente l'*app-version* con la versione dell'applicazione il cui parametro si trova nel file **__init__.py**


.. [#f1] Per alcune librerie, come PyKCS11 ad esempio, è necessario che siano rispettati dei prerequisiti, quali l'installazione di "swig" e
  la Visual Studio 2010 SDK. Il link al repository per ulteriori informazioni: `PyKCS11`_

.. _PyKCS11: https://github.com/LudovicRousseau/PyKCS11