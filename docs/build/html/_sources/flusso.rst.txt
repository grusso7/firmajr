Flusso di esecuzione
====================
In questa sezione sono presenti tutti i passaggi che fanno parte del processo di firma, dalla richiesta che parte da una web application alla
effettiva procedura di firma, differenziando i casi di firma P7M e PDF.
Analizzeremo soprattutto come viene utilizzata nella suite Babel dove tutta la gestione del processo di firma viene fatta nella videata
**Firma Digitale Due** che si trova in *Funzioni Pubbliche* nel progetto *Components*.

Avvio firma lato web application
--------------------------------
Per far partire la procedura di firma l'applicazione web dal quale viene effettuata la richiesta deve svolgere dei passaggi preliminari.
In questa fase viene creato il json <signConfiguration> che contiene tutti i parametri e la lista dei file da firmare.
In Babel il metodo si chiama **generateFirmaDueJSON** e si trova nella classe **SignFiles**.
La struttura è la seguente:

.. code-block:: JSON

  {
    "user_id": "codice_fiscale",
    "masterDocumentId": "masterDocumentId",
    "file_list": [
    {
    "file": "file_path",
    "file_id": "id",
    "file_mime_type": "file_mime_type",
    "file_name": "file_name",
    "file_type": "file_type (Es. DocumentoPicoNuovoPU)",
    "file_data": "{file additional data (only a bag)}",
    "signed_file_type": "p7m|pdf",
    "destination": "destination_path",
    "sig_attributes": {
      "visibility": "visibility",
      "position": {
        "page": "n",
        "width": "200.0",
        "height": "60.0",
        "padding_width": "75.0",
        "padding_height": "670.0",
        "signature_name": "Signature"
      },
      "p7m_sig_type": "p7m_sig_type",
      "text_template": "",
      }
    }],
    "test_mode": "true|false",
    "update_checker_url": "[optional]",
    "revocation_checker_url": "[optional]",
    "uploader": "http://localhost:8095/",
    "params": {
      "azienda": "codice_azienda",
      "serverIdentifier": "serverIdentifier",
      "resultChannel": "resultChannel",
      "endSignManagerUrl": "servlet di fine firma"
    }
  }

Il json viene salvato sul server redis dell'ambiente (Bologna ad esempio) ed associato ad una chiave che chiamamo token. Questa è una delle possibili
soluzioni, come da premessa questo è il metodo usato in Babel, è possibile personalizzare questa soluzione in altri modi.
Dopo questi passaggi viene chiamato un URL con una funzione javascript e l'applicazione web resta in attesa finché non viene conclusa l'operazione di
firma oppure scade il timeout.

.. code-block:: javascript

  function downloadAndNotify(url,name,command,token,close=false) {
    if (close) {
      window.location.href = url;
    } else {
        myWindow = window.open(url,name);
        myWindow.focus();
    }
    var cmd = command + '&params='+token;
    var e = new IDEvent("cmd", "", null, RD3_Glb.EVENT_ACTIVE, cmd);
  }

L'URL chiamato è un protocollo che è stato inserito durante l'installazione di FirmaJR ed ha la seguente struttura:

.. code-block:: none

  firmajr://<token>;<url_redis_server>

Il <token> è la chiave per identificare e recuperare sul server di redis il json, mentre <url_redis_server> è l'url codificato in base64 del server.

L'apertura di questo URL lancierà applicazione FirmaJR sul PC dell'utente, con alcune differenze se viene aperto da Chrome o Firefox. Su Chrome
viene visualizzato un popoup con la richiesta di confermare o annullare l'apertura dell'applicazione mentre su Firefox viene mostrata una finestra
la quale anch'essa chiede di confermare l'apertura dell'applicazione però con la possibilità di salvare la scelta così che nelle successive richieste
viene eseguita direttamente.

Operazioni preliminari
-----------------------
L'applicazione è in esecuzione, viene letto l'URL aperto dal browser e viene passato al metodo **handle_sign(start_params)** che gestisce le fasi
principali del processo di esecuzione di FirmaJR.
Prima della firma dei file vengono effettuate delle operazioni preliminari:

1. Parsing dell'URL e recupero json con i parametri per la firma
2. Controllo degli aggiornamenti
3. Controllo del certificato


Parsing URL e recupero parametri
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Nella prima fase sono previsti due casi:

1. Nel primo caso viene fatto il parsing dell'URL recuperando i due parametri attesi ovvero il token per identificare univocamente
   il json dei parametri e l'url del server di redis dove viene fatta una chiamata HTTP passando come parametro il token.
   La risposta della chiamata sarà il json dei parametri visto precedentemente.

2. Nel secondo caso invece si presenta quando l'applicazione si avvia in seguito ad un aggiornamento. I parametri non saranno presenti
   più nell'URL ma sono stati salvati sul file system, vedremo la procedura in seguito, quindi vengono recuperati nel metodo **get_sign_resume()**.


Controllo degli aggiornamenti
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Nella seconda fase c'è il controllo degli aggiornamenti [#f1]_ in FirmaJR viene fatto ogni volta che viene eseguita un'operazione di firma chiamando la funzione
**updates_manager(*parameter_to_save, update_checker_url*)**.

Url del server di aggiornamento è personalizzabile, infatti nel json scaricato nella fase 1 nei i parametri è presente il campo
*update_checker_url* che può essere diverso da quello preconfigurato.

L'Url è passato al metodo **updates_manager(*parameter_to_save, update_checker_url*)** insieme all'URL completo aperto dal browser
(*firmajr://<token>;<url>*).
Il metodo gestisce tutta la procedura; effettua il controllo della presenza di nuovi aggiornamenti, se presenti salva i parametri necessari
al recupero dell'operazione di firma in quanto per aggiornarsi è necessario che l'applicazione venga riavviata, infine avvia l'aggiornamento.

* Il controllo degli aggiornamenti viene effettuato dal metodo **check_for_updates(*update_checker_url*)** al quale viene passato
  l'url del server dove fare il controllo. Tale parametro come abbiamo visto è opzionale, se non viene passato viene utilizzato il default presente
  nel file di configurazione client_config.

* Se viene trovato un nuovo aggiornamento, l'URL di apertura dell'applicazione completo (*firmajr://<token>;<url_encoded>*) viene salvato sul
  file system nel file *sign_status.dat* nella directory *uploads* della home di FirmaJR. Viene salvato in questa cartella per comodità in quanto
  viene svuotata alla fine di ogni firma.
  Infine il metodo **run_updates(app_update)** effettua il download e l'estrazione dell'aggiornamento e riavvia l'applicazione.

* Dopo il riavvio vengono eseguiti gli stessi passi, se non vengono trovati nuovi aggiornamenti l'esecuzione prosegue allo step successivo.

.. code-block:: python

   def updates_manager(parameter_to_save, update_checker_url):
      """Gestione degli aggiornamenti. Effettua il controllo di nuovi aggiornamenti ed in tal caso salva i parametri della firma e
      avvia l'aggiornamento dell'applicazione.

      :param parameter_to_save: I parameteri da salvare. È l'URL completo con il quale viene lanciata l'applicazione.
      :type parameter_to_save: str
      :param update_checker_url: L'url del server dove sono presenti le nuove versioni dell'applicazione
      :type update_checker_url: str
      :return: Lo status dell'aggiornamento
      :rtype: UpdateStatus
      """
      log.info("Checking for client updates.. " + update_checker_url)
      app_update = check_for_updates(update_checker_url)
      if app_update:
          log.info("new update found!")
          save_sign_status(parameter_to_save)
          log.info("sign status saved. Start updating...")
          return run_updates(app_update)
      else:
          return UPDATE_STATUS_STR[UpdateStatus.NO_AVAILABLE_UPDATES]

   def check_for_updates(update_checker_url=None):
    """Controllo nuovi aggiornamenti.

    :param update_checker_url: Url server degli aggiornamenti, defaults to None
    :type update_checker_url: str, optional
    :return: UpdateObject utilizzato per aggiornare i binari
    :rtype: AppUpdate
    """
    assert CLIENT_CONFIG.PUBLIC_KEY is not None

    # Se update_checker_url è presente nel json, allora il controllo degli aggiornamenti viene
    # fatto su quell'URL altrimenti prendo il default dal file di configurazione
    if update_checker_url is not None:
        CLIENT_CONFIG.UPDATE_URLS[0] = update_checker_url + "deploy/"
    client = Client(CLIENT_CONFIG, refresh=True, progress_hooks=[progress])
    log.info("Actual client version: %s" % digital_signature.__version__)
    appUpdate = client.update_check(CLIENT_CONFIG.APP_NAME,
                                    digital_signature.__version__,
                                    channel='stable')
    return appUpdate

   def save_sign_status(params):
    """Salva i parametri sul file system

    :param params: Parametri iniziali passati all'avvio dell'applicazione nell'URL
    :type params: str
    """
    log.info("saving signature status...")
    try:
        with open(path.join(UPLOAD_FOLDER, 'sign_status.dat'), 'w') as f:
            f.write(params)
    except Exception as ex:
        log.error("error: %s" % ex)
        return error_response(SignStatus.ERROR.value, "Errore durante il salvataggio dei parametri per l'aggiornamento")

   def run_updates(app_update):
    """Lancia il download dell'aggiornamento e al completamento estrae il file dal zip e riavvia l'applicazione

    :param app_update: UpdateObject utilizzato per aggiornare i binari
    :type app_update: AppUpdate
    :return: Lo stato dell'aggiornamento
    :rtype: UpdateStatus
    """
    log.info('Extracting update and restart...')
    if hasattr(sys, "frozen"):
        downloaded = app_update.download()
        if downloaded:
            status = UpdateStatus.EXTRACTING_UPDATE_AND_RESTARTING
            log.info('Extracting update and restart...')
            time.sleep(1)
            app_update.extract_restart()
        else:
            status = UpdateStatus.UPDATE_DOWNLOAD_FAILED
    else:
        status = UpdateStatus.UPDATE_AVAILABLE_BUT_APP_NOT_FROZEN
    return UPDATE_STATUS_STR[status]

.. [#f1] Il progetto è configurato attraverso lo script della libreria PyUpdater, il quale genera un file di configurazione *client_config.py*. In questo file vengono
  salvati i parametri necessari a gestire l'operazione, come la public key che serve a decriptare il file zip che contiene l'aggiornamento, il nome
  dell'applicazione e l'url del server degli aggiornamenti.

Controllo del certificato
^^^^^^^^^^^^^^^^^^^^^^^^^
Nella terza fase del ciclo di esecuzione inizia la preparazione per la firma dei file gestito nel metodo **sign(json_parsed)**.
Vengono effettuati una serie di controlli per la presenza dei parametri nel json che contiene le informazioni necessarie alla firma e i file da firmare.
Anche in questa fase ci sono alcuni step fondamentali che analizziamo.

1. Reperimento di alcuni parametri dal json della richiesta per salvarli in variabili;
2. Aprire la sessione con la smartcard, fatto nel metodo **fetch_smart_card_sessions()** nel file *signature_util.py*.
   In questa funzione vengono caricati i driver di bit4id presenti nella cartella *..\AppData\Roaming\FirmaJR\drivers* e viene
   stabilita la comunicazione con la smartcard. Viene poi richiesto il pin nel metodo **get_pin(user_id)** dove user_id è il codice fiscale
   dell'utente preso dai parametri del json della richiesta.
   Il pin viene memorizzato nella variabile *user_session* e utilizzato per effettuare il login alla sessione della smartcard.
   Se il pin non è corretto il login fallisce e viene mostrato all'utente il messaggio di pin errato. È possibile riprovare o annullare.
   Se il pin viene sbagliato 3 volte la smartcard si blocca.

   .. code-block:: python

      try:
        sessions = DigiSignLib().get_smart_cards_sessions()
      except Exception as err:
        _, value, tb = sys.exc_info()
        log.error(value)
        log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
        clear_session(user_id)
        return error_response(SignStatus.ERROR.value, "Controllare che la smart card sia inserita correttamente")

      # attempt to login
      while True:
        try:
          get_pin(user_id)
          if user_session[user_id]["pin"] == "":
            raise ValueError("pin not valid")
          session = DigiSignLib().session_login(sessions, user_session[user_id]["pin"])
          break
        except Exception as err:
          _, value, tb = sys.exc_info()
          log.error(value)
          log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
          clear_session(user_id)
          if str(err) == 'aborted':
            return error_response(SignStatus.ABORTED.value, "Operazione annullata")
          show_warning_message("Controllare che il pin sia valido e corretto")

      # fetching certificate value
      try:
        certificate = DigiSignLib().get_certificate(session)
        certificate_value = DigiSignLib().get_certificate_value(session, certificate)
      except Exception as err:
        _, value, tb = sys.exc_info()
        log.error(value)
        log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
        clear_session(user_id)
        return error_response(SignStatus.ERROR.value, "Impossibile ottenere il certificato di firma")

3. Effettuato correttamente il login, viene preso dalla smartcard il certificato e salvato in una variabile attraverso il metodo
   **get_certificate_value(session, certificate)** presente nella classe DigiSignLib nel file *digiSign_lib.py*.

   .. code-block:: python

      @staticmethod
      def get_certificate_value(session, certificate):
      """
      Return the value of `certificate`
      Params:
          session: smart card session
          certificate: smart card certificate
      """
      log.info("fetching certificate value")
      try:
        certificate_value = session.getAttributeValue(certificate, [LowLevel.CKA_VALUE])[0]
      except:
          raise SmartCardConnectionError("Certificate has no valid value")

      return bytes(certificate_value)

4. Caricato il certificato, viene fatto il controllo dello stato di revoca e validità. La procedura è gestita dal metodo
   **get_certificate_status(revocation_checker_url, user_id, certificate_value, params)** che effettua una chiamata al *revocation checker server*
   utilizzando l'url preso dai parametri.

   .. code-block:: python

      def get_certificate_status(revocation_checker_url, user_id, certificate_value, params):
      """Controllo la validità e lo stato di revoca del certificato e salva il risultato nella sessione dell'utente

      :param revocation_checker_url: Url del revocation checker server che effettua il controllo
      :type revocation_checker_url: str
      :param user_id: Il codice fiscale dell'utente
      :type user_id: str
      :param certificate_value: Il certificato da controllare
      :type certificate_value: bytes
      :param params: Parametri personalizzabili, ed esempio nel sistema babel contengono il codice azienda
      :type params: str
      :return: Il json con il risultato del controllo contenente: status, behaviours, timestamp, check codice fiscale
      :rtype: json
      """
      check_resp = RevocationChecker().check(revocation_checker_url, certificate_value, params)
      cert_status = check_resp["status"]
      if cert_status == ERROR:
          # set cert_status to UNKNOWN to continue execution
          # log already done by RevocationChecker
          cert_status = UNKNOWN
      user_session[user_id]["status"] = cert_status

      status = user_session[user_id]["status"]
      log.info(f"Certificate status: {status}")
      return check_resp

   La risposta del server ha la seguente struttura:

   .. code-block:: python

      {
        "status": "status",         # Stato di validità del certificato, scaduto, valido o invalido
        "behaviours": "behaviours", # Contiene l'informazione di come l'applicazione deve comportarsi nei casi in cui il certificato non è regolare
        "timestamp": "timestamp",   # Data e ora della firma
        "check_cf": "check_cf",     # Controllo del codice fiscale dell'utente loggato con quello del certificato
        "check_certificate": "check_certificate" # Controllo se il certificato è stato revocato
      }

   Se il certificato è stato revocato la procedura si interrompe mostrando un messaggio all'utente.
   Se lo stato del certificato è non attendibile, caso in cui il certificato è valido ma non è garantito da una Autorità di Certificazione
   inclusa nell'elenco Pubblico dei Certificatori viene fatto un controllo sulla proprietà *behaviours* per decidere se mostrare un messaggio e
   far scegliere all'utente se continuare oppure interrompere l'operazione di firma e chiudere l'applicazione.
   Se il certificato è valido e tutti i controlli sono superati si passa alla firma effettiva dei file.

Processo di firma dei file
--------------------------
La firma digitale avviene all'interno di un loop che cicla sulla lista dei file passati nel json dei parametri.
Per ognuno vengono prese le proprietà dal json per inizializzare: le variabili, l'oggetto che conterrà il risultato e il path del file.
Se quest'ultimo è un URL il file viene scaricato con una chiamata http ad una servlet apposita e salvato nella cartella *uploads* nella home
di FirmaJR memorizzando il path locale in una variabile.

A questo punto, in base alla proprietà *signature_type* il file viene firmato in **P7M** oppure in **PDF** e la procedura è gestita rispettivamente
dai metodi **sign_p7m(*args*)** e **sign_pdf(*args*)**.

.. toctree::
   :maxdepth: 1

   firma_p7m.rst

.. toctree::
   :maxdepth: 1

   firma_pdf.rst

Entrambi i metodi restituiscono il path del file firmato che verrà aggiunto all'oggetto contenitore del risultato che a sua volta viene aggiunto
alla lista dei file firmati *signed_files_list* che è il dato che viene restituito dalla funzione insieme allo status.
Viene infine costruito il json che verrà inviato tramite una chiamata Http alla servlet di fine firma e l'applicazione terminerà l'esecuzione.

Debug
--------------------------
Per eseguire in debug un processo di firma basta sostituire nel main, all'interno del file *digiSign_server.py*, la variabile *sys_params*
decommentando la riga successiva e sostituendo l'url con quello della firma che deve essere analizzata.
L'url è possibile reperirlo sia dal file di log di FirmaJR che dagli strumenti sviluppatore del browser utilizzato.

Infine lanciare l'applicazione in debug direttamente dall'IDE.