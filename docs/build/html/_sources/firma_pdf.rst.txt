Firma PDF
=========
La firma di un file PDF avviene nel metodo **sign_pdf(*args*)** che si trova nel file *digiSign_lib.py* dei sorgenti.

Anche qui come nella firma p7m viene fatto subito il controllo dell'identità dell'utente, opzionale se è una firma in fase di test.

.. code-block:: python

    @staticmethod
    def sign_pdf(file_path, open_session, certificate, certificate_value, user_cf, sig_attributes, timestamp, check_cf):
    """Metodo per la gestione della firma del file PDF

    :param file_path: Il path del file da firmare
    :type file_path: str
    :param open_session: La sessione aperta della smartcard
    :type open_session: Object
    :param certificate: Il certificato della smartcard
    :type certificate: Obj
    :param certificate_value: Il valore del certificato
    :type certificate_value: bytes
    :param user_cf: Il codice fiscale dell'utente
    :type user_cf: str
    :param sig_attributes: I parametri della firma
    :type sig_attributes: Obj
    :param timestamp: Timestamp dell'ora di firma
    :type timestamp: timestamp
    :param check_cf: Parametro per fare o no il controllo del codice fiscale
    :type check_cf: bool
    :raises PdfVerificationError: Errore nella verifica del file firmato
    :return: Il path del file firmato in PDF
    :rtype: str
    """

    # check for signer identity
    if check_cf:
      DigiSignLib()._check_certificate_owner(certificate_value, user_cf)
    else:
      log.info("check for certificate owner skipped")

    log.info(f"reading pdf file {file_path}")
    datau = open(file_path, 'rb').read()
    datas = pdf_builder.sign(datau, open_session, certificate, certificate_value, 'sha256', sig_attributes, timestamp)

    signed_file_path = DigiSignLib().get_signed_files_path(file_path, 'pdf')

    log.info(f"saving output to {signed_file_path}")
    with open(signed_file_path, 'wb') as fp:
      fp.write(datau)
      fp.write(datas)

    log.info(f"verifying pdf signatures of {signed_file_path}")
    try:
      new_data = open(signed_file_path, 'rb').read()
      results = verify(new_data, [certificate_value])
      for key, res in enumerate(results, start=1):
        print('Signature %d: ' % key, res)
        log.info(f"Signature {key}: {res}")
        if not res['hashok?']:
          raise PdfVerificationError(f"Hash verification of Signature {key} is failed.")
        if not res['signatureok?']:
          raise PdfVerificationError(f"Signature verification of Signature {key} is failed.")
        if not res['certok?']:
          # TODO verify certificates
          log.error(f"Certificate verification of Signature {key} is failed.")
    except:
      log.error(f"Error during verification of Signature {key}:")
      raise

    return signed_file_path

Il file viene letto in bytes e viene passato al metodo **sign(*agrs*)** della classe **SignedData** nel file **pdf_builder.py** dei sorgenti
insieme alla sessione, il certificato, il valore del certificato, l'algoritmo crittografico, gli attributi di firma e il timestamp dell'ora di firma.
Viene letto attraverso la classe *Certificate* della libreria *asn1crypto* il valore del certificato nel formato standard x509 in modo da
poter reperire le informazioni in modo agevole ed estrarre in questo caso il nome dell'utente dal certificato e creare il seguente dict:

.. code-block:: python

    dct = {
      b'sigflags': 3, # Valore per il tag SigFlags del pdf, un valore diverso da 0 indica che sul pdf sono presenti delle firme, normalmente viene utilizzato sempre il 3
      b'name': b'%b' % x509.subject.native['common_name'].encode(), # Il nome dell'utente
      b'signingdate': b'%b' % timestamp.encode(),                   # Timestamp dell'ora di firma
      b'sign_name': sign_name.encode()                              # Il titolo del campo firma
    }

Quindi viene passato alla funzione **makepdf(self, pdfdata1, udct, zeros, sig_attributes)**, insieme ai bytes del file da firmare (pdfdata1),
un segnaposto che conterrà il file firmato (zeros) ed infine gli attributi di firma letti dal json iniziale.
Il metodo genera il nuovo file pdf aggiungendo dei tag che conterranno le informazioni della firma.
Tecnicamente la costruzione del nuovo pdf avviene in questo modo, viene parsato attraverso una libreria il file pdf da firmare in modo che al posto
dei bytes è possibile "navigare" il file attraverso delle proprietà. Ogni proprietà del file viene definita attraverso un Tag che all'interno del pdf
è un oggetto identificato da un identificatore **objid**.



.. code-block:: python

   def sign(self, datau, session, cert, cert_value, algomd, sig_attributes, timestamp):
      log.info('get certificate in format x509 to build signer attributes')
      x509 = Certificate.load(cert_value)

      sign_name = sig_attributes['position']['signature_name']
      if sign_name == "":
          sign_name = MyConfigLoader().get_pdf_config()['position']['signatureName']

      dct = {
          b'sigflags': 3,
          b'name': b'%b' % x509.subject.native['common_name'].encode(),
          b'signingdate': b'%b' % timestamp.encode(),
          b'sign_name': sign_name.encode()
      }

      # Variabile segnaposto per i bytes che conterranno il file firmato riferimenti della firma
      zeros = self.aligned(b'\0')

      log.info('start building the new pdf')
      try:
          pdfdata2 = self.makepdf(datau, dct, zeros, sig_attributes)
          log.info('pdf generated correctly')
      except Exception:
          raise PDFCreationError('Exception on creating pdf')

      log.info('preparing data to be signed')
      startxref = len(datau)
      pdfbr1 = pdfdata2.find(zeros)
      pdfbr2 = pdfbr1 + len(zeros)
      br = [0, startxref + pdfbr1 - 1, startxref + pdfbr2 + 1, len(pdfdata2) - pdfbr2 - 1]
      brfrom = b'[0000000000 0000000000 0000000000 0000000000]'
      brto = b'[%010d %010d %010d %010d]' % tuple(br)
      pdfdata2 = pdfdata2.replace(brfrom, brto, 1)

      b1 = pdfdata2[:br[1] - startxref]
      b2 = pdfdata2[br[2] - startxref:]
      md = session.digestSession(Mechanism(LowLevel.CKM_SHA256))
      md.update(datau)
      md.update(b1)
      md.update(b2)
      md = bytes(md.final())
      log.info('start pdf signing')
      try:
          contents = pdf_signer.sign(None, session, cert, cert_value, algomd, True, md)
          contents = self.aligned(contents)
          pdfdata2 = pdfdata2.replace(zeros, contents, 1)
          log.info('pdf signed')
      except Exception:
          raise PDFSigningError('error in the sign procedure')

      return pdfdata2


