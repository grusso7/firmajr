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

.. code-block:: python

  def makepdf(self, pdfdata1, udct, zeros, sig_attributes):
    parser = PDFParser(BytesIO(pdfdata1))
    document = PDFDocument(parser, fallback=False)
    log.info('get datas from pdf')
    prev = document.find_xref(parser)
    info = document.xrefs[0].trailer['Info'].objid
    root = document.xrefs[0].trailer['Root'].objid
    size = document.xrefs[0].trailer['Size']
    page_objid = document.catalog['Pages'].objid
    page = None

    log.info('check sig attributes...')
    position = MyConfigLoader().get_pdf_config()['position']
    if not sig_attributes:
        visibility = MyConfigLoader().get_pdf_config()['visibility']
    else:
        visibility = sig_attributes['visibility']
        log.info(f'the sign is {visibility}')
        if visibility == 'visible':
            position = sig_attributes['position']
            log.info(f'position: {position}')

    page_pos = position['page']
    if page_pos == 'n':
        try:
            pages_count = document.getobj(page_objid)['Count']
            page = document.getobj(page_objid)['Kids'][pages_count - 1].objid
        except Exception:
            page = int(1)
    else:
        try:
            page = document.getobj(page_objid)['Kids'][int(page_pos) - 1].objid
        except Exception:
            log.error('page not found...take the first')
            page = document.getobj(page_objid)['Kids'][0].objid

    infodata = self.getdata(pdfdata1, info, prev, document).strip()
    rootdata = self.getdata(pdfdata1, root, prev, document).strip()
    pagedata = self.getdata(pdfdata1, page, prev, document).strip()

    no = size
    multiple_signs = False
    signatures = self.get_signature_names(document)
    if len(signatures) > 0:
        multiple_signs = True

    if visibility == 'visible':
        rect_array = self.get_rect_array(pagedata, position)
        stream_name = compress(STREAM_WITH_NAME % udct[b'name'])
        if multiple_signs:
            objs = self.make_multi_visible_sig_objs(document, udct, no, page, pagedata, infodata, rootdata, stream_name, rect_array, zeros)
            xref = self.make_multi_visible_xref()
            new_size = 11
        else:
            objs = self.make_visible_sig_objs(udct, no, page, pagedata, infodata, rootdata, stream_name, rect_array, zeros)
            xref = self.make_visible_xref()
            new_size = 13
    else:
        if multiple_signs:
            objs = self.make_multi_inv_sig_objs(document, udct, no, page, pagedata, infodata, rootdata, zeros, len(signatures) + 1)
            xref = self.make_multi_inv_xref()
            new_size = 5
        else:
            objs = self.make_invisible_sig_objs(udct, no, page, pagedata, infodata, rootdata, zeros)
            xref = self.make_multi_inv_xref()
            new_size = 5

    pdfdata2 = b''.join(objs)
    startxref = len(pdfdata1)
    dct = {
        b'page': page,
        b'no': no,
        b'startxref': startxref + len(pdfdata2),
        b'prev': prev,
        b'info': no + 0,
        b'root': no + 1,
        b'size': no + new_size,
        b'p0': startxref + pdfdata2.find(b'\n%d 0 obj\n' % page) + 1,
        b'h1': hashlib.md5(pdfdata1).hexdigest().upper().encode('ascii'),
        b'h2': hashlib.md5(pdfdata2).hexdigest().upper().encode('ascii'),
    }
    for i in range(new_size):
        dct.update(({b'n%d' % i: startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + i)) + 1, }))

    trailer = b'''\
      trailer
      <</ID [<%(h1)s><%(h2)s>]/Info %(info)d 0 R/Prev %(prev)d/Root %(root)d 0 R/Size %(size)d>>\n\
      startxref\n\
      %(startxref)d\n\
      %%%%EOF\n\
      '''

    xref = xref % dct
    trailer = trailer % dct

    pdfdata2 = pdfdata2 + xref + trailer

    return pdfdata2

Per comprendere meglio cosa avviene descriviamo brevemente com'è strutturato un file pdf.

Un pdf è composto da:

* Un *header* che identifica la versione specifica al quale il pdf è conforme
* Un *body* contenente gli oggetti che sono presenti nel file
* Una *cross-reference table* contenente le informazioni degli oggetti indiretti del file
* Un *trailer* che fornisce la posizione della cross-reference table e di speciali oggetti all'interno del file

La struttura del file può essere modificata da aggiornamenti futuri, che consiste nell'aggiunta di nuovi elementi alla fine del file,
che è quello che avviene in FirmaJR. Vengono aggiunti nuovi oggetti e aggiornati i dati nella cross-reference table.

La costruzione del nuovo pdf avviene in questo modo: viene parsato attraverso una libreria il file pdf da firmare in modo che al posto
dei bytes è possibile "navigare" il file attraverso delle proprietà. Ogni proprietà è definita attraverso un Tag che all'interno del pdf
è un oggetto identificato da una proprietà chiamata **objid**.

Vengono estratti dal trailer tre oggetti che contengono informazioni per creare il nuovo pdf e sono:

1. **Info**, è un tag opzionale che contiene i metadata del file
2. **Root**, tag obbligatorio, è il catalogo dizionario che contiene le referenze degli altri oggetti definiti nel documento
3. **Size**, tag obbligatorio, è il numero di tutte le voci nella cross-reference table e definito dalla combinazione della sezione originale e tutte le sezioni aggiornate.

Visivamente la firma di un pdf può essere in due modi:

1. Visibile, viene apposta su una pagina, scelta, l'informazione della firma, eg. Nome e Cognome del firmatario
2. Invisibile, sul documento non c'è alcuna informazione visiva e la firma è visibile dal pannello firme

La visibilità della firma è parametrica e l'informazione è contenuta all'interno dei sig_attributes passati in ingresso.
In base a questo parametro vengono creati nuovi oggetti, ognuno contenente i tag necessari affinché la firma sia considerata valida per
ciascun caso e nello specifico della firma visibile viene individuata la pagina dove inserire il box con il nome e cognome del firmatario.
Ogni oggetto creato avrà un suo objid in modo che potrà essere identificato nella cross-reference table.

Di seguito il codice del metodo che crea un oggetto per una firma visibile:

.. code-block:: python

    def make_visible_sig_objs(self, udct, no, page, pagedata, infodata, rootdata, stream_name, rect, zeros):
      log.debug("load font")
      with open(path.join(BASE_PATH, 'encoded_font.bin'), 'rb') as font_file:
          font = font_file.read().decode('unicode-escape').encode('ISO-8859-1')
      objs = [
          self.makeobj(page, (b'/Annots[%d 0 R]' % (no + 2)) + pagedata),
          self.makeobj(no + 0, infodata),
          self.makeobj(no + 1, (b'/AcroForm<</SigFlags %d/Fields[%d 0 R]/DA(/Helv 0 Tf 0 g)/DR <</Font<</ZaDb %d 0 R/Helv %d 0 R>>>>>>' % (udct[b'sigflags'], no + 2, no + 11, no + 12)) + rootdata),
          self.makeobj(no + 2,
                  b'/AP<</N %d 0 R>>/Type/Annot/F 132/DA(/Arial 0 Tf 0 g)/FT/Sig/DR <<>>/P %d 0 R/Rect[%.2f %.2f %.2f %.2f]/Subtype/Widget/T(%s)/V %d 0 R' % (no + 3, page, rect[0], rect[1], rect[2], rect[3], udct[b'sign_name'], no + 4)),
          self.makeobj_stream(no + 3, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/XObject<</FRM %d 0 R>>>>/BBox[0 0 200 60]/Length 29' % (no + 5), compress(FRM_STREAM)),
          b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
          self.makeobj(no + 4,
                (b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/Name(%s)/Filter/Adobe.PPKLite/M(D:%s)/SubFilter/ETSI.CAdES.detached/Type/Sig/FT/Sig/Contents <' % (udct[b'name'], udct[b'signingdate'])) + zeros + b'>'),
          self.makeobj_stream(no + 5, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/XObject<</n0 %d 0 R/n2 %d 0 R>>>>/BBox[0 0 200 60]/Length 34' % (no + 6, no + 7), compress(N0_N2_STREAM)),
          self.makeobj_stream(no + 6, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]>>/BBox[0 0 100 100]/Length 18', compress(DSBLANK_STREAM)),
          self.makeobj_stream(no + 7, b'/Subtype/Form/Filter/FlateDecode/Type/XObject/Matrix [1 0 0 1 0 0]/FormType 1/Resources<</ProcSet [/PDF /Text /ImageB /ImageC /ImageI]/Font<</F1 %d 0 R>>>>/BBox[0 0 200 60]/Length %d' % (no + 8, len(stream_name)), stream_name),
          self.makeobj(no + 8, b'/Subtype/TrueType/FirstChar 32/Type/Font/BaseFont/ArialMT/FontDescriptor %d 0 R/Encoding/WinAnsiEncoding/LastChar 126/Widths[277 277 354 556 556 889 666 190 333 333 389 583 277 333 277 277 556 556 556 556 556 556 556 556 556 556 277 277 583 583 583 556 1015 666 666 722 722 666 610 777 722 277 500 666 556 833 722 777 666 777 722 666 610 722 666 943 666 666 610 277 277 277 469 556 333 556 556 500 556 556 277 556 556 222 222 500 222 833 556 556 556 556 333 500 277 556 500 722 500 500 500 333 259 333 583]' % (no + 9)),
          self.makeobj(no + 9, b'/Descent -210/CapHeight 716/StemV 80/Type/FontDescriptor/FontFile2 %d 0 R/Flags 32/FontBBox[-664 -324 2000 1039]/FontName/ArialMT/ItalicAngle 0/Ascent 728' % (no + 10)),
          self.makeobj_font_stream(no + 10, b'/Length1 96488/Filter/FlateDecode/Length 44982', font),
          self.makeobj(no + 11, b'/Name/ZaDb/Subtype/Type1/Type/Font/BaseFont/ZapfDingbats'),
          self.makeobj(no + 12, b'/Name/Helv/Subtype/Type1/Type/Font/BaseFont/Helvetica/Encoding/WinAnsiEncoding'),
      ]
      return objs

Ogni oggetto e tag è strettamente necessario per validità della firma.
I più importanti da citare sono gli oggetti che creato i seguenti tag:

* **Acroform**, dove sono definite proprietà del documento come i **SigFlags** che specificano le caratteristiche dei campi della firma, **Fields** un array di riferimenti a oggetti del documento, nel nostro caso il field firma creato successivamente.
* Il field della firma, ha come tag *AP*, il dizionario dell'Appearance dove vengono definiti i tag visivi, come il nome visualizzato nel pannello firma **/T**, le dimensioni del box che conterranno la firma visibile e su quale pagina sarà inserito che sono rispettivamente **/Rect** e */P* ed infine ma i più importanti il tag **/FT**, field type che è di tipo *Sig* e **/V**, field value che conterrà le informazioni del file firmato.
* Il field value, contiene le informazioni della firma. Il tag **/ByteRange**, che conterrà il range dei bytes della firma all'interno dell'intero documento e il più importante **/Contents** che conterrà i bytes del file firmato.

Per avere una descrizione dettagliata di tutti i tag, si rimanda alla documentazione ufficiale del pdf. `PDF Reference`_

Viene infine ricostruita la cross-reference table e il trailer con i riferimenti ai nuovi oggetti creati e vengono entrambi aggiunti
al pdf originale generando così un nuovo pdf.

Generato il nuovo pdf, avviene la firma dell'originale nel metodo *pdf_signer.sign*. Viene caricato il certificato dalla smartcard e creati
i signed attributes, che conterranno le informazioni del certificato, come l'ente, il numero seriale, l'algoritmo crittografico utilizzato e file
viene firmato.
Di seguito il codice del metodo :

.. code-block:: python

   def sign(datau, session, cert, cert_value, hashalgo, attrs=True, signed_value=None):
    if signed_value is None:
        signed_value = getattr(hashlib, hashalgo)(datau).digest()
    # signed_time = datetime.now() # not needed in signed attributes anymore

    x509 = Certificate.load(cert_value)
    certificates = []
    certificates.append(x509)

    cert_value_digest = bytes(session.digest(cert_value, Mechanism(LowLevel.CKM_SHA256)))
    log.info('building signed attributes...')
    signer = {
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': x509.issuer,
                'serial_number': x509.serial_number,
            }),
        }),
        'digest_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo}),
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
        'signature': signed_value,
    }
    if attrs:
        signer['signed_attrs'] = [
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('content_type'),
                'values': ('data',),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': (signed_value,),
            }),
            # cms.CMSAttribute({
            #     'type': cms.CMSAttributeType('signing_time'),
            #     'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
            # }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('1.2.840.113549.1.9.16.2.47'),
                'values': (tsp.SigningCertificateV2({
                    'certs': (tsp.ESSCertIDv2({
                        'hash_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo, 'parameters': None}),
                        'cert_hash': cert_value_digest,
                    }),),
                }),)
            }),
        ]
    config = {
        'version': 'v1',
        'digest_algorithms': cms.DigestAlgorithms((
            algos.DigestAlgorithm({'algorithm': hashalgo}),
        )),
        'encap_content_info': {
            'content_type': 'data',
        },
        'certificates': certificates,
        # 'crls': [],
        'signer_infos': [
            signer,
        ],
    }
    datas = cms.ContentInfo({
        'content_type': cms.ContentType('signed_data'),
        'content': cms.SignedData(config),
    })
    if attrs:
        tosign = datas['content']['signer_infos'][0]['signed_attrs'].dump()
        tosign = b'\x31' + tosign[1:]
    else:
        tosign = datau

    log.info('signed attributes ready')
    # fetching private key from smart card
    priv_key = SignatureUtils.fetch_private_key(session, cert)
    mechanism = Mechanism(LowLevel.CKM_SHA256_RSA_PKCS, None)
    log.info('signing...')
    # signing bytes to be signed
    signature = session.sign(priv_key, tosign, mechanism)

    datas['content']['signer_infos'][0]['signature'] = bytes(signature)

    return datas.dump()

I bytes firmati vengono sostituiti ai segnaposti nel file generato precedentemente e la firma è conclusa.

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

Il file viene salvato sul disco e verificato. Se la procedura va a buon fine verrà restituito il path del file altrimenti viene lanciata
un'eccezione.

Il path del file viene inserito nella lista dei file firmati firmati che saranno inviati nella chiamata http alla servlet di fine firma.
Il file può restare sul disco oppure essere inviato ad un server apposito, in base a questo il path può essere un url al download del file.

Dopo un'operazione di cleanup, viene effettuata la chiamata http alla servlet di fine firma e il flusso è concluso.

.. _PDF Reference: https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdf_reference_archive/pdf_reference_1-7.pdf