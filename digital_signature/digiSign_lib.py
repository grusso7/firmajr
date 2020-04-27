import mimetypes
import PyPDF2

from asn1crypto import cms
from my_logger import MyLogger
from OpenSSL import crypto
from os import path
from p7m_encoder import P7mEncoder, P7mAttributes
from pdf_builder import PDFLinearizedError
from signature_util import SignatureUtils
from tkinter import Tk, Label, Button, Frame
from verify import verify
import pdf_builder

log = MyLogger().my_logger()


# Custom exceptions:
class P7mCreationError(Exception):
    """ Raised when failing to create p7m """
    pass


class PdfVerificationError(Exception):
    """ Raised when failing to create p7m """
    pass


class PdfNotDeserializable(Exception):
    """ Raised when the pdf is not deserializable """
    pass


class CertificateValidityError(Exception):
    """ Raised for validity problems on the certificate """
    pass


class CertificateOwnerException(Exception):
    """ Raised if user_cf is not equal to smart card cf """
    pass


class DigiSignLib:
    @staticmethod
    def get_smart_cards_sessions():
        """ Check for connected smart card

            Returns:
                a session list of connected smart cards
        """
        # getting a smart card session
        return SignatureUtils().fetch_smart_card_sessions()

    @staticmethod
    def session_login(sessions, pin):
        """ Attempt to login on connected smart cards

            Param:
                sessions: connected smart card slots
                pin: user pin

            Returns:
                logged in session
        """

        # login on the session
        return SignatureUtils().user_login(sessions, pin)

    @staticmethod
    def sign_p7m(file_path, open_session, user_cf, sig_attrs, timestamp, check_cf):
        """Metodo per la gestione della firma P7M

        :param file_path: Path del file da firmare
        :type file_path: str
        :param open_session: La sessione aperta della smartcard
        :type open_session: Object
        :param user_cf: Codice fiscale dell'utente
        :type user_cf: str
        :param sig_attrs: Parametri della firma
        :type sig_attrs: Obj
        :param timestamp: Timestamp dell'ora di firma
        :type timestamp: timestamp
        :param check_cf: Parametro per fare o no il controllo del codice fiscale
        :type check_cf: bool
        :raises P7mCreationError: Errore nella creazione del P7M
        :return: Il path del file firmato in P7M
        :rtype: str
        """

        # fetching sig type
        sig_type = sig_attrs['p7m_sig_type']
        # fetching file content
        file_content = DigiSignLib().get_file_content(file_path)

        # check existing signatures
        p7m_attrs = P7mAttributes(b'', b'', b'')
        mime = mimetypes.MimeTypes().guess_type(file_path)[0]
        if mime == 'application/pkcs7' or mime == 'application/pkcs7-mime':
            info = cms.ContentInfo.load(file_content)
            # retrieving existing signatures attributes
            signed_data = info['content']
            p7m_attrs.algos = signed_data['digest_algorithms'].contents
            p7m_attrs.certificates = signed_data['certificates'].contents
            # Se la firma è parallela, viene sovrascritto il file con il native, ovvero il file originale.
            if sig_type == 'parallel':
                p7m_attrs.signer_infos = signed_data['signer_infos'].contents
                file_content = signed_data['encap_content_info'].native['content']

        # hashing file content
        file_content_digest = SignatureUtils().digest(open_session, file_content)

        # fetching smart card certificate
        certificate = DigiSignLib().get_certificate(open_session)
        # getting certificate value
        certificate_value = DigiSignLib().get_certificate_value(
            open_session, certificate)
        # hashing certificate value
        certificate_value_digest = SignatureUtils().digest(
            open_session, certificate_value)

        # check for signer identity
        if check_cf:
            DigiSignLib()._check_certificate_owner(certificate_value, user_cf)
        else:
            log.info("check for certificate owner skipped")

        # getting signed attributes p7m field
        try:
            signed_attributes = P7mEncoder().encode_signed_attributes(
                file_content_digest, certificate_value_digest, timestamp)
        except:
            raise P7mCreationError("Exception on encoding signed attributes")
        # getting bytes to be signed
        try:
            bytes_to_sign = P7mEncoder().bytes_to_sign(
                file_content_digest, certificate_value_digest, timestamp)
        except:
            raise P7mCreationError("Exception on encoding bytes to sign")

        # fetching private key from smart card
        priv_key = SignatureUtils().fetch_private_key(open_session, certificate)
        # signing bytes to be signed
        signed_attributes_signed = SignatureUtils().signature(
            open_session, priv_key, bytes_to_sign)

        # getting issuer from certificate
        issuer = SignatureUtils().get_certificate_issuer(open_session, certificate)
        # getting serial number from certificate
        serial_number = SignatureUtils().get_certificate_serial_number(
            open_session, certificate)
        # getting signer info p7m field
        try:
            signer_info = P7mEncoder().encode_signer_info(
                issuer, serial_number, signed_attributes,
                signed_attributes_signed, p7m_attrs.signer_infos)
        except:
            raise P7mCreationError("Exception on encoding signer info")

        # create the p7m content
        try:
            output_content = P7mEncoder().make_a_p7m(
                file_content, certificate_value, signer_info, p7m_attrs)
        except:
            raise P7mCreationError("Exception on encoding p7m file content")

        # saves p7m to file
        #   extracting needed part of file path
        signed_file_path = DigiSignLib().get_signed_files_path(file_path, 'p7m', sig_type)
        DigiSignLib().save_file_content(signed_file_path, output_content)

        return signed_file_path

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
        try:
            datas = pdf_builder.sign(datau, open_session, certificate, certificate_value, 'sha256', sig_attributes, timestamp)
        except PDFLinearizedError as err:
            log.warning(err)
            delinearized_file = DigiSignLib().delinearize_pdf(file_path)

            datau = open(delinearized_file, "rb").read()
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

    @staticmethod
    def delinearize_pdf(filepath):

        pdf = filepath
        output_filename = filepath.replace(".pdf", "-1.pdf")
        pdf_fh = open(pdf, 'rb')
        pdf = PyPDF2.PdfFileReader(pdf_fh, strict=False)

        writer = PyPDF2.PdfFileWriter()

        try:
            for i in range(0, pdf.getNumPages()):
                page = pdf.getPage(i)
                writer.addPage(page)

            with open(output_filename, 'wb') as fh:
                writer.write(fh)
        except Exception as error:
            pdf_fh.close()
            raise PdfNotDeserializable("Can't deserialize the pdf: %s", error)

        pdf_fh.close()
        return output_filename

    @staticmethod
    def session_logout(session):
        """ User logout from session """

        # logout from the session
        SignatureUtils().user_logout(session)

    @staticmethod
    def session_close(session):
        """ Close smart card `session` """

        # session close
        SignatureUtils().close_session(session)

    @staticmethod
    def get_file_content(file_path):
        """ Return `file_path` content in binary form """

        log.info(f"reading file {file_path}")
        with open(file_path, "rb") as file:
            file_content = file.read()

        return file_content

    @staticmethod
    def save_file_content(file_path, content):
        """ Save content to `file_path` """

        log.info(f"saving output to {file_path}")
        with open(file_path, "wb") as file:
            file.write(content)

    @staticmethod
    def get_certificate(session):
        """ Fetch certificate from `session` """

        return SignatureUtils().fetch_certificate(session)

    @staticmethod
    def get_certificate_value(session, certificate):
        """ Get certificate value from `certificate` from `session` """

        return SignatureUtils().get_certificate_value(session, certificate)

    @staticmethod
    def check_certificate_time_validity(status, block_if_expired, warn_if_expired):
        log.info("Chech for certificate time validity")

        if status == "NOT_VALID_YET":
            DigiSignLib()._not_valid_yet_popup()
            raise CertificateValidityError("Certificate not valid yet")
        elif status == "EXPIRED":
            if block_if_expired:
                log.info("Certificate expired and block_if_expires setted to True")
                raise CertificateValidityError("Certificate expired")

            if warn_if_expired:
                choice = {}
                DigiSignLib()._proceed_with_expired_certificate(choice)
                if "continue" not in choice:
                    log.error("Something went wrong with the expired certificate choise popup")
                    raise ValueError("Something went wrong with the expired certificate choise popup")
                if not choice["continue"]:
                    log.warning("User chosen to NOT proceed")
                    raise CertificateValidityError("Certificate expired")
                log.info("User chosen to proceed")
            else:
                log.warning("Certificate expired and warn_if_expires setted to False")

    @staticmethod
    def _check_certificate_owner(certificate_value, user_cf):
        """ Check if user_cf is equal to smart card cf. Raise a `CertificateOwnerException` """

        log.info("Chech for certificate owner")
        certificate_x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, bytes(certificate_value))

        subject = certificate_x509.get_subject()
        components = dict(subject.get_components())
        component = components[bytes("serialNumber".encode())]
        codice_fiscale = component.decode()[-16:]

        if codice_fiscale.upper() != user_cf.upper():
            raise CertificateOwnerException(f"{user_cf} (input) != {codice_fiscale} (smartcard)")
        else:
            log.info("owner verified")

    @staticmethod
    def _not_valid_yet_popup():
        """ Little popup for telling the user that his certificate is not valid yet """

        log.info("Certificate not valid yet")
        widget = Tk()
        row = Frame(widget)
        label1 = Label(row, text="Il certificato di firma non è ancora valido,")
        label2 = Label(row, text="firma digitale annullata")
        row.pack(side="top", padx=60, pady=20)
        label1.pack(side="top")
        label2.pack(side="top")

        def on_click():
            widget.destroy()

        button = Button(widget, command=on_click, text="OK")
        button.pack(side="top", fill="x", padx=120)
        filler = Label(widget, height=1, text="")
        filler.pack(side="top")

        widget.title("Warning")
        widget.attributes("-topmost", True)
        widget.update()
        DigiSignLib()._center(widget)
        widget.mainloop()

    @staticmethod
    def _proceed_with_expired_certificate(choice):
        """ Little popup for asking the user if he wants to sign with an expired certificate """

        log.warning("Certificate expired")
        widget = Tk()
        row1 = Frame(widget)
        label1 = Label(row1, text="Il certificato di firma risulta scaduto,")
        label2 = Label(row1, text="procedere comunque?")
        row1.pack(side="top", padx=60, pady=20)
        label1.pack(side="top")
        label2.pack(side="top")

        def on_click_ok():
            widget.destroy()
            choice["continue"] = True

        def on_click_nok():
            widget.destroy()
            choice["continue"] = False

        row2 = Frame(widget)
        button_ok = Button(row2, width=10, command=on_click_ok, text="OK")
        button_nok = Button(row2, width=10, command=on_click_nok, text="Annulla")
        row2.pack(side="top")
        button_ok.pack(side="left", padx=10)
        button_nok.pack(side="right", fill="x", padx=10)
        filler = Label(widget, height=1, text="")
        filler.pack(side="top")

        widget.title("Warning")
        widget.attributes("-topmost", True)
        widget.update()
        DigiSignLib()._center(widget)
        widget.mainloop()

    @staticmethod
    def _center(widget):
        """ Center `widget` on the screen """
        screen_width = widget.winfo_screenwidth()
        screen_height = widget.winfo_screenheight()

        x = screen_width / 2 - widget.winfo_width() / 2
        # Little higher than center
        y = screen_height / 2 - widget.winfo_height()

        widget.geometry(f"+{int(x)}+{int(y)}")

    @staticmethod
    def get_signed_files_path(file_path, sig_type, p7m_sig_type=None):
        #   extracting needed part of file path
        signed_file_base_path = path.dirname(file_path)
        signed_file_complete_name = path.basename(file_path)
        signed_file_name, signed_file_extension = path.splitext(signed_file_complete_name)
        #   composing final file name
        #   Check if file is already signed
        start = signed_file_name.find('firmato')
        if start != -1:
            signed_file_name = signed_file_name.replace('firmato', '')
            final_file_name = f"{signed_file_name[:start]}(firmato){signed_file_name[start:]}{signed_file_extension}"
        else:
            final_file_name = f"{signed_file_name}(firmato){signed_file_extension}"

        if sig_type == 'p7m' and (p7m_sig_type != 'parallel' or start != -1):
            final_file_name = final_file_name + f".{sig_type}"
        signed_file_path = path.join(signed_file_base_path, final_file_name)

        return signed_file_path
