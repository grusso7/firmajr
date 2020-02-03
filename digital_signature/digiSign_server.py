import json
import mimetypes
import urllib
import uuid
import validators

from base64 import b64decode
from datetime import datetime, timedelta
from digiSign_lib import DigiSignLib, CertificateOwnerException, CertificateValidityError
from my_config_loader import MyConfigLoader
from my_logger import MyLogger
from os import path, remove, sys, listdir, makedirs, environ
from requests import post, get
from revocation_checker import RevocationChecker
from shutil import move
from tkinter import Tk, Entry, Label, Button, Frame, messagebox, LEFT
from traceback import extract_tb
from urllib import request as urlfile
from update_checker import check_for_updates, run_updates, UPDATE_STATUS_STR, UpdateStatus
from enum import Enum

####################################################################
#       CONFIGURATION                                              #
####################################################################
# url
HOST = MyConfigLoader().get_server_config()["host"]
PORT = MyConfigLoader().get_server_config()["port"]
PROTOCOL = MyConfigLoader().get_server_config()["protocol"]
# mapped directories
# TEMPLATE_FOLDER = MyConfigLoader().get_server_config()["template_folder"]
UPLOAD_FOLDER = MyConfigLoader().get_server_config()["uploaded_file_folder"]
SIGNED_FOLDER = MyConfigLoader().get_server_config()["signed_file_folder"]
LOGS_FOLDER = MyConfigLoader().get_logger_config()["log_folder"]
# Allowed signature types
P7M = "p7m"
PDF = "pdf"
ALLOWED_SIGNATURE_TYPES = {P7M, PDF}
# Memorized pin
user_session = {}
SESSION_TIMEOUT = MyConfigLoader().get_server_config()["pin_validity_time"]
# Statuses
GOOD = RevocationChecker().GOOD
UNKNOWN = RevocationChecker().UNKNOWN
REVOKED = RevocationChecker().REVOKED
ERROR = RevocationChecker().ERROR
####################################################################


class SignStatus(Enum):
    SIGNED = "signed"
    ABORTED = "aborted"
    ERROR = "error"
    PARTIALLY_SIGNED = "partially_signed"


log = MyLogger().my_logger()
update_thread_launched = False


####################################################################
#       REST API                                                   #
####################################################################
def handle_sign(start_params):
    """Metodo principale. Effettua il parsing dei parametri contenuti nell'URL lanciato dalla web application,
    recupero dei parametri, controllo degli aggiornamenti e avvio processo di firma.

    :param start_params: È l'URL completo aperto nel browser
    :type start_params: str
    """
    if start_params.__len__() == 0:
        start_params = get_sign_resume()
    else:
        start_params = start_params[0]

    if start_params is None:
        return error_response(SignStatus.ERROR.value, "No file to sign or empty array params")

    log.info("Parameters from protocol = %s" % start_params)

    tolkien_list = start_params.rsplit(";", maxsplit=1)
    token = tolkien_list[0].lstrip(PROTOCOL)
    log.info("Token: %s" % token)
    rev_url_encoded = tolkien_list[1]
    rev_url = b64decode(rev_url_encoded).decode("utf-8")
    log.info("Revocation Url: %s" % rev_url)

    # Check for upload and signed folder
    if not path.exists(UPLOAD_FOLDER) or not path.isdir(UPLOAD_FOLDER):
        makedirs(UPLOAD_FOLDER)
    if not path.exists(SIGNED_FOLDER) or not path.isdir(SIGNED_FOLDER):
        makedirs(SIGNED_FOLDER)

    # remove this for prod
    # if "HTTP_PROXY" in environ:
    #     del environ["HTTP_PROXY"]


    log.info("getting paramaters...")
    try:
        r = get(rev_url + "/" + token)
        if r.status_code == 200:
            signature_params = r.json()
            log.info("parameters found: %s" % signature_params)

            # checking for client updates
            update_checker_url = signature_params["update_checker_url"]
            status_update = updates_manager(start_params, update_checker_url)
            log.info(status_update)

            log.info("signing...")
            master_document_id = ""
            if "masterDocumentId" in signature_params:
                master_document_id = signature_params["masterDocumentId"]
            end_sign_manager_url = signature_params['params']['endSignManagerUrl']
            result_channel = signature_params['params']['resultChannel']
            sign_result = sign(signature_params)
            # chiamare la endSignServletHere
            response_maker(end_sign_manager_url, result_channel, sign_result, master_document_id)
        else:
            log.error(r.status_code)
            show_warning_message("Errore durante il reperimento dei dati per la firma. "
                                 "Riprovare o contattare il servizio di assistenza.")
    except ConnectionError as conn_err:
        log.error(conn_err)
        show_warning_message("Impossibile stabilire una connessione con il server. Contattare l'assistenza.")
    except Exception as err:
        log.error("error: %s", err)
        show_warning_message("Errore, contattare il servizio di assistenza.")


def sign(json_parsed):
    """Metodo principale per la gestione del processo di firma dei file passati come parametro

    :param json_parsed: Il json contenente i parametri e i file da firmare
    :type json_parsed: str
    :return: Lista contenente lo status della firma e la lista dei file firmati oppure un messaggio in caso di errore
    :rtype: List[SignStatus, json]
    """
    ###################################
    # JSON structure:
    # {
    #     user_id: codice_fiscale // "X"*15 to skip check,
    #     masterDocumentId: masterDocumentId,
    #     file_list: [
    #         {
    #             file: file_path,
    #             file_id: id,
    #             file_mime_type: file_mime_type,
    #             file_name: file_name,
    #             file_type: file_type (Es. DocumentoPicoNuovoPU),
    #             file_data: {file additional data (only a bag)},
    #             signed_file_type: p7m|pdf
    #             "destination": destination_path,
    #             "sig_attributes": {
    #                 "visibility": visibility,
    #                 "position": {
    #                     "page": 'n',
    #                     "width": 200.0,
    #                     "height": 60.0,
    #                     "padding_width": 75.0,
    #                     "padding_height": 670.0,
    #                     "signature_name": "Signature"
    #                 },
    #                 "p7m_sig_type": p7m_sig_type,
    #                 "text_template": "",
    #             }
    #         },
    #         ...
    #     ],
    #     test_mode: true|false,
    #     update_checker_url: [optional],
    #     revocation_checker_url: [optional],
    #     uploader: "http://localhost:8095/",
    #     params: {
    #       azienda: codice_azienda,
    #       serverIdentifier: serverIdentifier,
    #       resultChannel: resultChannel,
    #       endSignManagerUrl: servlet di fine firma
    #     }
    # }
    ###################################

    if "user_id" not in json_parsed:
        error_message = "missing user_id field"
        return error_response(SignStatus.ERROR.value, error_message)
    user_id = json_parsed["user_id"]

    if "file_list" not in json_parsed:
        error_message = "missing file_list field"
        return error_response(SignStatus.ERROR.value, error_message)
    file_list = json_parsed["file_list"]

    if not isinstance(file_list, (list,)) or len(file_list) < 1:
        error_message = "Empty file_list"
        return error_response(SignStatus.ERROR.value, error_message)

    for json_file in file_list:
        if "file" not in json_file:
            error_message = "missing file field"
            return error_response(SignStatus.ERROR.value, error_message)

        if "signed_file_type" not in json_file:
            error_message = "missing signed_file_type field"
            return error_response(SignStatus.ERROR.value, error_message)
        sig_type = json_file["signed_file_type"]

        if "sig_attributes" not in json_file:
            error_message = "missing sig_attributes field"
            return error_response(SignStatus.ERROR.value, error_message)

        if not allowed_signature(sig_type):
            error_message = f"{sig_type} not allowed in signed_file_type field"
            return error_response(SignStatus.ERROR.value, error_message)

    if "uploader" not in json_parsed:
        error_message = "missing output_path field"
        return error_response(SignStatus.ERROR.value, error_message)
    path_for_signed_files = json_parsed["uploader"]

    # Check per la destinazione dei file firmati
    output_to_url = False
    if validators.url(path_for_signed_files):
        output_to_url = True
    else:
        if not path.exists(path_for_signed_files) or not path.isdir(path_for_signed_files):
            error_message = f"{path_for_signed_files} field is not a valid directory"
            return error_response(SignStatus.ERROR.value, error_message)

    # folder cleanup
    for _file in listdir(SIGNED_FOLDER):
        remove(path.join(SIGNED_FOLDER, _file))

    # getting params
    params = {}
    if "params" in json_parsed:
        params = json_parsed["params"]

    # getting revocation server url
    if "revocation_checker_url" not in json_parsed:
        error_message = "revocation_checker_url not found. Can't procede to revocation check"
        log.error(error_message)
        clear_session(user_id)
        return error_response(SignStatus.ERROR.value, error_message)

    revocation_checker_url = json_parsed["revocation_checker_url"]

    # checking for test mode
    test_mode = json_parsed["test_mode"]
    if not test_mode:
        # getting smart cards connected
        sessions = None
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

        # check for certificate status, time validity and behaviours
        try:
            rev_serv_resp = get_certificate_status(revocation_checker_url, user_id, certificate_value, params)
        except Exception as err:
            _, value, tb = sys.exc_info()
            log.error(value)
            log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
            clear_session(user_id)
            return error_response(SignStatus.ERROR.value, "Impossibile verificare il certificato di firma")

        log.info(f"revocation check results: {rev_serv_resp}")
        status = rev_serv_resp["status"]
        timestamp = rev_serv_resp["timestamp"]
        check_cf = rev_serv_resp["check_cf"]
        try:
            behaviours = rev_serv_resp["behaviours"]
            block_if_expired = behaviours["block_if_expired"]
            warn_if_expired = behaviours["warn_if_expired"]
            block_on_untrusted = behaviours["block_on_untrusted"]
            message_on_untrusted = behaviours["message_on_untrusted"]
        except:
            block_if_expired = "N"
            warn_if_expired = "N"
            block_on_untrusted = "N"
            message_on_untrusted = "N"
            pass

        try:
            DigiSignLib.check_certificate_time_validity(status, block_if_expired, warn_if_expired)
        except Exception as err:
            _, value, tb = sys.exc_info()
            log.error(value)
            log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
            clear_session(user_id)
            return error_response(SignStatus.ERROR.value, "Impossibile procedere, certificato scaduto!")

        # handle certificate status
        if user_session[user_id]["status"] == REVOKED:
            return error_response(SignStatus.ERROR.value, "Certificato di firma revocato! Impossibile procedere")

        if user_session[user_id]["status"] == UNKNOWN:
            if block_on_untrusted is True:
                return error_response(SignStatus.ERROR.value, "Il certificato risulta in stato sconosciuto, "
                                                        "impossibile procedere")

            if message_on_untrusted is True:
                if "continue" not in user_session[user_id]:
                    choice = {}
                    _unknown_certificate_choice(choice)
                    if "continue" not in choice:
                        return error_response(SignStatus.ABORTED.value, "La firma è stata interrorra dall'utente")

                    user_session[user_id]["continue"] = choice["continue"]
                if not user_session[user_id]["continue"]:
                    return error_response(SignStatus.ABORTED.value, "L'utente ha deciso di non procedere alla firma "
                                                                    "a causa dello stato sconosciuto del certificato")

    else:
        log.info("test mode enabled, revocation check skipped")

    # loop on given files
    signature_status = {}
    error_count = 0
    signed_count = 0
    signed_files_list = []
    for _index, file_to_sign in enumerate(file_list):
        # taking parameters
        file_id = file_to_sign["file_id"]
        file_name = file_to_sign["file_name"]
        file_type = file_to_sign["file_type"]
        file_mime_type = file_to_sign["file_mime_type"]
        file_data = file_to_sign["file_data"]
        signature_type = file_to_sign["signed_file_type"]
        file_path_to_sign = file_to_sign["file"]
        sig_attributes = file_to_sign["sig_attributes"]
        destination = file_to_sign["destination"]

        # initialize response structure
        output_item = {"file": file_path_to_sign,
                       "file_id": file_id,
                       "file_name": file_name,
                       "file_type": file_type,
                       "file_mime_type": file_mime_type,
                       "file_data": file_data,
                       "signed_file_type": signature_type,
                       "sig_attributes": sig_attributes,
                       "destination": destination,
                       "signed": "",
                       "signed_file": ""}
        signed_files_list.append(output_item)

        # handle url file paths
        if validators.url(file_path_to_sign):
            try:
                local_file_path = download_file(file_path_to_sign)
            except:
                log.error(f"Impossibile reperire il file: {file_path_to_sign}")
                _, value, tb = sys.exc_info()
                log.error(value)
                log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
                signed_files_list[_index]["signed"] = "no"
                error_count += 1
                signature_status[SignStatus.ERROR] = error_count
                continue
        else:
            local_file_path = file_path_to_sign
        log.info("LOCAL PATH = %s", local_file_path)
        temp_file_path = ""
        if not test_mode:
            try:
                if signature_type == P7M:
                    # p7m signature
                    temp_file_path = DigiSignLib().sign_p7m(local_file_path, session, user_id, sig_attributes,
                                                            timestamp, check_cf)
                elif signature_type == PDF:
                    # pdf signature
                    mime = mimetypes.MimeTypes().guess_type(local_file_path)[0]
                    if mime == 'application/pdf':
                        temp_file_path = DigiSignLib().sign_pdf(local_file_path, session, certificate, certificate_value,
                                                                user_id, sig_attributes, timestamp, check_cf)
                    else:
                        log.info(f"the file {local_file_path} is not a pdf will be ignored")
                        signed_files_list[_index]["signed"] = "no"
                        error_count += 1
                        signature_status[SignStatus.ERROR] = error_count
                        continue

                signed_files_list[_index]["signed"] = "yes"
                signed_count += 1
                signature_status[SignStatus.SIGNED] = signed_count
            except CertificateOwnerException as err:
                user_tip = "Codice fiscale dell'utente non corrispondente a quello della smart card. " \
                           "Impossibile procedere."
                DigiSignLib().session_logout(session)
                DigiSignLib().session_close(session)
                return error_response(SignStatus.ERROR.value, user_tip)
            except CertificateValidityError as err:
                user_tip = "Certificato non valido temporalmente"
                DigiSignLib().session_logout(session)
                DigiSignLib().session_close(session)
                return error_response(SignStatus.ERROR.value, user_tip)
            except:
                _, value, tb = sys.exc_info()
                log.error(value)
                log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
                signed_files_list[_index]["signed"] = "no"
                error_count += 1
                signature_status[SignStatus.ERROR] = error_count
                continue
        else:
            log.info("test mode enabled, signing skipped")
            temp_file_path = local_file_path
            signed_files_list[_index]["signed"] = "yes"
            signed_count += 1
            signature_status[SignStatus.SIGNED] = signed_count

        # moving signed file to given destination
        if output_to_url:
            log.info("moving signed file to given destination: %s", path_for_signed_files)
            with open(temp_file_path, "rb") as _file:
                files = {'upload-file': _file}
                data = {
                    'destination': destination,
                    'params': json.dumps(params)
                }
                try:
                    log.info(path_for_signed_files)     # Url uploader
                    res = post(path_for_signed_files, files=files, data=data)
                except:
                    _, value, tb = sys.exc_info()
                    log.error(value)
                    log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
                    signed_files_list[_index]["signed_file"] = "EXCEPTION!!"
                    error_count += 1
                    signature_status[SignStatus.ERROR] = error_count
                    continue
                if res.status_code != 200:
                    error_message = res.json()["error_message"]
                    log.error(error_message)
                    signed_files_list[_index]["signed_file"] = "ERROR!!"
                    error_count += 1
                    signature_status[SignStatus.ERROR] = error_count
                    continue
                else:
                    log.info("file signed and uploaded")
                    signed_files_list[_index]["signed"] = "yes - [remote]"
                    signed_files_list[_index]["signed_file"] = f"{res.text}"
                    signed_count += 1
                    signature_status[SignStatus.SIGNED] = signed_count
                    continue
        else:
            temp_file_name = path.basename(temp_file_path)
            signed_file_path = path.join(path_for_signed_files, temp_file_name)
            try:
                move(temp_file_path, signed_file_path)
                signed_files_list[_index]["signed_file"] = signed_file_path
            except:
                _, value, tb = sys.exc_info()
                log.error(value)
                log.error('\n\t'.join(f"{i}" for i in extract_tb(tb)))
                signed_files_list[_index]["signed_file"] = "LOST"
                error_count += 1
                signature_status[SignStatus.ERROR] = error_count
                continue

    # Folder cleanup
    for _file in listdir(UPLOAD_FOLDER):
        remove(path.join(UPLOAD_FOLDER, _file))

    # logout
    if not test_mode:
        try:
            DigiSignLib().session_logout(session)
        except:
            log.error("logout failed")
        # session close
        try:
            DigiSignLib().session_close(session)
        except:
            log.error("session close failed")
    ###################################
    # response JSON structure:
    # { signed_file_list: [
    #     {
    #         file_to_sign: ***,
    #         signed: yes|no,
    #         signed_file: ***
    #     },
    #     {
    #         file_to_sign: ***,
    #         signed: yes|no,
    #         signed_file: ***
    #     },
    #     ...
    # ]}
    ###################################
    if SignStatus.SIGNED in signature_status:
        if SignStatus.ERROR in signature_status:
            status = SignStatus.PARTIALLY_SIGNED.value
        else:
            status = SignStatus.SIGNED.value
    else:
        status = SignStatus.ERROR.value

    res = [status, signed_files_list]
    return res


####################################################################
#       UTILITIES                                                  #
####################################################################
def allowed_signature(signature_type):
    """ Returns if `signature_type` is allowed """
    return signature_type.lower() in ALLOWED_SIGNATURE_TYPES


def get_sign_resume():
    """Recupera i parametri per riprendere il processo di firma in seguito ad un aggiornamento

    :return: L'URL con i parametri iniziali
    :rtype: str
    """
    log.info("resuming signature status...")
    try:
        with open(path.join(UPLOAD_FOLDER, 'sign_status.dat')) as f:
            read_data = f.read()
            log.info("data from file: %s" % read_data)
            return read_data
    except FileNotFoundError as ex:
        return None


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


def response_maker(url_servlet_end_sign, _result_channel, result, master_document_id):
    """Costruisce il json con il risultato di firma e chiama la servlet di fine firma

    :param url_servlet_end_sign: Url della servlet di fine firma
    :type url_servlet_end_sign: str
    :param _result_channel: Identificatore del risultato della firma su redis
    :type _result_channel: str
    :param result: La lista del risultato di firma, contenente lo status e la lista dei file firmati
    :type result: List
    :param master_document_id: Id del documento master, utilizzato dal sistema Babel nel caso del firmone
    :type master_document_id: str
    :return: La risposta http della servlet
    :rtype: HttpResponse
    """

    log.info(
        "Sending response...{url: %s, result_channel: %s, result: %s, masterDocumentId: %s}",
        url_servlet_end_sign, _result_channel, result, master_document_id)
    res_maked = post(url=url_servlet_end_sign,
                     data=json.dumps(
                         {"ResultChannel": _result_channel,
                          "signStatus": result[0],
                          "masterDocumentId": master_document_id,
                          "result": result[1]}
                     ))
    return res_maked


def error_response(sign_status, error_message):
    return [sign_status, error_message]


def init_session(user_id):
    """ Initializes `user_session` associated with `user_id` """

    user_session[user_id] = {}


def clear_session(user_id):
    """ Clears `user_session` associated with `user_id` """

    log.info("Clearing PIN")
    if user_id in user_session:
        if "timestamp" in user_session[user_id]:
            user_session[user_id].pop("timestamp")
        if "pin" in user_session[user_id]:
            user_session[user_id].pop("pin")
        if "status" in user_session[user_id]:
            user_session[user_id].pop("status")
        if "continue" in user_session[user_id]:
            user_session[user_id].pop("continue")


def _is_session_valid(user_id):
    """ Check if `user_id` session is expired """

    return datetime.now() < user_session[user_id]["timestamp"] + timedelta(seconds=SESSION_TIMEOUT)


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

    #  Struttura del Json di risposta:
    # {
    #     "status": "status",
    #     "behaviours": "behaviours",
    #     "timestamp": "timestamp",
    #     "check_cf": "check_cf",
    #     "check_certificate": "check_certificate"
    # }

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


def get_pin(user_id):
    """ Gets you the `PIN` and saves it in `user_session` """

    if user_id not in user_session:
        init_session(user_id)

    if "pin" not in user_session[user_id]:
        _get_pin_popup(user_id)
    elif not _is_session_valid(user_id):
        log.info("Invalidating user_session")
        clear_session(user_id)
        _get_pin_popup(user_id)
    else:
        log.info("Refreshing user_session timestamp")
        user_session[user_id]["timestamp"] = datetime.now()

    # check for mishapening
    if "pin" not in user_session[user_id]:
        raise ValueError("aborted")


def _get_pin_popup(user_id):
    """ Little popup to input Smart Card PIN """

    log.info("User PIN input")
    widget = Tk()
    row = Frame(widget)
    label = Label(row, width=10, text="Inserisci PIN:")
    pinbox = Entry(row, width=15, show='*')
    row.pack(side="top", padx=60, pady=20)
    label.pack(side="left")
    pinbox.pack(side="right")

    def on_abort():
        log.info("Get pin aborted by user")
        widget.destroy()

    def on_click():
        user_session[user_id]["pin"] = pinbox.get()
        user_session[user_id]["timestamp"] = datetime.now()
        widget.destroy()

    widget.bind("<Return>", lambda a: on_click())
    widget.protocol("WM_DELETE_WINDOW", on_abort)
    button_ok = Button(widget, width=10, command=on_click, text="OK")
    button_ok.pack(side=LEFT, padx=(60, 10), pady=(0, 10))
    button_abort = Button(widget,  width=10, command=on_abort, text="Annulla")
    button_abort.pack(side=LEFT, padx=5, pady=(0, 10))
    filler = Label(widget, height=1, text="")
    filler.pack(side="top")

    widget.title("Smart Card PIN")
    widget.attributes("-topmost", True)
    widget.update()
    _center(widget)
    widget.mainloop()


def show_warning_message(message):
    """ Little popup to show warning message """

    log.info("show_warning_message")
    widget = Tk()
    widget.withdraw()
    messagebox.showwarning("Attenzione", message)
    widget.destroy()


def _unknown_certificate_choice(choice):
    """ Little popup for asking the user if he wants to sign with an unknoun certificate status """

    log.info("Unknown status")
    widget = Tk()
    row1 = Frame(widget)
    label1 = Label(row1, text="Al momento non è possibile verificare lo stato del")
    label2 = Label(row1, text="certificato di firma, procedere comunque?")
    label3 = Label(row1, text="(Questa scelta sarà memorizzata fino alla scadenza del PIN)")
    row1.pack(side="top", padx=60, pady=20)
    label1.pack(side="top")
    label2.pack(side="top")
    label3.pack(side="top")

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
    _center(widget)
    widget.mainloop()


def _center(widget):
    """ Center `widget` on the screen """
    screen_width = widget.winfo_screenwidth()
    screen_height = widget.winfo_screenheight()

    x = screen_width / 2 - widget.winfo_width() / 2
    # Little higher than center
    y = screen_height / 2 - widget.winfo_height()

    widget.geometry(f"+{int(x)}+{int(y)}")


def download_file(file_url):
    """Scarica il file dall'url passato come parametro

    :param file_url: Url dove scaricare il file
    :type file_url: str
    :return: Il path locale dove il file viene salvato
    :rtype: str
    """

    # get file name with random uuid
    file_name = str(uuid.uuid4())
    # get file content
    req = urllib.request.Request(file_url)
    req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36')

    url_resp = urllib.request.urlopen(req)
    content_type = url_resp.headers['content-type']
    guess_type = mimetypes.guess_extension(content_type).strip('.')
    url_content = url_resp.read()
    # create file locally
    if not path.exists(UPLOAD_FOLDER) or not path.isdir(UPLOAD_FOLDER):
        makedirs(UPLOAD_FOLDER)

    file_path = path.join(UPLOAD_FOLDER, '.'.join([file_name, guess_type]))
    with open(file_path, "wb") as _file:
        _file.write(url_content)

    return file_path


####################################################################
#       MAIN                                                       #
####################################################################
if __name__ == "__main__":
    log.info("App started. Check for resume...")
    sys_params = sys.argv[1:]
  #  sys_params = ['firmajr://B4F4940C-B901-526A-0890-9ECBD6FD0EB6;aHR0cDovLzEyNy4wLjAuMTo4MDgwL0RvY3RvckZhc2VuL1NlcnZlU2lnbkNvbmZpZ3VyYXRpb24=']
    handle_sign(sys_params)
    log.info("closing app")
