import digital_signature
import tkinter as tk
import tkinter.ttk as ttk
import time
import sys
from pyupdater.client import Client
from client_config import ClientConfig
from my_logger import MyLogger

log = MyLogger().my_logger()
CLIENT_CONFIG = ClientConfig()
progbar = None
root = None


class UpdateStatus(object):
    """Enumerated data type"""
    # pylint: disable=invalid-name
    # pylint: disable=too-few-public-methods
    UNKNOWN = 0
    NO_AVAILABLE_UPDATES = 1
    UPDATE_DOWNLOAD_FAILED = 2
    EXTRACTING_UPDATE_AND_RESTARTING = 3
    UPDATE_AVAILABLE_BUT_APP_NOT_FROZEN = 4
    COULDNT_CHECK_FOR_UPDATES = 5


UPDATE_STATUS_STR = \
    ['Unknown', 'No available updates were found.',
     'Update download failed.', 'Extracting update and restarting.',
     'Update available but application is not frozen.',
     'Couldn\'t check for updates.']


def check_for_updates(rev_checker_url=None):
    """Controllo nuovi aggiornamenti.

    :param update_checker_url: Url server degli aggiornamenti, defaults to None
    :type update_checker_url: str, optional
    :return: UpdateObject utilizzato per aggiornare i binari
    :rtype: AppUpdate
    """
    assert CLIENT_CONFIG.PUBLIC_KEY is not None
    # Se update_checker_url è presente nel json, allora il controllo degli aggiornamenti viene
    # fatto su quell'URL altrimenti prendo il default dal file di configurazione
    if rev_checker_url is not None:
        CLIENT_CONFIG.UPDATE_URLS[0] = rev_checker_url + "deploy/"
    client = Client(CLIENT_CONFIG, refresh=True, progress_hooks=[progress])
    log.info("Actual client version: %s" % digital_signature.__version__)
    appUpdate = client.update_check(CLIENT_CONFIG.APP_NAME,
                                    digital_signature.__version__,
                                    channel='stable')
    return appUpdate


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


def progress(data):
    global progbar
    global root

    if progbar is None:
        root = tk.Tk()
        # root.geometry('250x60+100+100')
        root.title('Aggiornamento...')
        step = tk.DoubleVar()
        step.set(0)

        frame = tk.Frame()
        frame.pack(fill=tk.BOTH, padx=2, pady=2)

        lbl = tk.Label(frame, text="Aggiornamento in corso, attendere prego...")
        lbl.pack()
        progbar = ttk.Progressbar(
            frame,
            orient=tk.HORIZONTAL,
            mode='determinate',
            variable=step)
        progbar.pack(fill=tk.X, expand=True)
        log.info('Downloading udpdate')
        root.attributes("-topmost", True)
        root.protocol("WM_DELETE_WINDOW", _on_closing)
        _center(root)
        root.update()

    n = int(float(data['percent_complete']))
    log.info('Percent complete: %2d' % n)
    progbar['value'] = n
    time.sleep(.2)
    root.update()


def _center(widget):
    """ Center `widget` on the screen """
    screen_width = widget.winfo_screenwidth()
    screen_height = widget.winfo_screenheight()

    x = screen_width / 2 - widget.winfo_width() / 2
    # Little higher than center
    y = screen_height / 2 - widget.winfo_height() / 2

    widget.geometry(f"+{int(x) - 100}+{int(y)}")


def _on_closing():
    pass


def UpdatePyUpdaterClientConfig(revocation_checker_url):
    updateUrl = revocation_checker_url
    CLIENT_CONFIG.UPDATE_URLS = [updateUrl]
