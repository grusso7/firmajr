from my_config_loader import MyConfigLoader
from my_logger import MyLogger
from os import listdir, devnull, fsdecode
from PyKCS11 import PyKCS11Lib, Mechanism, LowLevel
from asn1crypto.x509 import Certificate

####################################################################
#       CONFIGURATION                                              #
####################################################################
# driver directory
DRIVER_FOLDER = MyConfigLoader().get_server_config()["driver_folder"]
####################################################################
log = MyLogger().my_logger()


# custom exceptions
class SmartCardConnectionError(ConnectionError):
    """ Raised when something goes wrong with the smart card """
    pass


class SignatureUtils:

    @staticmethod
    def fetch_smart_card_sessions():
        """ Return a `session` list for the connected smart cards """

        log.info("loading drivers")
        pkcs11 = PyKCS11Lib()
        driver_loaded = False

        # try with default
        try:
            pkcs11.load()
            driver_loaded = True
        except:
            log.warning("no default driver")

        # anyway load known drivers
        for file in listdir(DRIVER_FOLDER):
            try:
                pkcs11.load(file)
                log.info(f"driver {fsdecode(file)} loaded")
                driver_loaded = True
            except:
                log.warning(
                    f"driver {fsdecode(file)} NOT loaded")
                continue

        # cannot load any driver file
        if not driver_loaded:
            raise SmartCardConnectionError("No driver found")

        slots = SignatureUtils._fetch_slots(pkcs11)

        sessions = []
        for slot in slots:
            try:
                session = pkcs11.openSession(
                    slot, LowLevel.CKS_RW_PUBLIC_SESSION)
                sessions.append(session)
            except:
                continue

        if len(sessions) < 1:
            raise SmartCardConnectionError("Can not open any session")

        return sessions

    @staticmethod
    def _fetch_slots(pkcs11_lib):
        """ Return a `slot list` (connected Smart Cards) """

        log.info("getting slots")
        try:
            slots = pkcs11_lib.getSlotList(tokenPresent=True)
            if len(slots) < 1:
                raise Exception()  # only to get to the external except block
            else:
                return slots
        except:
            raise SmartCardConnectionError("No smart card slot found")

    @staticmethod
    def close_session(session):
        """ Close smart card `session` """

        log.info("Close smart card session")
        session.closeSession()

    @staticmethod
    def user_login(sessions, pin):
        """
            User login on a `session` using `pin`

            Params:
                sessions: smart card session list
                pin: user pin

            Returns:
                the logged in session
        """

        log.info("user login")
        for session in sessions:
            try:
                session.login(pin)
                return session
            except:
                continue

        raise SmartCardConnectionError(
            "Can not login on any sessions provided")

    @staticmethod
    def user_logout(session):
        """
            User logout from a `session`

            Params:
                session: smart card session
        """

        log.info("user logout")
        session.logout()

    @staticmethod
    def fetch_certificate(session):
        """
            Return smart card certificate

            Params:
                session: smart card session
        """

        log.info("fetching certificate")
        try:
            certificates = session.findObjects(
                [(LowLevel.CKA_CLASS, LowLevel.CKO_CERTIFICATE)])
        except:
            raise SmartCardConnectionError("Certificate not found")

        certificate = None
        log.info("picking non_repudiation certificate")
        for cert in certificates:
            cert_value = SignatureUtils.get_certificate_value(session, cert)
            x509 = Certificate.load(cert_value)
            try:
                key_usage = x509.key_usage_value
                if 'non_repudiation' in key_usage.native:
                    certificate = cert
                    break
            except:
                log.info("key usage not found, skip this certificate")
                continue

        if certificate is None:
            log.info("non_repudiation certificate not found, pick the latest one")
            last_certificate_index = len(certificates) - 1
            certificate = certificates[last_certificate_index]

        return certificate

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
            certificate_value = session.getAttributeValue(
                certificate, [LowLevel.CKA_VALUE])[0]
        except:
            raise SmartCardConnectionError("Certificate has no valid value")

        return bytes(certificate_value)

    @staticmethod
    def get_certificate_issuer(session, certificate):
        """
            Return the issuer of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        """

        log.info("fetching certificate issuer")
        try:
            certificate_issuer = session.getAttributeValue(
                certificate, [LowLevel.CKA_ISSUER])[0]
        except:
            raise SmartCardConnectionError("Certificate has no valid issuer")

        return bytes(certificate_issuer)

    @staticmethod
    def get_certificate_serial_number(session, certificate):
        """
            Return the serial number of `certificate`

            Params:
                session: smart card session
                certificate: smart card certificate
        """

        log.info("fetching certificate serial number")
        try:
            serial_number = session.getAttributeValue(
                certificate, [LowLevel.CKA_SERIAL_NUMBER])[0]
        except:
            raise SmartCardConnectionError(
                "Certificate has no valid serial number")

        try:
            int_serial_number = int.from_bytes(
                serial_number, byteorder='big', signed=True)
        except:
            raise SmartCardConnectionError(
                "Can not cast certificate serial number to integer")
        return int_serial_number

    @staticmethod
    def fetch_private_key(session, certificate):
        """
            Return smart card private key reference

            Params:
                session: smart card session
                certificate: certificate connected to the key
        """

        log.info("fetching private key")
        try:
            # getting the certificate id
            identifier = session.getAttributeValue(
                certificate, [LowLevel.CKA_ID])[0]
            # same as the key id
            priv_key = session.findObjects([
                (LowLevel.CKA_CLASS, LowLevel.CKO_PRIVATE_KEY),
                (LowLevel.CKA_ID, identifier)])[0]
        except:
            raise SmartCardConnectionError(
                "Certificate has no valid private key")
        # if you don't print priv_key you get a sign general error -.-
        print(priv_key, file=open(devnull, "w"))  # to avoid general error
        return priv_key

    @staticmethod
    def fetch_public_key(session, certificate):
        """
            Return smart card public key reference

            Params:
                session: smart card session
                certificate: certificate connected to the key
        """

        log.info("fetching public key")
        try:
            # getting the certificate id
            identifier = session.getAttributeValue(
                certificate, [LowLevel.CKA_ID])[0]
            # same as the key id
            pub_key = session.findObjects([
                (LowLevel.CKA_CLASS, LowLevel.CKO_PUBLIC_KEY),
                (LowLevel.CKA_ID, identifier)])[0]
        except:
            raise SmartCardConnectionError(
                "Certificate has no valid public key")
        return pub_key

    @staticmethod
    def digest(session, content):
        """
            Return `content` hash

            Params:
                session: smart card session
                content: content to hash
        """

        log.info("hashing content")
        try:
            digest = session.digest(content, Mechanism(LowLevel.CKM_SHA256))
        except:
            raise SmartCardConnectionError("Failed on digest content")

        return bytes(digest)

    @staticmethod
    def signature(session, priv_key, content):
        """
            Sign `content` with `privKey` reference

            Reurn:
                signature in bytearray

            Params:
                session: smart card session.
                privKey: reference to the smart card private key.
                content: bytes to hash and sign
        """

        log.info("signing content")
        try:
            signature = session.sign(priv_key, content, Mechanism(
                LowLevel.CKM_SHA256_RSA_PKCS, None))
        except:
            raise SmartCardConnectionError("Failed on sign content")

        return bytes(signature)
