import json
from base64 import b64encode
from os import environ

from my_logger import MyLogger
from requests import post
from singleton_type import SingletonType

log = MyLogger().my_logger()


class RevocationChecker(object, metaclass=SingletonType):
    def __init__(self):
        # Certificate revocation_checker endpoint
        # checker_host = MyConfigLoader().get_revocation_checker_config()["host"]
        # checker_port = MyConfigLoader().get_revocation_checker_config()["port"]
        # self.cheker_endpoint = f"http://{checker_host}:{checker_port}/"

        # certificate statuses
        self.GOOD = "GOOD"
        self.UNKNOWN = "UNKNOWN"
        self.REVOKED = "REVOKED"
        self.ERROR = "ERROR"

    def check(self, revocation_checker_url, certificate_value, params):
        try:
            payload = {"certificate": b64encode(certificate_value), "params": json.dumps(params)}
            # if "HTTP_PROXY" in environ:
            #     del environ["HTTP_PROXY"]
            res = post(url=revocation_checker_url + "check", data=payload)
        except:
            log.warning(f"Trouble connecting to revocation_checker_server")
            return self.ERROR

        if not res.json():
            log.warning(f"Revocation checker server returned a bad response")
            return self.ERROR

        if res.status_code != 200:
            if "message" not in res.json():
                log.warning(f"Missing message json field")
                return self.ERROR
            error_message = res.json()["message"]

            check_res = self.UNKNOWN
            log.warning(f"Revocation checker server returned status code {res.status_code}")
            log.warning(f"Associated error message: {error_message}")
        else:
            if "status" not in res.json():
                log.warning(f"Missing status json field")
                return self.ERROR
            check_res = res.json()

        return check_res
