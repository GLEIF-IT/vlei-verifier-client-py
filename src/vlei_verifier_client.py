import json
import logging
import requests
import sys
from dataclasses import dataclass



# Create a logger object.
logger = logging.getLogger(__name__)

# Configure the logger to write messages to stdout.
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# Set the log level to include all messages.

logger.setLevel(logging.DEBUG)


@dataclass
class VerifierResponse:
    code: int
    message: str
    body: dict


class _VerifierServiceAdapter:
    def __init__(self, verifier_base_url: str = "http://localhost:7676"):
        self.verifier_base_url = verifier_base_url

        self.auths_url = f"{self.verifier_base_url}/authorizations/"
        self.presentations_url = f"{self.verifier_base_url}/presentations/"
        self.reports_url = f"{self.verifier_base_url}/reports/"
        self.verify_signed_headers_url = f"{self.verifier_base_url}/request/verify/"
        self.verify_signature_url = f"{self.verifier_base_url}/signature/verify/"
        self.add_rot_url = f"{self.verifier_base_url}/root_of_trust/"

    def check_login_request(self, aid: str) -> requests.Response:
        logger.info(f"Check login request sent with: aid = {aid}")
        res = requests.get(
            f"{self.auths_url}{aid}", headers={"Content-Type": "application/json"}
        )
        logger.info(f"login status: {json.dumps(res.json())}")
        return res

    def credential_presentation_request(self, said: str, vlei: str) -> requests.Response:
        logger.info(f"Credential presentation request sent with: said = {said}")
        res = requests.put(
            f"{self.presentations_url}{said}",
            headers={"Content-Type": "application/json+cesr"},
            data=vlei,
        )
        logger.info(f"Credential presentation response for said = {said}:  {json.dumps(res.json())}")
        return res

    def verify_signed_headers_request(self, aid, sig, ser) -> requests.Response:
        logger.info(
            f"Signed headers verification request sent with aid = {aid}, sig = {sig}, ser = {ser}"
        )
        res = requests.post(f"{self.verify_signed_headers_url}{aid}", params={"sig": sig, "data": ser})
        logger.info(
            f"Signed headers verification response for aid = {aid}, sig = {sig}, ser = {ser}:  {json.dumps(res.json())}")
        return res

    def verify_signature_request(self, signature, submitter, digest):
        logger.info(
            f"Signature verification request sent with signature = {signature}, submitter = {submitter}, digest = {digest}"
        )
        payload = {
            "signature": signature,
            "signer_aid": submitter,
            "non_prefixed_digest": digest
        }
        res = requests.post(self.verify_signature_url, json=payload)
        return res

    def add_root_of_trust_request(self, aid, vlei, oobi) -> requests.Response:
        logger.info(f"Add root of trust request send with: aid = {aid}, vlei = {vlei}, oobi = {oobi}")
        payload = {
            "vlei": vlei,
            "oobi": oobi
        }
        res = requests.post(f"{self.add_rot_url}{aid}", headers={"Content-Type": "application/json"}, json=payload)
        logger.info(
            f"Add root of trust response for aid = {aid}, vlei = {vlei}, oobi = {oobi}:  {json.dumps(res.json())}")
        return res


class VerifierClient:
    """
    A client to interact with the vlei-verifier service for authentication, credential presentation,
    signature verification, and root of trust management.

    Attributes:
        verifier_base_url (str): The base URL of the Verifier service. Defaults to "http://localhost:7676".
        verifier_service_adapter (_VerifierServiceAdapter): Adapter for interacting with the Verifier service.
    """

    def __init__(self, verifier_base_url: str = "http://localhost:7676"):
        """
        Initializes the VerifierClient with a specified base URL.

        Args:
            verifier_base_url (str): The base URL of the vlei-verifier service. Defaults to "http://localhost:7676".
        """
        self.verifier_base_url = verifier_base_url
        self.verifier_service_adapter = _VerifierServiceAdapter(self.verifier_base_url)

    def check_login(self, aid: str) -> VerifierResponse:
        """
        Checks if the provided AID is logged in.

        Args:
            aid (str): AID to check.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = self.verifier_service_adapter.check_login_request(aid)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response

    def login(self, said: str, vlei: str) -> VerifierResponse:
        """
        Submits a credential presentation request to log in using vLEI credentials.

        Args:
            said (str): SAID of the credential.
            vlei (str): The vLEI credential data.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = self.verifier_service_adapter.credential_presentation_request(said, vlei)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response

    def verify_signed_headers(self, aid: str, sig: str, ser: str) -> VerifierResponse:
        """
        Verifies signed headers for a request.

        Args:
            aid (str): AID of the signer.
            sig (str): The signature of the headers.
            ser (str): The serialized headers to verify.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = self.verifier_service_adapter.verify_signed_headers_request(aid, sig, ser)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response

    def add_root_of_trust(self, aid: str, vlei: str, oobi: str) -> VerifierResponse:
        """
        Adds a root of trust to the Verifier.

        Args:
            aid (str): AID of the root of trust.
            vlei (str): The root of trust vLEI credential.
            oobi (str): The OOBI data for the root of trust.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = self.verifier_service_adapter.add_root_of_trust_request(aid, vlei, oobi)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response

    def verify_signature(self, signature: str, signer_aid: str, non_prefixed_digest: str) -> VerifierResponse:
        """
        Verifies a signature for the given signer AID and digest.

        Args:
            signature (str): The signature to verify.
            signer_aid (str): AID of the signer.
            non_prefixed_digest (str): The digest of the data being verified, without prefix.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = self.verifier_service_adapter.verify_signature_request(signature, signer_aid, non_prefixed_digest)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response
