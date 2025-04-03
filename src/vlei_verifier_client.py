import json
import logging
import sys
from dataclasses import dataclass
import aiohttp
import requests

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
        self.presentations_history_url = f"{self.verifier_base_url}/presentations/history/"
        self.reports_url = f"{self.verifier_base_url}/reports/"
        self.verify_signed_headers_url = f"{self.verifier_base_url}/request/verify/"
        self.verify_signature_url = f"{self.verifier_base_url}/signature/verify/"
        self.add_rot_url = f"{self.verifier_base_url}/root_of_trust/"

    def authorization_request(self, aid: str, headers) -> requests.Response:
        logger.info(f"Authorization request sent with: aid = {aid}")
        res = requests.get(
            f"{self.auths_url}{aid}", headers={"Content-Type": "application/json", **headers}
        )
        logger.info(f"Authorization status: {json.dumps(res.json())}")
        return res

    def presentation_request(self, said: str, vlei: str) -> requests.Response:
        logger.info(f"Presentation request sent with: said = {said}")
        res = requests.put(
            f"{self.presentations_url}{said}",
            headers={"Content-Type": "application/json+cesr"},
            data=vlei,
        )
        logger.info(f"Presentation response for said = {said}:  {json.dumps(res.json())}")
        return res

    def presentations_history_request(self, aid: str) -> requests.Response:
        logger.info(f"Presentation history request sent with: aid = {aid}")
        res = requests.get(f"{self.presentations_history_url}{aid}", headers={"Content-Type": "application/json"})
        logger.info(f"Presentation history response for aid = {aid}:  {json.dumps(res.json())}")
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


class _AsyncVerifierServiceAdapter:
    def __init__(self, verifier_base_url: str = "http://localhost:7676"):
        self.verifier_base_url = verifier_base_url

        self.auths_url = f"{self.verifier_base_url}/authorizations/"
        self.presentations_url = f"{self.verifier_base_url}/presentations/"
        self.reports_url = f"{self.verifier_base_url}/reports/"
        self.verify_signed_headers_url = f"{self.verifier_base_url}/request/verify/"
        self.verify_signature_url = f"{self.verifier_base_url}/signature/verify/"
        self.add_rot_url = f"{self.verifier_base_url}/root_of_trust/"

    async def authorization_request(self, aid: str, headers) -> aiohttp.ClientResponse:
        logger.info(f"Authorization request sent with: aid = {aid}")
        url = f"{self.auths_url}{aid}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"Content-Type": "application/json", **headers}) as response:
                data = await response.json()
                logger.info(f"Authorization status: {json.dumps(data)}")
                return response

    async def presentation_request(self, said: str, vlei: str) -> aiohttp.ClientResponse:
        logger.info(f"Presentation request sent with: said = {said}")
        url = f"{self.presentations_url}{said}"
        async with aiohttp.ClientSession() as session:
            async with session.put(url, headers={"Content-Type": "application/json+cesr"}, data=vlei) as response:
                data = await response.json()
                logger.info(f"Presentation response for said = {said}:  {json.dumps(data)}")
                return response

    async def presentations_history_request(self, aid: str) -> aiohttp.ClientResponse:
        logger.info(f"Presentation history request sent with: aid = {aid}")
        url = f"{self.verifier_base_url}{aid}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"Content-Type": "application/json"}) as response:
                data = await response.json()
                logger.info(f"Presentation history response for aid = {aid}:  {json.dumps(data)}")
                return response

    async def verify_signed_headers_request(self, aid: str, sig: str, ser: str) -> aiohttp.ClientResponse:
        logger.info(
            f"Signed headers verification request sent with aid = {aid}, sig = {sig}, ser = {ser}"
        )
        url = f"{self.verify_signed_headers_url}{aid}"
        params = {"sig": sig, "data": ser}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, params=params) as response:
                data = await response.json()
                logger.info(
                    f"Signed headers verification response for aid = {aid}, sig = {sig}, ser = {ser}:  {json.dumps(data)}")
                return response

    async def verify_signature_request(self, signature: str, submitter: str, digest: str) -> aiohttp.ClientResponse:
        logger.info(
            f"Signature verification request sent with signature = {signature}, submitter = {submitter}, digest = {digest}"
        )
        url = self.verify_signature_url
        payload = {
            "signature": signature,
            "signer_aid": submitter,
            "non_prefixed_digest": digest
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                return response

    async def add_root_of_trust_request(self, aid: str, vlei: str, oobi: str) -> aiohttp.ClientResponse:
        logger.info(f"Add root of trust request sent with: aid = {aid}, vlei = {vlei}, oobi = {oobi}")
        url = f"{self.add_rot_url}{aid}"
        payload = {
            "vlei": vlei,
            "oobi": oobi
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers={"Content-Type": "application/json"}, json=payload) as response:
                data = await response.json()
                logger.info(
                    f"Add root of trust response for aid = {aid}, vlei = {vlei}, oobi = {oobi}:  {json.dumps(data)}")
                return response


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

    def authorization(self, aid: str, headers: dict[str, str] = None) -> VerifierResponse:
        """
        Checks if the provided AID is authorized.

        Args:
            aid (str): AID to check.
            headers: Signed headers.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        headers = headers or {}
        res = self.verifier_service_adapter.authorization_request(aid, headers)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response

    def presentation(self, said: str, vlei: str) -> VerifierResponse:
        """
        Submits a presentation request to log in using vLEI credentials.

        Args:
            said (str): SAID of the credential.
            vlei (str): The vLEI credential data.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = self.verifier_service_adapter.presentation_request(said, vlei)
        response = VerifierResponse(
            code=res.status_code,
            body=res.json(),
            message=res.json()["msg"],
        )
        return response

    def get_presentations_history(self, aid: str) -> VerifierResponse:
        res = self.verifier_service_adapter.presentations_history_request(aid)
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


class AsyncVerifierClient:
    """
    An asynchronous client to interact with the vlei-verifier service for authentication, credential presentation,
    signature verification, and root of trust management.

    Attributes:
        verifier_base_url (str): The base URL of the Verifier service. Defaults to "http://localhost:7676".
        verifier_service_adapter (_AsyncVerifierServiceAdapter): Adapter for interacting with the Verifier service asynchronously.
    """

    def __init__(self, verifier_base_url: str = "http://localhost:7676"):
        """
        Initializes the AsyncVerifierClient with a specified base URL.

        Args:
            verifier_base_url (str): The base URL of the vlei-verifier service. Defaults to "http://localhost:7676".
        """
        self.verifier_base_url = verifier_base_url
        self.verifier_service_adapter = _AsyncVerifierServiceAdapter(self.verifier_base_url)

    async def authorization(self, aid: str, headers: dict[str, str] = None) -> VerifierResponse:
        """
        Asynchronously checks if the provided AID is logged in.

        Args:
            aid (str): AID to check.
            headers: Signed headers.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        headers = headers or {}
        res = await self.verifier_service_adapter.authorization_request(aid, headers)
        data = await res.json()
        return VerifierResponse(
            code=res.status,
            body=data,
            message=data["msg"],
        )

    async def presentation(self, said: str, vlei: str) -> VerifierResponse:
        """
        Asynchronously submits a credential presentation request to log in using vLEI credentials.

        Args:
            said (str): SAID of the credential.
            vlei (str): The vLEI credential data.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = await self.verifier_service_adapter.presentation_request(said, vlei)
        data = await res.json()
        return VerifierResponse(
            code=res.status,
            body=data,
            message=data["msg"],
        )

    async def get_presentations_history(self, aid) -> VerifierResponse:
        res = await self.verifier_service_adapter.presentations_history_request(aid)
        data = await res.json()
        return VerifierResponse(
            code=res.status,
            body=data,
            message=data["msg"],
        )

    async def verify_signed_headers(self, aid: str, sig: str, ser: str) -> VerifierResponse:
        """
        Asynchronously verifies signed headers for a request.

        Args:
            aid (str): AID of the signer.
            sig (str): The signature of the headers.
            ser (str): The serialized headers to verify.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = await self.verifier_service_adapter.verify_signed_headers_request(aid, sig, ser)
        data = await res.json()
        return VerifierResponse(
            code=res.status,
            body=data,
            message=data["msg"],
        )

    async def add_root_of_trust(self, aid: str, vlei: str, oobi: str) -> VerifierResponse:
        """
        Asynchronously adds a root of trust to the Verifier.

        Args:
            aid (str): AID of the root of trust.
            vlei (str): The root of trust vLEI credential.
            oobi (str): The OOBI data for the root of trust.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = await self.verifier_service_adapter.add_root_of_trust_request(aid, vlei, oobi)
        data = await res.json()
        return VerifierResponse(
            code=res.status,
            body=data,
            message=data["msg"],
        )

    async def verify_signature(self, signature: str, signer_aid: str, non_prefixed_digest: str) -> VerifierResponse:
        """
        Asynchronously verifies a signature for the given signer AID and digest.

        Args:
            signature (str): The signature to verify.
            signer_aid (str): AID of the signer.
            non_prefixed_digest (str): The digest of the data being verified, without prefix.

        Returns:
            code: The response code from the Verifier service.
            body: The JSON response from the Verifier service.
            message: The response message from the Verifier service.
        """
        res = await self.verifier_service_adapter.verify_signature_request(signature, signer_aid, non_prefixed_digest)
        data = await res.json()
        return VerifierResponse(
            code=res.status,
            body=data,
            message=data["msg"],
        )