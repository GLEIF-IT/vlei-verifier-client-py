from dataclasses import dataclass


@dataclass
class VerifierResponse:
    code: int
    message: str
    body: dict