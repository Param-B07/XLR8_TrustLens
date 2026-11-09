import json
import logging
import os
from datetime import datetime
from pathlib import Path

from web3 import Web3
from web3.contract import Contract
from web3.exceptions import Web3Exception

from app.analysis.risk import RISK_TIERS, report_sha256

logger = logging.getLogger(__name__)
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_PATH = (
    WORKSPACE_ROOT
    / "contracts"
    / "artifacts"
    / "contracts"
    / "ThreatRegistry.sol"
    / "ThreatRegistry.json"
)
DEFAULT_DEPLOYMENT_PATH = WORKSPACE_ROOT / "contracts" / "deployments" / "localhost.json"


class RegistryError(RuntimeError):
    pass


class RegistryConflictError(RegistryError):
    pass


class RegistryIntegrityError(RegistryError):
    pass


def _report_digest(value: str) -> bytes:
    normalized = value[2:] if value.startswith("0x") else value
    try:
        digest = bytes.fromhex(normalized)
    except ValueError as exc:
        raise RegistryError("Report hash must be a 32-byte hexadecimal SHA-256 digest.") from exc
    if len(digest) != 32:
        raise RegistryError("Report hash must be a 32-byte hexadecimal SHA-256 digest.")
    return digest


def _report_timestamp(value: str) -> int:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegistryError("Report timestamp is invalid.") from exc
    if timestamp.tzinfo is None:
        raise RegistryError("Report timestamp must include a timezone.")
    result = int(timestamp.timestamp())
    if result <= 0 or result > (1 << 64) - 1:
        raise RegistryError("Report timestamp is outside the supported range.")
    return result


def _load_deployment_address() -> str:
    configured_address = os.environ.get("REGISTRY_CONTRACT_ADDRESS")
    if configured_address:
        return configured_address

    deployment_path = Path(
        os.environ.get("REGISTRY_DEPLOYMENT_FILE", str(DEFAULT_DEPLOYMENT_PATH))
    )
    try:
        with deployment_path.open(encoding="utf-8") as deployment_file:
            deployment = json.load(deployment_file)
    except FileNotFoundError as exc:
        raise RegistryError(
            "Registry deployment is missing; deploy ThreatRegistry or configure REGISTRY_CONTRACT_ADDRESS."
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError("Registry deployment file could not be read.") from exc
    address = deployment.get("contractAddress") if isinstance(deployment, dict) else None
    if not isinstance(address, str) or not address:
        raise RegistryError("Registry deployment file has no contract address.")
    return address


def _connect() -> tuple[Web3, Contract, str]:
    rpc_url = os.environ.get("WEB3_RPC_URL", "http://127.0.0.1:8545")
    web3 = Web3(
        Web3.HTTPProvider(
            rpc_url,
            request_kwargs={"timeout": 5},
        )
    )
    try:
        if not web3.is_connected():
            raise RegistryError("Local EVM node is not reachable.")
        address = Web3.to_checksum_address(_load_deployment_address())
    except (OSError, ValueError, Web3Exception) as exc:
        if isinstance(exc, RegistryError):
            raise
        logger.warning("Could not connect to the threat registry", exc_info=True)
        raise RegistryError("Threat registry is unavailable or misconfigured.") from exc

    artifact_path = Path(
        os.environ.get("REGISTRY_ARTIFACT_PATH", str(DEFAULT_ARTIFACT_PATH))
    )
    try:
        with artifact_path.open(encoding="utf-8") as artifact_file:
            artifact = json.load(artifact_file)
    except FileNotFoundError as exc:
        raise RegistryError("ThreatRegistry artifact is missing; compile the contract first.") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError("ThreatRegistry artifact could not be read.") from exc
    abi = artifact.get("abi") if isinstance(artifact, dict) else None
    if not isinstance(abi, list):
        raise RegistryError("ThreatRegistry artifact has no ABI.")
    try:
        if not web3.eth.get_code(address):
            raise RegistryError("No contract is deployed at the configured registry address.")
    except RegistryError:
        raise
    except (OSError, ValueError, Web3Exception) as exc:
        logger.warning("Could not inspect registry contract code", exc_info=True)
        raise RegistryError("Threat registry is unavailable or misconfigured.") from exc
    return web3, web3.eth.contract(address=address, abi=abi), address


def _event_transaction_hash(contract: Contract, report_id: str) -> str:
    try:
        events = contract.events.ReportCommitted().get_logs(
            from_block=0,
            to_block="latest",
        )
    except (OSError, ValueError, Web3Exception) as exc:
        logger.warning("Could not retrieve registry event for %s", report_id, exc_info=True)
        raise RegistryError("Registry transaction event could not be retrieved.") from exc
    for event in reversed(events):
        if event["args"]["reportId"] == report_id:
            return "0x" + bytes(event["transactionHash"]).hex()
    raise RegistryError("Registry record exists but its transaction event was not found.")


def commit_report(report: dict) -> dict:
    required = ("report_id", "report_hash", "risk_level", "analysis_timestamp")
    if any(not isinstance(report.get(key), str) or not report[key] for key in required):
        raise RegistryError("Report is missing required commitment fields.")
    if report["risk_level"] not in RISK_TIERS:
        raise RegistryError("Report has an unsupported risk level.")
    if report_sha256(report) != report["report_hash"]:
        raise RegistryIntegrityError(
            "Report integrity check failed; refusing to commit altered data."
        )

    digest = _report_digest(report["report_hash"])
    timestamp = _report_timestamp(report["analysis_timestamp"])
    web3, contract, contract_address = _connect()

    try:
        existing = contract.functions.getReport(report["report_id"]).call()
        if existing[4]:
            existing_matches = (
                bytes(existing[0]) == digest
                and existing[1] == report["risk_level"]
                and existing[2] == timestamp
            )
            if not existing_matches:
                raise RegistryConflictError(
                    "This report ID already has a different on-chain commitment."
                )
            transaction_hash = _event_transaction_hash(contract, report["report_id"])
            return {
                "report_id": report["report_id"],
                "report_hash": "0x" + digest.hex(),
                "risk_level": report["risk_level"],
                "timestamp": timestamp,
                "reporter_address": Web3.to_checksum_address(existing[3]),
                "contract_address": contract_address,
                "transaction_hash": transaction_hash,
                "already_committed": True,
            }

        private_key = os.environ.get("REGISTRY_PRIVATE_KEY")
        if not private_key:
            raise RegistryError("REGISTRY_PRIVATE_KEY is required to commit reports.")
        account = web3.eth.account.from_key(private_key)
        function = contract.functions.registerReport(
            report["report_id"],
            digest,
            report["risk_level"],
            timestamp,
        )
        nonce = web3.eth.get_transaction_count(account.address)
        gas_price = web3.eth.gas_price
        estimated_gas = function.estimate_gas({"from": account.address})
        transaction = function.build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "chainId": web3.eth.chain_id,
                "gas": max(estimated_gas * 6 // 5, 100_000),
                "gasPrice": gas_price,
            }
        )
        signed = web3.eth.account.sign_transaction(transaction, private_key=private_key)
        transaction_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(transaction_hash, timeout=30)
        if receipt["status"] != 1:
            raise RegistryError("Threat registry transaction was reverted.")
    except RegistryError:
        raise
    except (OSError, ValueError, Web3Exception) as exc:
        logger.warning("Could not commit report %s to the registry", report["report_id"], exc_info=True)
        raise RegistryError("Report could not be committed to the threat registry.") from exc

    return {
        "report_id": report["report_id"],
        "report_hash": "0x" + digest.hex(),
        "risk_level": report["risk_level"],
        "timestamp": timestamp,
        "reporter_address": Web3.to_checksum_address(account.address),
        "contract_address": contract_address,
        "transaction_hash": "0x" + bytes(transaction_hash).hex(),
        "already_committed": False,
    }


def verify_report(report_id: str, report_hash: str) -> dict:
    digest = _report_digest(report_hash)
    web3, contract, contract_address = _connect()
    try:
        commitment = contract.functions.getReport(report_id).call()
        if not commitment[4]:
            return {
                "report_id": report_id,
                "exists": False,
                "matches": False,
                "contract_address": contract_address,
                "transaction_hash": None,
            }
        transaction_hash = _event_transaction_hash(contract, report_id)
        return {
            "report_id": report_id,
            "exists": True,
            "matches": bytes(commitment[0]) == digest,
            "report_hash": "0x" + bytes(commitment[0]).hex(),
            "risk_level": commitment[1],
            "timestamp": commitment[2],
            "reporter_address": Web3.to_checksum_address(commitment[3]),
            "contract_address": contract_address,
            "transaction_hash": transaction_hash,
        }
    except RegistryError:
        raise
    except (OSError, ValueError, Web3Exception) as exc:
        logger.warning("Could not verify report %s against the registry", report_id, exc_info=True)
        raise RegistryError("Report could not be verified against the threat registry.") from exc
