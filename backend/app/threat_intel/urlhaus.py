import logging
import os

import httpx

logger = logging.getLogger(__name__)
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


def check_urlhaus(url: str) -> dict:
    auth_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        return {
            "status": "unavailable",
            "match": None,
            "detail": (
                "URLhaus requires an Auth-Key. Configure URLHAUS_AUTH_KEY to enable "
                "threat-feed lookups."
            ),
            "source": "URLhaus",
        }

    try:
        response = httpx.post(
            URLHAUS_ENDPOINT,
            headers={"Auth-Key": auth_key},
            data={"url": url},
            timeout=5.0,
            follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.TimeoutException:
        logger.info("URLhaus request timed out")
        return {
            "status": "unavailable",
            "match": None,
            "detail": "URLhaus did not respond before the timeout.",
            "source": "URLhaus",
        }
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code
        if status_code in {401, 403}:
            logger.warning("URLhaus rejected the configured Auth-Key (HTTP %s)", status_code)
            detail = (
                "URLhaus rejected URLHAUS_AUTH_KEY. Check or regenerate the key in "
                "the abuse.ch Authentication Portal."
            )
        else:
            logger.warning("URLhaus returned HTTP %s", status_code)
            detail = "URLhaus could not be reached or returned an error."
        return {
            "status": "unavailable",
            "match": None,
            "detail": detail,
            "source": "URLhaus",
        }
    except httpx.HTTPError:
        logger.warning("URLhaus request failed")
        return {
            "status": "unavailable",
            "match": None,
            "detail": "URLhaus could not be reached or returned an error.",
            "source": "URLhaus",
        }
    except ValueError:
        logger.warning("URLhaus returned invalid JSON", exc_info=True)
        return {
            "status": "unavailable",
            "match": None,
            "detail": "URLhaus returned an unreadable response.",
            "source": "URLhaus",
        }

    if not isinstance(payload, dict):
        return {
            "status": "unavailable",
            "match": None,
            "detail": "URLhaus returned an unreadable response.",
            "source": "URLhaus",
        }

    query_status = payload.get("query_status")
    if query_status == "ok":
        return {
            "status": "match",
            "match": True,
            "detail": "URLhaus reports a known malicious URL match.",
            "source": "URLhaus",
            "threat": payload.get("threat"),
        }
    if query_status == "no_results":
        return {
            "status": "no_match",
            "match": False,
            "detail": "URLhaus returned no known match; this is not proof of safety.",
            "source": "URLhaus",
        }
    return {
        "status": "unavailable",
        "match": None,
        "detail": "URLhaus returned an unrecognized query status.",
        "source": "URLhaus",
    }
