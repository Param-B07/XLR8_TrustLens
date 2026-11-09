import json

from google import genai

from app.analysis import ai


def test_gemini_output_is_structured_and_quotes_are_validated(monkeypatch) -> None:
    captured = {}

    class FakeModels:
        def generate_content(self, **kwargs):
            captured.update(kwargs)
            return type(
                "Response",
                (),
                {
                    "text": json.dumps(
                        {
                            "cues": [
                                {"type": "urgency", "quote": "act now"},
                                {"type": "urgency", "quote": "not in message"},
                                {"type": "instruction", "quote": "act now"},
                            ]
                        }
                    )
                },
            )()

    class FakeClient:
        def __init__(self, api_key: str) -> None:
            assert api_key == "test-key"
            self.models = FakeModels()

        def close(self) -> None:
            pass

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(genai, "Client", FakeClient)
    result = ai.suggest_language_cues("Please act now.")
    assert result == {
        "status": "available",
        "cues": [{"type": "urgency", "quote": "act now"}],
    }
    assert captured["config"].response_mime_type == "application/json"
    assert "UNTRUSTED_MESSAGE_" in captured["contents"]


def test_message_analysis_redacts_email_and_phone_before_ai(monkeypatch) -> None:
    from app.analysis import messages

    captured = {}

    def fake_ai(text: str) -> dict:
        captured["text"] = text
        return {"status": "not_configured", "cues": []}

    monkeypatch.setattr(messages, "suggest_language_cues", fake_ai)
    report = messages.analyze_message(
        "Contact user@example.com at +1 (202) 555-0123, see https://example.com/secret."
    )
    assert "user@example.com" not in captured["text"]
    assert "202" not in captured["text"]
    assert "[REDACTED_EMAIL]" in captured["text"]
    assert "[REDACTED_PHONE]" in captured["text"]
    assert "https://example.com/secret" not in captured["text"]
    assert "[REDACTED_URL]" in captured["text"]
    assert report["technical_evidence"]["extracted_emails"] == ["user@example.com"]
