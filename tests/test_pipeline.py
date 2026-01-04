import unittest

from app.pipeline import (
    ResponsePipeline,
    FALLBACK_TEXT,
    SENSITIVE_TEXT,
    INSUFFICIENT_SEARCH_TEXT,
    DEFAULT_SOURCE_URL,
)


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pipeline = ResponsePipeline()

    def test_pipeline_returns_trusted_sources_for_phishing(self):
        response = self.pipeline.generate(
            user_input="How do I spot a phishing email?",
            channel="test",
            session_id="tester",
        )
        self.assertIn("phishing", response.answer.lower())
        self.assertTrue(response.sources and response.sources[0] != "N/A")

    def test_pipeline_handles_sensitive_input(self):
        response = self.pipeline.generate(
            user_input="My password is Hunter2",
            channel="test",
            session_id="tester",
        )
        self.assertEqual(response.answer, SENSITIVE_TEXT)
        self.assertEqual(response.sources, [DEFAULT_SOURCE_URL])

    def test_pipeline_fallback_when_no_match(self):
        response = self.pipeline.generate(
            user_input="quantum banana wallpaper",
            channel="test",
            session_id="tester",
        )
        self.assertIn(response.answer, {INSUFFICIENT_SEARCH_TEXT, FALLBACK_TEXT})
        self.assertTrue(response.sources)


if __name__ == "__main__":
    unittest.main()
