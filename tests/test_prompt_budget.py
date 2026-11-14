import json
import unittest

from mimic import codegen


def endpoint(path, response):
    return {
        "method": "GET",
        "path": path,
        "status": 200,
        "statuses": [200],
        "sample_count": 1,
        "raw_paths": [path],
        "schemas": {"responses": {"2xx": {"type": "object"}}},
        "samples": [
            {
                "path": path,
                "query": "",
                "status": 200,
                "request": {"kind": "empty", "size_bytes": 0},
                "response": {
                    "kind": "json",
                    "size_bytes": len(json.dumps(response).encode()),
                    "value": response,
                },
                "request_body": "",
                "response_body": json.dumps(response),
            }
        ],
        "query": "",
        "request_body": "",
        "response_body": json.dumps(response),
    }


def detail_record(digest):
    details = digest.split(
        "Endpoint details (one complete JSON object per record):\n", 1
    )[1].split("\nCapture budget summary:", 1)[0]
    return json.loads(details)


class PromptBudgetTests(unittest.TestCase):
    def test_oversized_json_is_omitted_as_a_complete_value(self):
        digest = codegen.build_digest(
            [endpoint("/large", {"payload": "x" * 50000})],
            max_endpoint_bytes=4096,
            max_digest_bytes=8192,
        )

        record = detail_record(digest)

        self.assertLessEqual(len(json.dumps(record).encode()), 4096)
        self.assertEqual(
            record["samples"][0]["response"]["omitted"],
            "JSON value exceeds endpoint byte budget",
        )
        self.assertNotIn("value", record["samples"][0]["response"])

    def test_prompt_is_bounded_by_utf8_bytes(self):
        endpoints = [
            endpoint(f"/items/{index}", {"text": "🙂" * 4000})
            for index in range(20)
        ]

        prompt = codegen.build_prompt(
            "api.example.com",
            endpoints,
            max_endpoint_bytes=4096,
            max_prompt_bytes=8192,
        )

        self.assertLessEqual(len(prompt.encode("utf-8")), 8192)
        self.assertIn("endpoint_index_entries_omitted", prompt)
        self.assertIn("END CAPTURED TRAFFIC", prompt)

    def test_prompt_output_is_deterministic(self):
        endpoints = [endpoint("/z", {"z": 1}), endpoint("/a", {"a": 1})]

        first = codegen.build_prompt("api.example.com", endpoints)
        second = codegen.build_prompt("api.example.com", list(reversed(endpoints)))

        self.assertEqual(first, second)

    def test_legacy_endpoint_dictionaries_still_render(self):
        legacy = {
            "method": "POST",
            "path": "/messages",
            "status": 201,
            "query": "draft=true",
            "request_body": '{"text":"hi"}',
            "response_body": '{"id":1}',
        }

        digest = codegen.build_digest([legacy], max_digest_bytes=8192)
        record = detail_record(digest)

        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["samples"][0]["query"], "draft=true")
        self.assertEqual(record["samples"][0]["request"]["kind"], "text")


if __name__ == "__main__":
    unittest.main()
