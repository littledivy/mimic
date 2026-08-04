import json
import unittest

from mimic.sources import mitm


class FakeMitm:
    def __init__(self, bodies=None):
        self.bodies = bodies or {}
        self.calls = []

    def body(self, flow_id, side):
        self.calls.append((flow_id, side))
        return self.bodies.get((flow_id, side), b"")


def flow(
    flow_id,
    path,
    *,
    method="GET",
    status=200,
    request_body=b"",
    response_body=b"",
    request_headers=None,
    response_headers=None,
):
    request_headers = list(request_headers or [])
    response_headers = list(response_headers or [])
    request = {
        "host": "api.example.com",
        "method": method,
        "path": path,
        "headers": request_headers,
        "contentLength": len(request_body),
    }
    response = None
    if status is not None:
        response = {
            "status_code": status,
            "headers": response_headers,
            "contentLength": len(response_body),
        }
    record = {"id": flow_id, "request": request}
    if response is not None:
        record["response"] = response
    bodies = {
        (flow_id, "request"): request_body,
        (flow_id, "response"): response_body,
    }
    return record, bodies


class CaptureQualityTests(unittest.TestCase):
    def make_capture(self, specs):
        flows = []
        bodies = {}
        for spec in specs:
            record, record_bodies = flow(*spec[0], **spec[1])
            flows.append(record)
            bodies.update(record_bodies)
        return flows, FakeMitm(bodies)

    def test_repeated_short_ids_collapse_into_route_template(self):
        flows, client = self.make_capture([
            (("one", "/v1/users/123"), {}),
            (("two", "/v1/users/456"), {}),
        ])

        endpoints = mitm.endpoints(client, flows, "api.example.com", include_bodies=False)

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/v1/users/{user_id}")
        self.assertEqual(endpoints[0]["sample_count"], 2)
        self.assertEqual(
            endpoints[0]["raw_paths"], ["/v1/users/123", "/v1/users/456"]
        )
        self.assertEqual(client.calls, [])

    def test_high_confidence_and_multiple_ids_are_normalized(self):
        flows, client = self.make_capture([
            (("uuid", "/users/550e8400-e29b-41d4-a716-446655440000"), {}),
            (("nested", "/users/123/posts/456"), {}),
        ])

        endpoints = mitm.endpoints(client, flows, "api.example.com", include_bodies=False)

        self.assertEqual(
            [endpoint["path"] for endpoint in endpoints],
            ["/users/{user_id}", "/users/{user_id}/posts/{post_id}"],
        )

    def test_versions_dates_and_static_numbers_remain_literal(self):
        paths = [
            "/v1/page/2",
            "/v1/reports/2024",
            "/v1/status/200",
            "/v1/images/1080",
        ]
        flows, client = self.make_capture([
            ((str(index), path), {}) for index, path in enumerate(paths)
        ])

        endpoints = mitm.endpoints(client, flows, "api.example.com", include_bodies=False)

        self.assertEqual([endpoint["path"] for endpoint in endpoints], sorted(paths))

    def test_telemetry_is_filtered_before_body_download(self):
        record, bodies = flow(
            "telemetry",
            "/v1/telemetry",
            method="POST",
            request_body=b'{"event":"open"}',
            response_body=b"{}",
        )
        client = FakeMitm(bodies)

        endpoints = mitm.endpoints(client, [record], "api.example.com")

        self.assertEqual(endpoints, [])
        self.assertEqual(client.calls, [])

        endpoints = mitm.endpoints(
            client, [record], "api.example.com", include_telemetry=True
        )
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(
            client.calls,
            [("telemetry", "request"), ("telemetry", "response")],
        )

    def test_sample_hydration_is_capped(self):
        specs = []
        for index in range(7):
            specs.append((
                (str(index), f"/v1/items/1?variant={index}"),
                {
                    "response_body": json.dumps({"index": index}).encode(),
                    "response_headers": [("content-type", "application/json")],
                },
            ))
        flows, client = self.make_capture(specs)

        endpoints = mitm.endpoints(client, flows, "api.example.com", max_samples=5)

        self.assertEqual(endpoints[0]["sample_count"], 7)
        self.assertEqual(endpoints[0]["schema_sample_count"], 5)
        self.assertEqual(len(endpoints[0]["samples"]), 5)
        self.assertEqual(len(client.calls), 5)
        self.assertTrue(all(side == "response" for _, side in client.calls))

    def test_schemas_merge_multiple_request_and_response_samples(self):
        first_request = {
            "id": 1,
            "items": [{"x": 1}],
            "name": "first",
            "nullable": None,
            "score": 1,
        }
        second_request = {
            "extra": True,
            "id": 2,
            "items": [{"x": 2, "y": True}],
            "nullable": "known",
            "score": 1.5,
        }
        first, first_bodies = flow(
            "one",
            "/v1/users/1",
            method="POST",
            request_body=json.dumps(first_request).encode(),
            response_body=b'{"ok":true,"user":{"id":1}}',
        )
        second, second_bodies = flow(
            "two",
            "/v1/users/2",
            method="POST",
            status=400,
            request_body=json.dumps(second_request).encode(),
            response_body=b'{"error":"invalid"}',
        )
        client = FakeMitm({**first_bodies, **second_bodies})

        endpoint = mitm.endpoints(client, [first, second], "api.example.com")[0]
        request_schema = endpoint["schemas"]["request"]

        self.assertEqual(endpoint["path"], "/v1/users/{user_id}")
        self.assertEqual(
            request_schema["required"], ["id", "items", "nullable", "score"]
        )
        self.assertNotIn("name", request_schema["required"])
        self.assertEqual(request_schema["properties"]["score"], {"type": "number"})
        self.assertEqual(
            request_schema["properties"]["nullable"],
            {"type": ["null", "string"]},
        )
        item_schema = request_schema["properties"]["items"]["items"]
        self.assertEqual(item_schema["required"], ["x"])
        self.assertIn("y", item_schema["properties"])
        self.assertEqual(
            sorted(endpoint["schemas"]["responses"]), ["2xx", "4xx"]
        )


if __name__ == "__main__":
    unittest.main()
