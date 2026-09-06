import asyncio
import unittest

import agent_server


HTTP_METHODS = {
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "trace",
}

SPLIT_ROUTE_CASES = {
    "/api/team-hub-secure/{connection_id}/{hub_path:path}": {
        "concrete_path": (
            "/api/team-hub-secure/00000000-0000-4000-8000-000000000000/"
            "v1/health"
        ),
        "schema_path": "/api/team-hub-secure/{connection_id}/{hub_path}",
        "methods": {"delete", "get", "head", "post", "put"},
    },
    "/api/sessions/{session_id}/workspace/preview": {
        "concrete_path": "/api/sessions/chat/workspace/preview",
        "schema_path": "/api/sessions/{session_id}/workspace/preview",
        "methods": {"get", "head"},
    },
    "/api/sessions/{session_id}/workspace/download": {
        "concrete_path": "/api/sessions/chat/workspace/download",
        "schema_path": "/api/sessions/{session_id}/workspace/download",
        "methods": {"get", "head"},
    },
}


class OpenAPIOperationIdTests(unittest.TestCase):
    def schema(self) -> dict:
        previous = agent_server.app.openapi_schema
        try:
            agent_server.app.openapi_schema = None
            return agent_server.app.openapi()
        finally:
            agent_server.app.openapi_schema = previous

    def router_response(self, method: str, path: str) -> tuple[int, dict[str, str]]:
        async def dispatch() -> tuple[int, dict[str, str]]:
            messages: list[dict] = []

            async def receive() -> dict:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message: dict) -> None:
                messages.append(message)

            await agent_server.app.router(
                {
                    "type": "http",
                    "asgi": {"version": "3.0", "spec_version": "2.3"},
                    "http_version": "1.1",
                    "method": method,
                    "scheme": "http",
                    "path": path,
                    "raw_path": path.encode("ascii"),
                    "query_string": b"",
                    "headers": [],
                    "client": ("127.0.0.1", 12345),
                    "server": ("127.0.0.1", 7850),
                    "root_path": "",
                },
                receive,
                send,
            )
            started = next(
                message
                for message in messages
                if message.get("type") == "http.response.start"
            )
            headers = {
                bytes(name).decode("latin-1").lower(): bytes(value).decode("latin-1")
                for name, value in started.get("headers", [])
            }
            return int(started["status"]), headers

        return asyncio.run(dispatch())

    def test_operation_ids_are_globally_unique_and_method_specific(self) -> None:
        schema = self.schema()
        uses: dict[str, list[tuple[str, str]]] = {}
        for path, path_item in schema["paths"].items():
            for method, operation in path_item.items():
                if method not in HTTP_METHODS:
                    continue
                operation_id = operation.get("operationId")
                self.assertIsInstance(operation_id, str)
                self.assertTrue(operation_id)
                uses.setdefault(operation_id, []).append((method, path))

        duplicates = {
            operation_id: locations
            for operation_id, locations in uses.items()
            if len(locations) > 1
        }
        self.assertEqual(duplicates, {})

        for case in SPLIT_ROUTE_CASES.values():
            path = case["schema_path"]
            expected = case["methods"]
            path_item = schema["paths"][path]
            actual = set(path_item).intersection(HTTP_METHODS)
            self.assertEqual(actual, expected)
            for method in expected:
                self.assertTrue(
                    path_item[method]["operationId"].endswith(f"_{method}"),
                    path_item[method]["operationId"],
                )

    def test_split_routes_keep_hidden_aggregate_runtime_route_first(self) -> None:
        for runtime_path, case in SPLIT_ROUTE_CASES.items():
            with self.subTest(path=runtime_path):
                routes = [
                    route
                    for route in agent_server.app.router.routes
                    if getattr(route, "path", None) == runtime_path
                ]
                expected = {method.upper() for method in case["methods"]}
                self.assertEqual(len(routes), len(expected) + 1)
                self.assertFalse(routes[0].include_in_schema)
                self.assertEqual(routes[0].methods, expected)
                self.assertTrue(
                    all(route.include_in_schema for route in routes[1:])
                )
                self.assertTrue(
                    all(route.endpoint is routes[0].endpoint for route in routes)
                )
                visible = [route for route in routes if route.include_in_schema]
                self.assertEqual(
                    {frozenset(route.methods or ()) for route in visible},
                    {frozenset({method}) for method in expected},
                )
                self.assertTrue(all(len(route.methods or ()) == 1 for route in visible))

                unsupported_method = "PATCH" if "DELETE" in expected else "DELETE"
                status, headers = self.router_response(
                    unsupported_method,
                    case["concrete_path"],
                )
                self.assertEqual(status, 405)
                self.assertEqual(
                    {
                        method.strip()
                        for method in headers["allow"].split(",")
                        if method.strip()
                    },
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
