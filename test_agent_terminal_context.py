import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import agent_server


def codex_developer_instructions(command: list[str]) -> str:
    value = next(
        item
        for item in command
        if item.startswith("developer_instructions=")
    )
    return json.loads(value.split("=", 1)[1])


class AgentTerminalContextTests(unittest.TestCase):
    def test_agent_environment_identifies_chat_terminal(self) -> None:
        env = agent_server.agent_runner_env("sess-ab/cd")

        self.assertEqual(env["AGENTSDOCK_CHAT_ID"], "sess-ab/cd")
        self.assertEqual(env["AGENTSDOCK_TMUX_SESSION"], "zd_sess_ab_cd")
        self.assertEqual(
            env["AGENTSDOCK_MANIFEST_PATH"],
            str(agent_server.codex_manifest_path("sess-ab/cd")),
        )
        self.assertTrue(env["AGENTSDOCK_MANIFEST_PATH"].endswith("/manifests/current.json"))
        self.assertEqual(
            env["AGENTSDOCK_PUBLISH_CLI"],
            str(agent_server.SERVER_ROOT / "agentsdock_publish.py"),
        )
        self.assertEqual(
            env["AGENTSDOCK_JOBS_CLI"],
            str(agent_server.SERVER_ROOT / "agentsdock_jobs.py"),
        )
        self.assertEqual(
            env["AGENTSDOCK_CHATS_CLI"],
            str(agent_server.SERVER_ROOT / "agentsdock_chats.py"),
        )
        self.assertEqual(
            env["AGENTSDOCK_MAIL_CLI"],
            str(agent_server.SERVER_ROOT / "agentsdock_mail.py"),
        )
        for name in agent_server.PROVIDER_SECRET_ENV_NAMES:
            self.assertNotIn(name, env)

    def test_codex_app_server_environment_exports_publisher(self) -> None:
        env = agent_server.codex_app_server_env()

        self.assertEqual(
            env["AGENTSDOCK_PUBLISH_CLI"],
            str(agent_server.SERVER_ROOT / "agentsdock_publish.py"),
        )
        self.assertEqual(
            env["AGENTSDOCK_MAIL_CLI"],
            str(agent_server.SERVER_ROOT / "agentsdock_mail.py"),
        )
        for name in agent_server.PROVIDER_SECRET_ENV_NAMES:
            self.assertNotIn(name, env)

    def test_claude_prompt_uses_stable_terminal_indirection(self) -> None:
        command = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
        )
        prompt = command[command.index("--append-system-prompt") + 1]

        self.assertIn("AGENTSDOCK_TMUX_SESSION", prompt)
        self.assertIn("read-only", prompt)
        self.assertNotIn("sess-123", prompt)
        self.assertNotIn("/tmp/manifest.json", prompt)

    def test_claude_prompt_is_stable_across_sessions_and_runs(self) -> None:
        first = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/run-a.json"),
        )
        second = agent_server.build_claude_cmd(
            "sess-456",
            {"id": "sess-456", "backend": "claude"},
            Path("/tmp/run-b.json"),
        )

        first_prompt = first[first.index("--append-system-prompt") + 1]
        second_prompt = second[second.index("--append-system-prompt") + 1]
        self.assertEqual(first_prompt, second_prompt)
        self.assertNotIn("Current jobs for this chat", first_prompt)
        self.assertNotIn("turn-start snapshot", first_prompt)
        # The static provider-authority and delivery guidance now lives here
        # once per session instead of being appended to every turn's prompt,
        # so the prelude is larger but still bounded and byte-stable.
        self.assertIn(
            agent_server.PROVIDER_THREAD_INSTRUCTION_ADDENDUM.strip(),
            first_prompt,
        )
        self.assertLess(len(first_prompt), 12_000)

    def test_claude_transcript_suppression_flag_only_affects_fresh_command(self) -> None:
        standalone = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
            no_session_persistence=True,
        )
        ordinary = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
        )
        resumed = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
            provider_id="claude-parent",
            no_session_persistence=True,
        )

        self.assertIn("--no-session-persistence", standalone)
        self.assertNotIn("--no-session-persistence", ordinary)
        self.assertNotIn("--no-session-persistence", resumed)

        legacy = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
            no_session_persistence=False,
        )
        self.assertNotIn("--no-session-persistence", legacy)

    def test_claude_transcript_suppression_probe_is_cached(self) -> None:
        probe = Mock(
            return_value="--print --no-session-persistence --help"
        )
        with (
            patch.object(
                agent_server,
                "CLAUDE_NO_SESSION_PERSISTENCE_SUPPORTED",
                None,
            ),
            patch.object(agent_server, "run_catalog_command", probe),
        ):
            self.assertTrue(agent_server.claude_supports_no_session_persistence())
            self.assertTrue(agent_server.claude_supports_no_session_persistence())

        probe.assert_called_once_with([agent_server.CLAUDE_BIN, "--help"])

    def test_legacy_system_prompt_format_contract_remains_usable(self) -> None:
        legacy = agent_server.SYSTEM_PROMPT.format(
            manifest_path="/tmp/legacy-run.json",
            terminal_session="zd_legacy",
        )

        self.assertEqual(legacy, agent_server.CLAUDE_PROMPT_PRELUDE.format())
        self.assertIn("Treat milestone completion as progress", legacy)
        self.assertIn("every requested milestone and acceptance check", legacy)

    def test_codex_prompt_names_terminal_and_preserves_user_prompt(self) -> None:
        command = agent_server.build_codex_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "codex"},
            "Inspect the terminal state.",
            Path("/tmp/manifest.json"),
        )
        developer_prompt = codex_developer_instructions(command)

        self.assertIn("`zd_sess_123`", developer_prompt)
        self.assertIn("current turn's provider-authority block", developer_prompt)
        self.assertNotIn("--chat-id sess-123", developer_prompt)
        self.assertIn("manifests/current.json", developer_prompt)
        self.assertEqual(command[-1], "Inspect the terminal state.")
        self.assertNotIn("[AgentsDock context]", command[-1])

    def test_codex_history_import_removes_legacy_launch_context(self) -> None:
        jobs_context = (
            "\nScheduled jobs:\n"
            "- Legacy server-owned instructions.\n\n"
            "Current jobs for this chat (turn-start snapshot; prompts omitted):\n"
            "- none\n\n"
        )
        legacy_message = (
            "[AgentsDock context]\n"
            "Legacy launch instructions.\n"
            "User prompt follows.\n"
            "]\n\n"
            + jobs_context
            + agent_server.session_prompt_addendum({
                "system_prompt": "Use the staging cluster.",
            })
            + "Immutable user text."
        )
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.write_text(json.dumps({
                "type": "event_msg",
                "payload": {
                    "type": "user_message",
                    "message": legacy_message,
                },
            }) + "\n")
            items = agent_server.parse_codex_history(history_path, None)

        self.assertEqual(items, [{"kind": "user", "text": "Immutable user text."}])

    def test_codex_history_import_unwraps_legacy_steering_in_both_record_shapes(self) -> None:
        legacy_message = (
            agent_server.LEGACY_STEERING_PREFIX
            + "[Interrupted message]\nOriginal request.\n"
            "[End interrupted message]\n\n"
            "[Steering message]\nLatest steering text.\n"
            "[End steering message]\n\n"
            "[Attached files]\n"
            "- /tmp/latest.png (latest.png, image/png)\n"
            "Use these local paths directly when needed.\n"
        )
        records = [
            {
                "type": "event_msg",
                "payload": {"type": "user_message", "message": legacy_message},
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{
                        "type": "input_text",
                        "text": legacy_message.replace(
                            "Latest steering text.",
                            "Second latest steering text.",
                        ),
                    }],
                },
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            items = agent_server.parse_codex_history(history_path, None)

        self.assertEqual(items, [
            {"kind": "user", "text": "Latest steering text."},
            {"kind": "user", "text": "Second latest steering text."},
        ])

    def test_claude_history_import_unwraps_legacy_steering(self) -> None:
        legacy_message = (
            agent_server.LEGACY_STEERING_PREFIX
            + "[Interrupted message]\nOriginal request.\n"
            "[End interrupted message]\n\n"
            "[Steering message]\nLatest steering text.\n"
            "[End steering message]"
        )
        with tempfile.TemporaryDirectory() as tmp:
            history_path = Path(tmp) / "history.jsonl"
            history_path.write_text(json.dumps({
                "type": "user",
                "message": {
                    "content": [{"type": "text", "text": legacy_message}],
                },
            }) + "\n")
            items = agent_server.parse_claude_history(history_path, None)

        self.assertEqual(items, [{"kind": "user", "text": "Latest steering text."}])

    def test_history_import_hides_nested_fallback_memory_wrappers(self) -> None:
        generated = (
            "[Codex rollover memory]\n"
            "Generated rollover summary.\n"
            "[End Codex rollover memory]\n\n"
            "[Current user prompt]\n"
            "[Fork memory context]\n"
            "Generated fork summary.\n"
            "[End fork memory context]\n\n"
            "[Current user prompt]\n"
            "Immutable user text."
        )

        self.assertEqual(
            agent_server.strip_agentsdock_generated_user_text(generated),
            "Immutable user text.",
        )

    def test_history_import_uses_the_outer_memory_boundary(self) -> None:
        generated = (
            "[Codex rollover memory]\n"
            "Summary containing a copied delimiter:\n"
            "[End Codex rollover memory]\n\n"
            "[Current user prompt]\n"
            "This text is still part of the generated summary.\n"
            "[End Codex rollover memory]\n\n"
            "[Current user prompt]\n"
            "Immutable user text."
        )

        self.assertEqual(
            agent_server.strip_agentsdock_generated_user_text(generated),
            "Immutable user text.",
        )

    def test_length_delimited_memory_preserves_user_owned_boundary_text(self) -> None:
        immutable = (
            "Keep this exact user text.\n"
            "[End Codex rollover memory]\n\n"
            "[Current user prompt]\n"
            "This delimiter is user-owned."
        )
        generated = agent_server.build_memory_augmented_prompt(
            "Codex rollover memory",
            "Bounded generated summary with unicode: café.",
            immutable,
        )

        self.assertEqual(
            agent_server.strip_agentsdock_generated_user_text(generated),
            immutable,
        )

    def test_per_chat_system_prompt_reaches_both_backends(self) -> None:
        session = {
            "id": "sess-123",
            "system_prompt": "Always verify the deployment target before editing.",
        }
        claude_command = agent_server.build_claude_cmd(
            "sess-123",
            {**session, "backend": "claude"},
            Path("/tmp/manifest.json"),
        )
        claude_prompt = claude_command[claude_command.index("--append-system-prompt") + 1]
        codex_prompt = agent_server.build_codex_cmd(
            "sess-123",
            {**session, "backend": "codex"},
            "Check the current status.",
            Path("/tmp/manifest.json"),
        )
        codex_developer_prompt = codex_developer_instructions(codex_prompt)

        for prompt in (claude_prompt, codex_developer_prompt):
            self.assertIn("[Per-chat system instructions]", prompt)
            self.assertIn("Always verify the deployment target before editing.", prompt)
        self.assertEqual(codex_prompt[-1], "Check the current status.")

    def test_steering_history_never_enters_privileged_provider_context(self) -> None:
        provider_prompt = agent_server.build_turn_provider_prompt(
            "sess-123",
            "Latest raw user text.",
            [],
            [
                {"prompt": "Original interrupted request.", "file_ids": []},
                {"prompt": "Latest raw user text.", "file_ids": []},
            ],
        )
        claude_command = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
        )
        codex_command = agent_server.build_codex_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "codex"},
            provider_prompt,
            Path("/tmp/manifest.json"),
        )

        claude_system_prompt = claude_command[
            claude_command.index("--append-system-prompt") + 1
        ]
        codex_developer_prompt = codex_developer_instructions(codex_command)
        self.assertNotIn("Original interrupted request.", claude_system_prompt)
        self.assertNotIn("Original interrupted request.", codex_developer_prompt)
        self.assertNotIn("Latest raw user text.", claude_system_prompt)
        self.assertNotIn("Latest raw user text.", codex_developer_prompt)
        self.assertEqual(codex_command[-1], "Latest raw user text.")

    def test_provider_argv_redaction_hides_context_and_user_prompt(self) -> None:
        claude = agent_server.build_claude_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "claude"},
            Path("/tmp/manifest.json"),
        )
        codex = agent_server.build_codex_cmd(
            "sess-123",
            {"id": "sess-123", "backend": "codex"},
            "Private user prompt.",
            Path("/tmp/manifest.json"),
        )

        redacted_claude = agent_server.redacted_provider_argv(claude, agent_server.BACKEND_CLAUDE)
        redacted_codex = agent_server.redacted_provider_argv(codex, agent_server.BACKEND_CODEX)

        self.assertNotIn("[AgentsDock context]", json.dumps(redacted_claude))
        self.assertNotIn("[AgentsDock context]", json.dumps(redacted_codex))
        self.assertNotIn("Private user prompt.", json.dumps(redacted_codex))
        self.assertIn("<system-prompt>", redacted_claude)
        self.assertEqual(redacted_codex[-1], "<prompt>")

    def test_codex_merges_user_developer_instructions(self) -> None:
        with patch.object(
            agent_server,
            "codex_user_developer_instructions",
            return_value="Existing user instruction.",
        ):
            command = agent_server.build_codex_cmd(
                "sess-123",
                {"id": "sess-123", "backend": "codex"},
                "Raw prompt.",
                Path("/tmp/manifest.json"),
            )

        developer_prompt = codex_developer_instructions(command)
        self.assertTrue(developer_prompt.startswith("Existing user instruction."))
        self.assertIn("You are operating through AgentsDock", developer_prompt)
        self.assertNotIn("[AgentsDock context]", developer_prompt)
        self.assertEqual(command[-1], "Raw prompt.")

    def test_public_session_exposes_per_chat_system_prompt(self) -> None:
        public = agent_server.public_session({
            "id": "sess-123",
            "title": "Deployment",
            "system_prompt": "Use the staging cluster.",
        })

        self.assertEqual(public["system_prompt"], "Use the staging cluster.")

    def test_both_agent_prompts_explain_renderable_latex_delimiters(self) -> None:
        claude_prompt = agent_server.CLAUDE_PROMPT_PRELUDE.format()
        codex_prompt = agent_server.CODEX_PROMPT_PRELUDE.format(
            manifest_path="/tmp/manifest.json",
            terminal_session="zd_sess_123",
            chat_id="sess-123",
        )

        self.assertIn("inline math as `$...$`", claude_prompt)
        self.assertIn("display math as `$$...$$`", claude_prompt)
        self.assertIn("inline math as `$...$`", codex_prompt)
        self.assertIn("display math as `$$...$$`", codex_prompt)

    def test_both_agent_prompts_explain_clickable_workspace_file_links(self) -> None:
        claude_prompt = agent_server.CLAUDE_PROMPT_PRELUDE.format()
        codex_prompt = agent_server.CODEX_PROMPT_PRELUDE.format(
            manifest_path="/tmp/manifest.json",
            terminal_session="zd_sess_123",
            chat_id="sess-123",
        )

        claude_compact = " ".join(claude_prompt.split())
        self.assertIn("relative to the chat working directory", claude_compact)
        codex_compact = " ".join(codex_prompt.split())
        for compact in (claude_compact, codex_compact):
            self.assertIn("`#L42`", compact)
            self.assertIn("`file://`", compact)
        self.assertIn("$AGENTSDOCK_MANIFEST_PATH", claude_compact)
        self.assertIn("/tmp/manifest.json", codex_compact)

    def test_both_agent_prompts_explain_artifact_and_video_publishing(self) -> None:
        claude_prompt = agent_server.CLAUDE_PROMPT_PRELUDE.format()
        codex_prompt = agent_server.CODEX_PROMPT_PRELUDE.format(
            manifest_path="/tmp/manifests/current.json",
            terminal_session="zd_sess_123",
            chat_id="sess-123",
        )

        for prompt in (claude_prompt, codex_prompt):
            compact = " ".join(prompt.split())
            self.assertIn("Publish user-facing files", compact)
            self.assertIn('"files":["/absolute/path.ext"', compact)
            self.assertIn("`--authority-file` command", compact)
            self.assertIn("playable `.mp4`/`.mov` videos", compact)
            self.assertIn("successful JSON receipt", compact)
            self.assertIn("submitted for attachment", compact)
            self.assertIn("not Slack", compact)
        self.assertIn("$AGENTSDOCK_MANIFEST_PATH", claude_prompt)
        self.assertIn("/tmp/manifests/current.json", codex_prompt)


class SessionSystemPromptPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_session_store_updates_and_clears_system_prompt(self) -> None:
        store = agent_server.SessionStore()
        store.sessions["sess-123"] = {
            "id": "sess-123",
            "title": "Deployment",
            "folder": "General",
            "backend": "codex",
            "system_prompt": None,
        }

        with patch.object(store, "save", AsyncMock()):
            updated = await store.update("sess-123", {"system_prompt": "  Use staging.  "})
            self.assertEqual(updated["system_prompt"], "Use staging.")
            cleared = await store.update("sess-123", {"system_prompt": None})

        self.assertIsNone(cleared["system_prompt"])


if __name__ == "__main__":
    unittest.main()
