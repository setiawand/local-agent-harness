from __future__ import annotations

import sys
from typing import Any, TextIO


class TerminalStream:
    """
    Minimal terminal renderer for mlx-code Agent events.

    The renderer prints assistant text as it arrives, suppresses XML
    <tool_call>...</tool_call> blocks from the visible answer, and reports
    tool lifecycle events.

    A TerminalStream instance is intended to be created for one agent.run()
    invocation, as done by harness.cli.
    """

    _TOOL_OPEN = "<tool_call>"
    _TOOL_CLOSE = "</tool_call>"

    def __init__(self, output: TextIO | None = None):
        self.output = output if output is not None else sys.stdout
        self.text_buffer = ""
        self._finished = False

    def _emit_text(self, text: str) -> None:
        if text:
            self.output.write(text)
            self.output.flush()

    @staticmethod
    def _longest_partial_suffix(text: str, marker: str) -> int:
        """Length of the longest suffix of text that prefixes marker."""
        max_len = min(len(text), len(marker) - 1)
        for length in range(max_len, 0, -1):
            if text.endswith(marker[:length]):
                return length
        return 0

    def _process_text(self, chunk: str) -> None:
        """
        Incrementally remove tool-call XML without eating adjacent answer text.

        Important: when a partial '<tool_call>' prefix is retained at the end
        of a chunk, return immediately. Continuing the loop with the same
        buffer was the source of an earlier infinite-loop regression.
        """
        if not chunk:
            return

        # An agent.run() can contain several assistant/tool cycles. A
        # turn_end flushes the current segment, but later assistant text in
        # the same run must still be rendered.
        self._finished = False
        self.text_buffer += chunk

        while self.text_buffer:
            open_at = self.text_buffer.find(self._TOOL_OPEN)

            if open_at >= 0:
                close_at = self.text_buffer.find(
                    self._TOOL_CLOSE, open_at + len(self._TOOL_OPEN)
                )

                if close_at >= 0:
                    # Emit text before the hidden tool-call block and remove
                    # the complete XML block.
                    self._emit_text(self.text_buffer[:open_at])
                    self.text_buffer = self.text_buffer[
                        close_at + len(self._TOOL_CLOSE):
                    ]
                    continue

                # An opening tag has arrived but its closing tag has not.
                # Keep the entire incomplete tool call hidden.
                self._emit_text(self.text_buffer[:open_at])
                self.text_buffer = self.text_buffer[open_at:]
                return

            # No complete opening tag. Keep only a possible partial opening
            # marker at the end of the current stream chunk.
            keep = self._longest_partial_suffix(
                self.text_buffer, self._TOOL_OPEN
            )
            if keep:
                self._emit_text(self.text_buffer[:-keep])
                self.text_buffer = self.text_buffer[-keep:]
                return

            self._emit_text(self.text_buffer)
            self.text_buffer = ""

    def _finish_text(self) -> None:
        """Flush ordinary trailing text; discard an incomplete tool-call tag."""
        if self._finished:
            return
        self._finished = True

        if self.text_buffer.startswith(self._TOOL_OPEN):
            # Never leak a truncated tool-call payload into the terminal.
            self.text_buffer = ""
            return

        # A suffix such as '<tool_' is not a complete tool call. At the end
        # of a turn, render it as ordinary text rather than silently dropping
        # user-visible content.
        self._emit_text(self.text_buffer)
        self.text_buffer = ""

    @staticmethod
    def _payload(event: dict[str, Any]) -> dict[str, Any]:
        payload = event.get("payload")
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _text_from_event(event: dict[str, Any]) -> str | None:
        payload = event.get("payload")
        event_type = str(event.get("type", "")).lower()

        if isinstance(payload, str):
            return payload if event_type in {
                "text", "text_delta", "assistant_text", "token"
            } else None

        if not isinstance(payload, dict):
            return None

        # mlx-code event payloads use "text"; alternate keys are accepted
        # to remain tolerant of compatible mlx-code event versions.
        if event_type in {
            "text", "text_delta", "assistant_text", "token",
            "content_delta", "text_chunk",
        }:
            for key in ("text", "delta", "content", "token"):
                value = payload.get(key)
                if isinstance(value, str):
                    return value

        # Some event versions use a generic delta event with a text field.
        if event_type in {"delta", "stream"}:
            for key in ("text", "delta", "content"):
                value = payload.get(key)
                if isinstance(value, str):
                    return value

        return None

    async def on_event(self, event: dict[str, Any]) -> None:
        """Consume one mlx-code Agent event."""
        if not isinstance(event, dict):
            return

        event_type = str(event.get("type", "")).lower()
        payload = self._payload(event)

        text = self._text_from_event(event)
        if text is not None:
            self._process_text(text)
            return

        if event_type in {"tool_start", "tool_begin"}:
            name = payload.get("name", "tool")
            self._finish_text()
            self.output.write(f"\n⚙ Running {name}...\n")
            self.output.flush()
            return

        if event_type in {"tool_end", "tool_complete"}:
            name = payload.get("name", "Tool")
            is_error = bool(payload.get("is_error", False))
            status = "✗" if is_error else "✓"
            suffix = " failed" if is_error else " completed"
            self.output.write(f"{status} {name}{suffix}\n")
            self.output.flush()
            return

        if event_type in {"turn_end", "turn_complete", "message_end"}:
            self._finish_text()
            return

        if event_type in {"error", "agent_error"}:
            self._finish_text()
            message = payload.get("message") or payload.get("error") or "Unknown error"
            self.output.write(f"\nAgent stream error: {message}\n")
            self.output.flush()

    def finish(self) -> None:
        """Explicitly flush any remaining visible text."""
        self._finish_text()
