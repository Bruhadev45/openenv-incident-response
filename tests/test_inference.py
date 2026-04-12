from __future__ import annotations

import io
from contextlib import redirect_stdout

import inference


def test_log_step_matches_required_stdout_format() -> None:
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        inference.log_step(
            step=3,
            action='{"action_type":"click","target":"button-1"}',
            reward=1,
            done=True,
            error=None,
        )

    assert (
        buffer.getvalue().strip()
        == '[STEP] step=3 action={"action_type":"click","target":"button-1"} '
        "reward=1.00 done=true error=null"
    )


def test_log_end_uses_required_fields_only() -> None:
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        inference.log_end(success=False, steps=2, rewards=[0, 0.125])

    assert buffer.getvalue().strip() == "[END] success=false steps=2 rewards=0.00,0.12"


def test_parse_action_from_invalid_response_uses_fallback() -> None:
    assert inference.parse_action_from_response("not json at all") == inference.FALLBACK_ACTION
