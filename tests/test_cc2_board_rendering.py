from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def load_module(relative: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_markdown_table_escapes_pipe_characters_for_human_board() -> None:
    renderer = load_module('.omx/cc2/render_board_md.py', 'render_board_md_for_test')

    rows = renderer.table(['Column', 'Meaning'], [['permission|preset', 'cannot leak | split columns']])

    assert rows[2] == '| permission\\|preset | cannot leak \\| split columns |'


def test_issue_parity_intake_rows_are_normalized_as_board_items() -> None:
    generator = load_module('scripts/generate_cc2_board.py', 'generate_cc2_board_for_test')

    item = generator.intake_item(
        {
            'id': 'CC2-PARITY-CODEX-GRANULAR-PERMISSIONS',
            'source_anchor': 'Codex issue #22595 and ROADMAP.md#policy-engine',
            'source_type': 'external_issue_and_roadmap',
            'title': 'Granular permission profile adaptation',
            'release_bucket': 'alpha_blocker',
            'lifecycle_status': 'active',
            'dependencies': ['policy profile model', 'approval-token audit trail'],
            'verification_required': ['status JSON exposes active profile', 'path-scope cannot be bypassed'],
            'deferral_rationale': None,
        }
    )

    assert item['id'] == 'CC2-PARITY-CODEX-GRANULAR-PERMISSIONS'
    assert item['status'] == 'active'
    assert item['source_path'] == '.omx/cc2/issue-parity-intake.json'
    assert item['owner_lane'] == 'parity_overlay'
    assert item['category'] == 'security'
    assert item['dependencies'] == ['policy profile model', 'approval-token audit trail']
    assert item['verification_required'] == ['status JSON exposes active profile', 'path-scope cannot be bypassed']
    assert item['deferral_rationale'] == ''
