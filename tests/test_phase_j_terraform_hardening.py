"""Phase J — Terraform parser hardening / branch-coverage closure.

The Terraform ingest path is one of ATMS's most-used IaC entry points,
but its coverage sat at 74.2% (48 statements + 19 branches uncovered
out of 210). Roadmap V4 Phase J closes that gap by driving every
remaining branch with synthetic .tf inputs:

  * `_mask_strings`: <<-EOT dash-indent, <<"EOT" quoted marker,
    empty-marker bail-out, unterminated heredoc, backslash escape
    inside double-quoted string.
  * `_strip_comments`: same heredoc variants, /* */ block comments
    spanning lines, comments hidden inside strings.
  * `_read_terraform`: 50 MB byte cap across directory walk, symlinked
    .tf files skipped, files whose stat() raises OSError skipped.
  * `parse_terraform`: HCL pseudo-namespaces (var/local/module/each)
    do NOT fake-look-like dataflows; non-AWS/Azure/Google vendor
    metadata is left blank; unclosed brace block degrades gracefully.

Phase J is pure test additions — no production code change. The goal
is to lock these defensive branches in place so a future refactor of
the scanner can't silently regress them.

Real-world consequence: every one of these branches guards against a
parser bug that would either crash on user IaC or silently produce a
wrong threat model. They MATTER. The previous 74% number was hiding
them.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_phase_j_terraform_hardening.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import os
from pathlib import Path
from unittest.mock import patch

import pytest

from atms.ingest.terraform import (
    _balanced_block,
    _mask_strings,
    _read_terraform,
    _strip_comments,
    parse_terraform,
)

# ---------------------------------------------------------------------------
# _mask_strings: heredoc variants
# ---------------------------------------------------------------------------


def test_mask_strings_dash_indent_heredoc():
    """`<<-EOT` (dash means indented closing marker allowed) is recognised."""
    src = 'x = <<-EOT\n  hello { world }\n  EOT\nresource "aws_s3_bucket" "b" {}\n'
    out = _mask_strings(src)
    # Heredoc body is blanked → braces inside `hello { world }` no
    # longer count toward brace balance.
    assert "{ world }" not in out
    # The trailing real resource block must survive. (Note: `_mask_strings`
    # masks the CONTENTS of the type/name strings too — that's by design,
    # `_RESOURCE_RE` runs on the comment-stripped-but-unmasked text. Here
    # we just confirm structure survives.)
    assert "resource" in out
    assert "{}" in out
    # Same length contract.
    assert len(out) == len(src)


def test_mask_strings_quoted_marker_heredoc():
    """`<<"EOT"` (or `<<'EOT'`) quoted marker form is recognised."""
    src = 'x = <<"EOT"\n  hidden { inside }\nEOT\nresource "aws_lb" "l" {}\n'
    out = _mask_strings(src)
    assert "hidden { inside }" not in out
    # Structure survives (type/name strings are masked, but the keyword
    # `resource` and braces aren't).
    assert "resource" in out
    assert "{}" in out
    assert len(out) == len(src)


def test_mask_strings_empty_heredoc_marker():
    """`<<` with no marker is a malformed heredoc — scanner advances and
    continues, doesn't crash or hang."""
    src = 'x = <<\nresource "aws_s3_bucket" "b" {}\n'
    out = _mask_strings(src)
    # Just ensure we get back same-length string without hanging.
    assert len(out) == len(src)


def test_mask_strings_unterminated_heredoc_bails():
    """Heredoc that opens but never closes — `_mask_strings` must bail
    (line 184-186 break path) rather than loop forever."""
    src = 'x = <<EOT\n  body { line }\n  no terminator anywhere\n'
    out = _mask_strings(src)
    # Same length, no infinite loop, no exception.
    assert len(out) == len(src)


def test_mask_strings_escape_inside_string():
    """`"foo \\" bar"` — the escaped quote must not terminate the string
    (lines 195-200). The whole string content gets masked, including
    the escaped pair (the scanner blanks BOTH characters of `\\"` to
    preserve same-length output)."""
    src = r'x = "foo \" still { inside } bar"' + "\n"
    out = _mask_strings(src)
    # Braces inside the (escaped) string must be masked to spaces.
    assert "{ inside }" not in out
    # Same-length contract — this is the load-bearing invariant for
    # downstream offset arithmetic.
    assert len(out) == len(src)
    # Opening + closing quotes of the outer string survive. (The
    # escaped-quote PAIR `\"` is blanked to two spaces, so only 2
    # quotes remain in output — that's expected behavior for the
    # masker.)
    assert out.count('"') == 2


# ---------------------------------------------------------------------------
# _strip_comments: comment + string + heredoc interactions
# ---------------------------------------------------------------------------


def test_strip_comments_block_comment_multiline():
    """`/* ... */` spanning multiple lines (lines 276-285)."""
    src = '/* outer\n   comment\n   spans lines */\nresource "aws_s3_bucket" "b" {}\n'
    out = _strip_comments(src)
    assert "outer" not in out
    assert "comment" not in out
    assert 'resource "aws_s3_bucket" "b"' in out


def test_strip_comments_block_comment_unterminated():
    """`/*` with no closing `*/` — scanner runs to end of file rather
    than crashing."""
    src = "/* never closed\nstill in comment\n"
    out = _strip_comments(src)
    assert len(out) == len(src)


def test_strip_comments_preserves_hash_inside_string():
    """`#` inside a `"..."` literal is not a comment and must survive."""
    src = 'x = "value with # not-a-comment"\nresource "aws_s3_bucket" "b" {}\n'
    out = _strip_comments(src)
    # The # inside the string must NOT be blanked (it's part of the literal).
    assert "# not-a-comment" in out
    assert 'resource "aws_s3_bucket" "b"' in out


def test_strip_comments_preserves_slash_inside_string():
    """`//` inside a `"..."` literal is not a comment."""
    src = 'x = "https://example.com/path"\nresource "aws_s3_bucket" "b" {}\n'
    out = _strip_comments(src)
    assert "https://example.com/path" in out


def test_strip_comments_inside_heredoc_dash_indent():
    """`<<-EOT` heredoc bodies don't get comment-stripped (dash-indent
    variant of lines 247-256)."""
    src = (
        'x = <<-EOT\n'
        '  # this is a literal #, not a comment\n'
        '  // also literal\n'
        '  EOT\n'
        'resource "aws_s3_bucket" "b" {}\n'
    )
    out = _strip_comments(src)
    # Heredoc body comments preserved.
    assert "# this is a literal" in out
    assert "// also literal" in out


def test_strip_comments_heredoc_quoted_marker():
    """`<<"EOT"` quoted-marker form in _strip_comments (lines 250-256)."""
    src = 'x = <<"EOT"\n  body\nEOT\n# real comment\nresource "aws_s3_bucket" "b" {}\n'
    out = _strip_comments(src)
    assert "# real comment" not in out
    assert "real comment" not in out
    assert 'resource "aws_s3_bucket" "b"' in out


def test_strip_comments_empty_heredoc_marker():
    """`<<` with no marker — scanner advances (lines 267-268)."""
    src = "x = <<\nresource \"aws_s3_bucket\" \"b\" {}\n"
    out = _strip_comments(src)
    assert len(out) == len(src)


def test_strip_comments_unterminated_heredoc_runs_to_end():
    """`<<EOT` without a closing marker — scanner sets i = n and exits
    cleanly (the `end = ... ; i = (end.end() if end else n)` branch)."""
    src = "x = <<EOT\n  body line\n  no terminator\n"
    out = _strip_comments(src)
    assert len(out) == len(src)


def test_strip_comments_handles_escape_inside_string():
    """`"foo \\" still string"` — escaped quote does not terminate the
    string (lines 234-236 in `_strip_comments`)."""
    src = 'x = "value with \\" escaped quote" # comment\n'
    out = _strip_comments(src)
    # The comment is stripped, but the string content is preserved.
    assert "escaped quote" in out
    assert "# comment" not in out


# ---------------------------------------------------------------------------
# _read_terraform: directory walk, byte cap, symlinks, OSError on stat
# ---------------------------------------------------------------------------


def test_read_terraform_byte_cap_truncates(tmp_path, monkeypatch, caplog):
    """When total .tf size exceeds the byte cap, the read stops and
    logs a warning (lines 348-359). We lower the cap to a few bytes
    instead of writing 50 MB of synthetic .tf to disk."""
    from atms.ingest import terraform as tf_mod

    proj = tmp_path / "big_tf"
    proj.mkdir()
    # 50-byte cap; each file is ~32 bytes, so file #2 trips it.
    monkeypatch.setattr(tf_mod, "_TF_MAX_BYTES", 50)

    (proj / "a.tf").write_text('resource "aws_s3_bucket" "a" {}\n', encoding="utf-8")
    (proj / "b.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")

    with caplog.at_level("WARNING"):
        text = _read_terraform(proj)

    # First file's content is in the result; second was skipped.
    assert 'resource "aws_s3_bucket" "a"' in text
    assert 'resource "aws_s3_bucket" "b"' not in text
    # Warning fired with the canonical phrase from the log line.
    assert any("cap reached" in r.message for r in caplog.records), \
        f"expected 'cap reached' in log records, got {[r.message for r in caplog.records]}"


def test_read_terraform_skips_symlinks(tmp_path):
    """Symlinked .tf files are skipped (lines 340-341)."""
    proj = tmp_path / "with_link"
    proj.mkdir()
    real = proj / "real.tf"
    real.write_text('resource "aws_s3_bucket" "r" {}\n', encoding="utf-8")
    link = proj / "link.tf"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/permission")
    text = _read_terraform(proj)
    # The real file is read; the link is dropped.
    assert text.count('"r"') == 1


def test_read_terraform_skips_files_with_oserror_on_stat(tmp_path):
    """`f.stat()` may raise OSError on broken symlinks / weird FS — that
    file is skipped, not crashed on (lines 346-347).

    Implementation note: in Python 3.13's pathlib, `Path.is_symlink()`
    routes through `Path.lstat()` which in turn calls the same stat
    machinery. Naively patching `Path.stat` will therefore also break
    `is_symlink`. So we patch ONLY for non-symlink stat() — by checking
    the call stack via a flag, or simpler: patch `stat` to raise only
    for the specific bad file AFTER is_symlink has already been called
    by patching at a name-based level."""
    proj = tmp_path / "stat_err"
    proj.mkdir()
    good = proj / "good.tf"
    bad = proj / "bad.tf"
    good.write_text('resource "aws_s3_bucket" "g" {}\n', encoding="utf-8")
    bad.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")

    real_stat = Path.stat
    real_lstat = Path.lstat

    def fake_stat(self, *a, **kw):
        # OSError only for the bad file, only on real stat (not lstat).
        if self.name == "bad.tf" and kw.get("follow_symlinks") is not False:
            raise OSError("simulated stat failure")
        return real_stat(self, *a, **kw)

    def fake_lstat(self, *a, **kw):
        # Pass through — never raise, so is_symlink works normally.
        return real_lstat(self, *a, **kw)

    with patch.object(Path, "stat", fake_stat), patch.object(Path, "lstat", fake_lstat):
        text = _read_terraform(proj)
    assert 'resource "aws_s3_bucket" "g"' in text
    assert 'resource "aws_s3_bucket" "x"' not in text


def test_read_terraform_skips_files_with_oserror_on_is_symlink(tmp_path):
    """`f.is_symlink()` raises OSError on some weird FS conditions —
    skip that file (lines 342-343)."""
    proj = tmp_path / "symlink_err"
    proj.mkdir()
    good = proj / "good.tf"
    bad = proj / "bad.tf"
    good.write_text('resource "aws_s3_bucket" "g" {}\n', encoding="utf-8")
    bad.write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")

    real_is_symlink = Path.is_symlink

    def fake_is_symlink(self):
        if self.name == "bad.tf":
            raise OSError("simulated is_symlink failure")
        return real_is_symlink(self)

    with patch.object(Path, "is_symlink", fake_is_symlink):
        text = _read_terraform(proj)
    assert 'resource "aws_s3_bucket" "g"' in text
    assert 'resource "aws_s3_bucket" "x"' not in text


def test_read_terraform_skips_vendored_dirs(tmp_path):
    """Files under .terraform/, .git/, node_modules/ are NOT read."""
    proj = tmp_path / "vendored"
    proj.mkdir()
    (proj / ".terraform").mkdir()
    (proj / ".git").mkdir()
    (proj / "src").mkdir()
    (proj / "real.tf").write_text('resource "aws_s3_bucket" "r" {}\n', encoding="utf-8")
    (proj / ".terraform" / "vendor.tf").write_text(
        'resource "aws_s3_bucket" "vendored" {}\n', encoding="utf-8"
    )
    (proj / ".git" / "ignored.tf").write_text(
        'resource "aws_s3_bucket" "ignored" {}\n', encoding="utf-8"
    )
    (proj / "src" / "extra.tf").write_text(
        'resource "aws_s3_bucket" "extra" {}\n', encoding="utf-8"
    )
    text = _read_terraform(proj)
    assert '"r"' in text
    assert '"extra"' in text
    assert '"vendored"' not in text
    assert '"ignored"' not in text


# ---------------------------------------------------------------------------
# parse_terraform: HCL pseudo-namespaces + vendor inference + brace edge
# ---------------------------------------------------------------------------


def test_parse_terraform_hcl_pseudo_namespaces_not_dataflows(tmp_path):
    """`var.foo`, `local.bar`, `data.x.y`, `module.a.b`, etc. must not
    become fake dataflows (lines 408-415)."""
    src = """
    resource "aws_s3_bucket" "data_lake" {
      bucket = "${var.bucket_name}-${local.suffix}"
      tags   = data.aws_caller_identity.current.account_id
    }
    resource "aws_lambda_function" "f" {
      function_name = module.naming.lambda_name
    }
    """
    p = tmp_path / "pseudo.tf"
    p.write_text(src, encoding="utf-8")
    sys_obj = parse_terraform(p)
    # No dataflows generated — var/local/data/module are filtered.
    assert sys_obj.dataflows == []
    # Two real resources.
    assert len(sys_obj.components) == 2


def test_parse_terraform_unknown_vendor_no_meta(tmp_path):
    """A resource whose type doesn't start with aws_/azurerm_/google_
    gets no `vendor` metadata key (line 396-398 negative branch).

    Use a real `oci_objectstorage_bucket` (Oracle Cloud) — the Oracle
    prefix doesn't match the three sniffed vendors, so vendor stays
    blank and the meta dict is missing the `vendor` key.
    """
    src = """
    resource "oci_objectstorage_bucket" "ora" {
      compartment_id = "ocid"
    }
    """
    p = tmp_path / "oci.tf"
    p.write_text(src, encoding="utf-8")
    sys_obj = parse_terraform(p)
    assert len(sys_obj.components) == 1
    meta = sys_obj.components[0].metadata
    assert "vendor" not in meta
    assert meta["terraform_resource"] == "oci_objectstorage_bucket"


def test_parse_terraform_cross_resource_interpolation_dataflow(tmp_path):
    """`${aws_lb.front.arn}` inside one resource's body must produce a
    `reference` dataflow to the named resource (line 433-437)."""
    src = """
    resource "aws_lb" "front" {
      name = "front"
    }
    resource "aws_lambda_function" "api" {
      function_name = "api"
      environment {
        variables = {
          LB_ARN = aws_lb.front.arn
        }
      }
    }
    """
    p = tmp_path / "refs.tf"
    p.write_text(src, encoding="utf-8")
    sys_obj = parse_terraform(p)
    ids = {c.metadata.get("terraform_name"): c.id for c in sys_obj.components}
    # One dataflow from api → front (the lambda references the LB).
    refs = [df for df in sys_obj.dataflows if df.label == "reference"]
    assert any(df.source == ids["api"] and df.target == ids["front"] for df in refs), \
        f"expected api→front reference, got {[(df.source, df.target, df.label) for df in sys_obj.dataflows]}"


def test_parse_terraform_depends_on_dataflow(tmp_path):
    """`depends_on = [aws_lb.front]` produces a `depends_on` dataflow."""
    src = """
    resource "aws_lb" "front" {}
    resource "aws_lambda_function" "api" {
      depends_on = [aws_lb.front]
    }
    """
    p = tmp_path / "depends.tf"
    p.write_text(src, encoding="utf-8")
    sys_obj = parse_terraform(p)
    deps = [df for df in sys_obj.dataflows if df.label == "depends_on"]
    assert len(deps) == 1


def test_parse_terraform_unclosed_brace_block_degrades_gracefully(tmp_path):
    """A `resource "..." "..." {` with no matching `}` — the parser
    must NOT raise. `_balanced_block` returns (open_pos, len(text))
    (line 309) and we end up consuming the rest of the file as the
    body. The resource still surfaces as a component."""
    src = (
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "name"\n'
        '  versioning {\n'
        '    enabled = true\n'
        # No closing braces at all.
    )
    p = tmp_path / "broken.tf"
    p.write_text(src, encoding="utf-8")
    # The parser must NOT raise.
    sys_obj = parse_terraform(p)
    # And the resource still gets a component.
    assert len(sys_obj.components) == 1
    assert sys_obj.components[0].metadata["terraform_name"] == "b"


def test_parse_terraform_directory_mode_with_multiple_files(tmp_path):
    """Directory mode reads + concatenates every .tf — components from
    each file co-exist + cross-file refs link them."""
    proj = tmp_path / "multi"
    proj.mkdir()
    (proj / "main.tf").write_text(
        'resource "aws_lb" "front" {}\n', encoding="utf-8"
    )
    (proj / "lambda.tf").write_text(
        'resource "aws_lambda_function" "api" {\n'
        '  environment { variables = { LB = aws_lb.front.arn } }\n'
        '}\n',
        encoding="utf-8",
    )
    sys_obj = parse_terraform(proj)
    assert len(sys_obj.components) == 2
    # Cross-file reference produces a dataflow.
    refs = [df for df in sys_obj.dataflows if df.label == "reference"]
    assert len(refs) == 1


def test_parse_terraform_balanced_block_no_close_returns_eof():
    """Unit test for `_balanced_block` — when `{` opens but never
    closes, return (open_pos, len(text)) (line 309)."""
    text = "{ no close anywhere"
    start, end = _balanced_block(text, 0)
    assert start == 0
    assert end == len(text)


def test_parse_terraform_empty_input_safe(tmp_path):
    """Empty .tf file produces empty System, no exception."""
    p = tmp_path / "empty.tf"
    p.write_text("", encoding="utf-8")
    sys_obj = parse_terraform(p)
    assert sys_obj.components == []
    assert sys_obj.dataflows == []
    assert sys_obj.trust_boundaries == []
