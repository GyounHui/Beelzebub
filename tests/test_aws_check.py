import os
import json
import tempfile
import pytest

from lib.tools import aws_check


def test_extract_keys_from_line():
    line = "AKIAAAAAAAAAAAAAAAAA:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
    ak, sk = aws_check.extract_keys_from_line(line)
    assert ak is not None
    # secret matched by generic 40-char pattern
    assert sk is not None


def test_run_from_file_parsing_and_writing(tmp_path, monkeypatch):
    # Create a fake input file with two lines: one valid-like, one invalid
    file_path = tmp_path / "aws_keys.txt"
    file_path.write_text("AKIAFAKEKEY1234567890:secrettokenplaceholder1234567890123456\nnot-a-key\n")

    # Monkeypatch validate_aws_key to avoid real AWS calls
    def fake_validate(access_key, secret_key, session_token=None, region="us-east-1"):
        if access_key.startswith("AKIA"):
            return True, {"Arn": "arn:aws:iam::123456789012:user/test"}
        return False, "invalid"

    monkeypatch.setattr(aws_check, "validate_aws_key", fake_validate)

    out_valid, out_invalid = aws_check.run_from_file(str(file_path), list_buckets=False, output_dir=str(tmp_path))

    assert os.path.exists(out_valid)
    assert os.path.exists(out_invalid)

    with open(out_valid, "r") as f:
        lines = [json.loads(l) for l in f.readlines()]
    assert any("identity" in rec for rec in lines)
