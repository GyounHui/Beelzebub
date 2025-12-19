import re
import os
import json
import time
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import boto3

from lib.tools.utils import clear, banner
from lib.tools.colors import wh, g, r, res


def extract_keys_from_line(line: str):
    # Try to extract common AWS key patterns from a line
    ak_match = re.search(r"(A3T[0-9A-Z]{16}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AROA[0-9A-Z]{16})", line)
    sk_match = re.search(r"([A-Za-z0-9/+=]{40})", line)
    ak = ak_match.group(0) if ak_match else None
    sk = sk_match.group(0) if sk_match else None
    return ak, sk


def validate_aws_key(access_key: str, secret_key: str, session_token: str = None, region: str = "us-east-1"):
    try:
        client = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
        )
        identity = client.get_caller_identity()
        return True, identity
    except NoCredentialsError:
        return False, "No credentials"
    except ClientError as e:
        return False, str(e)
    except EndpointConnectionError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def aws_check():
    clear()
    print(banner)
    print(f"{wh}[{g}+{wh}] AWS Key Validator\n")
    # Interactive wrapper for run_from_file
    default_path = "Result/env-scanner/aws.txt"
    path = input(f"{wh}[{g}+{wh}] Path to AWS keys file (default: {default_path}): {res}").strip() or default_path

    if not os.path.exists(path):
        print(f"{r}[!] File not found: {path}{res}")
        return

    consent = input(f"{wh}[{g}!{wh}] This tool will actively call AWS STS to validate keys. Type 'I consent' to proceed: {res}")
    if consent.strip() != "I consent":
        print(f"{r}[!] Consent not given. Aborting.{res}")
        return

    list_buckets_input = input(f"{wh}[{g}?{wh}] Attempt a safe S3 probe (list buckets) for valid keys? (y/N): {res}")
    list_buckets = list_buckets_input.strip().lower() == 'y'

    run_from_file(path, list_buckets=list_buckets)


def run_from_file(path: str, list_buckets: bool = False, output_dir: str = "Result"):
    """Non-interactive runner. Reads `path` for keys, validates them via STS, and optionally lists S3 buckets.

    Writes two files to `output_dir`: `aws_valid.txt` (json lines) and `aws_invalid.txt`.
    """
    os.makedirs(output_dir, exist_ok=True)
    valid_path = os.path.join(output_dir, "aws_valid.txt")
    invalid_path = os.path.join(output_dir, "aws_invalid.txt")

    valid_out = open(valid_path, "a", encoding="utf-8")
    invalid_out = open(invalid_path, "a", encoding="utf-8")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]

    for line in lines:
        ak, sk = extract_keys_from_line(line)
        if not ak or not sk:
            if ":" in line or "|" in line:
                sep = ":" if ":" in line else "|"
                parts = line.split(sep)
                if len(parts) >= 2:
                    ak = ak or parts[0].strip()
                    sk = sk or parts[1].strip()

        if not ak or not sk:
            invalid_out.write(f"{line} # parse_failed\n")
            continue

        ok, info = validate_aws_key(ak, sk)
        time.sleep(0.1)
        if ok:
            record = {"access_key": ak, "secret_key": "REDACTED", "identity": info}
            # Optionally attempt a safe S3 list-buckets probe
            if list_buckets:
                try:
                    s3 = boto3.client("s3", aws_access_key_id=ak, aws_secret_access_key=sk)
                    resp = s3.list_buckets()
                    buckets = [b.get("Name") for b in resp.get("Buckets", [])]
                    record["buckets"] = buckets
                except Exception as e:
                    record["buckets_error"] = str(e)

            valid_out.write(json.dumps(record) + "\n")
        else:
            invalid_out.write(f"{ak}#{sk} # {info}\n")

    valid_out.close()
    invalid_out.close()
    return valid_path, invalid_path


if __name__ == "__main__":
    aws_check()
