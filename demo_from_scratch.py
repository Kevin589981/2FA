import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

import cv2
import qrcode


@dataclass(frozen=True)
class TotpCredential:
    issuer: str
    account: str
    secret_base32: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"  # SHA1/SHA256/SHA512

    def digest_callable(self):
        alg = self.algorithm.upper()
        if alg == "SHA1":
            return hashlib.sha1
        if alg == "SHA256":
            return hashlib.sha256
        if alg == "SHA512":
            return hashlib.sha512
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")


def pretty_time(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def generate_secret_base32(num_bytes: int = 20) -> str:
    raw = os.urandom(num_bytes)
    # Uppercase, without padding, matches common otpauth QR expectations
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def base32_decode_no_padding(secret_base32: str) -> bytes:
    s = secret_base32.strip().replace(" ", "").upper()
    # Base32 needs length multiple of 8; add padding if missing.
    pad_len = (-len(s)) % 8
    s_padded = s + ("=" * pad_len)
    return base64.b32decode(s_padded, casefold=True)


def hotp(key: bytes, counter: int, digits: int, digestmod) -> str:
    # RFC 4226
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, digestmod).digest()
    offset = h[-1] & 0x0F
    truncated = h[offset : offset + 4]
    code_int = struct.unpack(">I", truncated)[0] & 0x7FFFFFFF
    code = code_int % (10**digits)
    return str(code).zfill(digits)


def totp(
    secret_base32: str,
    for_time: int,
    digits: int = 6,
    period: int = 30,
    t0: int = 0,
    digestmod=hashlib.sha1,
) -> str:
    # RFC 6238
    if period <= 0:
        raise ValueError("period must be positive")
    counter = (int(for_time) - int(t0)) // int(period)
    key = base32_decode_no_padding(secret_base32)
    return hotp(key=key, counter=counter, digits=digits, digestmod=digestmod)


def totp_verify(
    secret_base32: str,
    code: str,
    for_time: int,
    digits: int = 6,
    period: int = 30,
    t0: int = 0,
    digestmod=hashlib.sha1,
    valid_window: int = 1,
) -> bool:
    # Allow drift in number of time-steps (periods)
    code_norm = code.strip().replace(" ", "")
    if not code_norm.isdigit():
        return False

    counter_now = (int(for_time) - int(t0)) // int(period)
    for delta in range(-valid_window, valid_window + 1):
        counter = counter_now + delta
        if counter < 0:
            continue
        expected = hotp(
            key=base32_decode_no_padding(secret_base32),
            counter=counter,
            digits=digits,
            digestmod=digestmod,
        )
        if hmac.compare_digest(expected, code_norm):
            return True
    return False


def provisioning_uri(cred: TotpCredential) -> str:
    # Google Authenticator style otpauth URI
    # otpauth://totp/{issuer}:{account}?secret=...&issuer=...&algorithm=...&digits=...&period=...
    label = f"{cred.issuer}:{cred.account}"
    path = "/" + quote(label, safe="")
    query = urlencode(
        {
            "secret": cred.secret_base32,
            "issuer": cred.issuer,
            "algorithm": cred.algorithm.upper(),
            "digits": str(int(cred.digits)),
            "period": str(int(cred.period)),
        }
    )
    return f"otpauth://totp{path}?{query}"


def parse_otpauth_uri(uri: str) -> TotpCredential:
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError("Not an otpauth URI")
    if parsed.netloc.lower() != "totp":
        raise ValueError("Only totp type is supported")

    qs = parse_qs(parsed.query)

    secret = (qs.get("secret") or [None])[0]
    if not secret:
        raise ValueError("Missing secret in otpauth URI")

    issuer = (qs.get("issuer") or [""])[0]

    algorithm = (qs.get("algorithm") or ["SHA1"])[0]
    digits = int((qs.get("digits") or ["6"])[0])
    period = int((qs.get("period") or ["30"])[0])

    # Label path like /Issuer:account (may contain issuer again)
    label = parsed.path.lstrip("/")
    if ":" in label:
        label_issuer, account = label.split(":", 1)
        account = account
        if not issuer:
            issuer = label_issuer
    else:
        account = label

    return TotpCredential(
        issuer=issuer or "",
        account=account,
        secret_base32=secret,
        digits=digits,
        period=period,
        algorithm=algorithm,
    )


def save_credential(path: Path, cred: TotpCredential) -> None:
    path.write_text(
        json.dumps(
            {
                "issuer": cred.issuer,
                "account": cred.account,
                "secret_base32": cred.secret_base32,
                "digits": cred.digits,
                "period": cred.period,
                "algorithm": cred.algorithm,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def load_credential(path: Path) -> TotpCredential:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return TotpCredential(
        issuer=obj["issuer"],
        account=obj["account"],
        secret_base32=obj["secret_base32"],
        digits=int(obj.get("digits", 6)),
        period=int(obj.get("period", 30)),
        algorithm=str(obj.get("algorithm", "SHA1")),
    )


def write_qr_png(data: str, out_path: Path) -> None:
    img = qrcode.make(data)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path)


def decode_qr_from_image(image_path: Path) -> str:
    img = cv2.imread(str(image_path))
    if img is None:
        raise FileNotFoundError(f"Cannot read image: {image_path}")

    detector = cv2.QRCodeDetector()
    payload, _, _ = detector.detectAndDecode(img)
    if not payload:
        raise ValueError(f"No QR payload decoded from: {image_path}")
    return payload


def cmd_init(args: argparse.Namespace) -> int:
    cred_path = Path(args.cred)
    qr_path = Path(args.qr)

    cred = TotpCredential(
        issuer=args.issuer,
        account=args.account,
        secret_base32=generate_secret_base32(num_bytes=args.bytes),
        digits=args.digits,
        period=args.period,
        algorithm=args.algorithm,
    )

    save_credential(cred_path, cred)

    uri = provisioning_uri(cred)
    write_qr_png(uri, qr_path)

    print("[init] saved credential:", cred_path)
    print("[init] saved QR image:", qr_path)
    print("[init] otpauth URI:")
    print(uri)
    return 0


def cmd_scan_and_compare(args: argparse.Namespace) -> int:
    cred = load_credential(Path(args.cred))

    decoded_uri = decode_qr_from_image(Path(args.qr))
    print("[scan] decoded otpauth URI:")
    print(decoded_uri)

    # Simulate: phone scans QR -> gets secret/params
    from_qr = parse_otpauth_uri(decoded_uri)

    now = int(time.time())

    code_from_phone_like = totp(
        secret_base32=from_qr.secret_base32,
        for_time=now,
        digits=from_qr.digits,
        period=from_qr.period,
        digestmod=from_qr.digest_callable(),
    )

    code_from_stored_secret = totp(
        secret_base32=cred.secret_base32,
        for_time=now,
        digits=cred.digits,
        period=cred.period,
        digestmod=cred.digest_callable(),
    )

    print(f"[compare] now = {pretty_time(now)} ({now})")
    print(f"[compare] code (from decoded QR)   = {code_from_phone_like}")
    print(f"[compare] code (from stored secret)= {code_from_stored_secret}")

    ok = code_from_phone_like == code_from_stored_secret
    print(f"[compare] match = {ok}")
    return 0 if ok else 2


def cmd_random_time_verify(args: argparse.Namespace) -> int:
    cred = load_credential(Path(args.cred))

    now = int(time.time())
    delta = random.randint(-args.window_seconds, args.window_seconds)
    ts = now + delta

    code = totp(
        secret_base32=cred.secret_base32,
        for_time=ts,
        digits=cred.digits,
        period=cred.period,
        digestmod=cred.digest_callable(),
    )

    verified = totp_verify(
        secret_base32=cred.secret_base32,
        code=code,
        for_time=ts,
        digits=cred.digits,
        period=cred.period,
        digestmod=cred.digest_callable(),
        valid_window=args.valid_window,
    )

    print(f"[verify] random time = {pretty_time(ts)} ({ts})")
    print(f"[verify] generated code at time    = {code}")
    print(f"[verify] verify(for_time=ts)       = {verified}")
    print(
        f"[verify] params: digits={cred.digits} period={cred.period} alg={cred.algorithm} valid_window={args.valid_window}"
    )

    return 0 if verified else 3


def cmd_check_user_code(args: argparse.Namespace) -> int:
    cred = load_credential(Path(args.cred))

    code = args.code
    if not code:
        code = input("请输入手机上的 6 位动态码: ").strip()
    code = code.replace(" ", "")

    now = int(time.time())
    verified = totp_verify(
        secret_base32=cred.secret_base32,
        code=code,
        for_time=now,
        digits=cred.digits,
        period=cred.period,
        digestmod=cred.digest_callable(),
        valid_window=args.valid_window,
    )

    print(f"[check] now = {pretty_time(now)} ({now})")
    print(f"[check] input code = {code}")
    print(f"[check] verified = {verified}")
    print(
        f"[check] params: digits={cred.digits} period={cred.period} alg={cred.algorithm} valid_window={args.valid_window}"
    )

    return 0 if verified else 4


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "2FA (TOTP) from-scratch demo: Base32/HOTP/TOTP/otpauth URI without pyotp; QR generate/decode + verify"
        )
    )

    p.add_argument("--cred", default="totp_credential.json", help="credential json path")
    p.add_argument("--qr", default="totp_qr.png", help="QR png path")

    sub = p.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="generate credential + save QR")
    p_init.add_argument("--issuer", default="DemoIssuer", help="issuer shown in authenticator")
    p_init.add_argument("--account", default="demo@example.com", help="account name shown in authenticator")
    p_init.add_argument("--digits", type=int, default=6, help="TOTP digits")
    p_init.add_argument("--period", type=int, default=30, help="TOTP period seconds")
    p_init.add_argument("--algorithm", default="SHA1", help="SHA1/SHA256/SHA512")
    p_init.add_argument("--bytes", type=int, default=20, help="secret bytes before base32")
    p_init.set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="decode QR image and compare codes")
    p_scan.set_defaults(func=cmd_scan_and_compare)

    p_verify = sub.add_parser("verify", help="verify at a random timestamp")
    p_verify.add_argument(
        "--window-seconds",
        type=int,
        default=12 * 3600,
        help="random timestamp range around now (±seconds)",
    )
    p_verify.add_argument(
        "--valid-window",
        type=int,
        default=1,
        help="accepted drift in number of periods (time-steps)",
    )
    p_verify.set_defaults(func=cmd_random_time_verify)

    p_check = sub.add_parser("check", help="input a 6-digit code from phone and verify")
    p_check.add_argument("--code", default=None, help="6-digit code (if omitted, will prompt)")
    p_check.add_argument(
        "--valid-window",
        type=int,
        default=1,
        help="accepted drift in number of periods (time-steps)",
    )
    p_check.set_defaults(func=cmd_check_user_code)

    return p


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
