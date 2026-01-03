import argparse
import base64
import hashlib
import json
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path

import cv2
import pyotp
import qrcode


@dataclass(frozen=True)
class TotpCredential:
    issuer: str
    account: str
    secret_base32: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"

    def digest_callable(self):
        alg = self.algorithm.upper()
        if alg == "SHA1":
            return hashlib.sha1
        if alg == "SHA256":
            return hashlib.sha256
        if alg == "SHA512":
            return hashlib.sha512
        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def provisioning_uri(self) -> str:
        totp = pyotp.TOTP(
            self.secret_base32,
            digits=self.digits,
            interval=self.period,
            digest=self.digest_callable(),
        )
        return totp.provisioning_uri(name=self.account, issuer_name=self.issuer)

    def totp(self) -> pyotp.TOTP:
        return pyotp.TOTP(
            self.secret_base32,
            digits=self.digits,
            interval=self.period,
            digest=self.digest_callable(),
        )


def generate_secret_base32(num_bytes: int = 20) -> str:
    # 20 bytes is common (160-bit) for TOTP/HOTP
    raw = os.urandom(num_bytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


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
    payload, points, _ = detector.detectAndDecode(img)
    if not payload:
        raise ValueError(f"No QR payload decoded from: {image_path}")
    return payload


def pretty_time(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


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

    uri = cred.provisioning_uri()
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

    # Simulate: phone scans QR -> gets secret -> generates 6-digit code
    phone_like = pyotp.parse_uri(decoded_uri)

    now = int(time.time())
    code_from_phone = phone_like.now()
    code_from_local_secret = cred.totp().now()

    print(f"[compare] now = {pretty_time(now)} ({now})")
    print(f"[compare] code (from decoded QR)   = {code_from_phone}")
    print(f"[compare] code (from stored secret)= {code_from_local_secret}")

    ok = code_from_phone == code_from_local_secret
    print(f"[compare] match = {ok}")
    return 0 if ok else 2


def cmd_random_time_verify(args: argparse.Namespace) -> int:
    cred = load_credential(Path(args.cred))
    totp = cred.totp()

    # Choose a random timestamp around now (default ±12 hours)
    now = int(time.time())
    delta = random.randint(-args.window_seconds, args.window_seconds)
    ts = now + delta

    # Generate a code at that time, then verify at the same time.
    code = totp.at(ts)

    # valid_window=1 means accept adjacent time-step too.
    verified = totp.verify(code, for_time=ts, valid_window=args.valid_window)

    print(f"[verify] random time = {pretty_time(ts)} ({ts})")
    print(f"[verify] generated code at time    = {code}")
    print(f"[verify] verify(for_time=ts)       = {verified}")
    print(
        f"[verify] params: digits={cred.digits} period={cred.period} alg={cred.algorithm} valid_window={args.valid_window}"
    )

    return 0 if verified else 3


def cmd_check_user_code(args: argparse.Namespace) -> int:
    cred = load_credential(Path(args.cred))
    totp = cred.totp()

    code = args.code
    if not code:
        code = input("请输入手机上的 6 位动态码: ").strip()
    code = code.replace(" ", "")

    now = int(time.time())
    verified = totp.verify(code, for_time=now, valid_window=args.valid_window)

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
            "2FA (TOTP) end-to-end demo: generate secret -> QR (otpauth URI) -> decode QR -> compare codes -> random-time verify"
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
        help="accepted drift in number of periods (pyotp valid_window)",
    )
    p_verify.set_defaults(func=cmd_random_time_verify)

    p_check = sub.add_parser("check", help="input a 6-digit code from phone and verify")
    p_check.add_argument("--code", default=None, help="6-digit code (if omitted, will prompt)")
    p_check.add_argument(
        "--valid-window",
        type=int,
        default=1,
        help="accepted drift in number of periods (pyotp valid_window)",
    )
    p_check.set_defaults(func=cmd_check_user_code)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
