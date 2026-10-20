"""One budget, a few local HTTP 402s, a signed voucher for each, one left unsigned.

    TREESHIP_BIN=/path/to/treeship python -m treeship_commerce.demo_402

A payer agent is given a task and a spending limit. Each seller answers
the first request with HTTP 402. When the amount still fits the budget, the
agent signs a voucher and the seller delivers. The voucher is a Treeship
receipt (``payment.voucher.sign``). The seller in this process checks that
receipt with ``treeship verify`` and then delivers. When the next amount
would pass the limit, the agent signs no voucher and does not pay.

This is the buy side of a machine-payment diagram: task, budget, 402,
voucher, delivery. Validation, redemption, a settlement guarantee, escrow,
and the movement of money are a network's step. This process does not take
it, and it does not speak to Mastercard Agent Pay for Machines. The voucher
scheme is ``local.402.v1``, minted here.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

from treeship_sdk import Treeship, TreeshipError

from .lifecycle import close_session, open_demo_session
from .receipts import TreeshipReceipts

ACTOR = "agent://payer"
PRINCIPAL = "principal://campaign"
BUDGET_MINOR = 500
CURRENCY = "USD"
SCHEME = "local.402.v1"
_ART = re.compile(r"art_[0-9a-f]{32}")

# Three calls fit. The fourth would, and is withheld.
OFFERS = (
    {"payee": "research.example", "service": "social-research", "amount_minor": 150},
    {"payee": "images.example", "service": "campaign-image", "amount_minor": 200},
    {"payee": "images.example", "service": "campaign-image", "amount_minor": 100},
    {"payee": "images.example", "service": "campaign-image", "amount_minor": 100},
)


def _statement(path: Path) -> dict[str, Any]:
    record = json.loads(path.read_text())
    payload = record["envelope"]["payload"]
    padded = payload + "=" * (-len(payload) % 4)
    statement = json.loads(base64.urlsafe_b64decode(padded))
    if not isinstance(statement, dict):
        raise ValueError("artifact payload is not an object")
    return statement


class _Seller:
    """A localhost seller. 402 until shown a voucher this ship can verify."""

    def __init__(self, root: Path, binary: str, env: dict[str, str]) -> None:
        self.root = root
        self.binary = binary
        self.env = env
        self.offers: dict[str, dict[str, Any]] = {}
        self.redeemed: set[str] = set()
        self.delivered: list[dict[str, Any]] = []
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        seller = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802 — stdlib name
                seller._handle(self)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        if parsed.path != "/v1/resource":
            self._send(handler, 404, {"error": "not found"})
            return
        query = parse_qs(parsed.query)
        try:
            offer = {
                "payee": query["payee"][0],
                "service": query["service"][0],
                "amount_minor": int(query["amount"][0]),
                "currency": CURRENCY,
            }
        except (KeyError, ValueError, IndexError):
            self._send(handler, 400, {"error": "payee, service, and amount are required"})
            return
        voucher = handler.headers.get("X-Local-Voucher")
        if not voucher:
            challenge = secrets.token_hex(16)
            self.offers[challenge] = offer
            self._send(
                handler,
                402,
                {
                    "scheme": SCHEME,
                    "challenge": challenge,
                    **offer,
                    "settlement": "not performed",
                },
            )
            return
        try:
            body = self._redeem(voucher, offer)
        except ValueError as err:
            self._send(handler, 403, {"error": str(err), "settlement": "not performed"})
            return
        self._send(handler, 200, body)

    def _redeem(self, artifact_id: str, offer: dict[str, Any]) -> dict[str, Any]:
        if not _ART.fullmatch(artifact_id):
            raise ValueError("voucher id is not an artifact id")
        if artifact_id in self.redeemed:
            raise ValueError("voucher already redeemed in this process")
        path = self.root / ".treeship" / "artifacts" / f"{artifact_id}.json"
        if not path.is_file():
            raise ValueError("voucher receipt is not in this ship")
        statement = _statement(path)
        meta = statement.get("meta") if isinstance(statement.get("meta"), dict) else {}
        if statement.get("action") != "payment.voucher.sign":
            raise ValueError("receipt is not a voucher")
        challenge = meta.get("challenge")
        issued = self.offers.get(challenge) if isinstance(challenge, str) else None
        if issued is None:
            raise ValueError("voucher names no challenge this seller issued")
        for field in ("payee", "service", "amount_minor", "currency"):
            if meta.get(field) != issued[field] or offer[field] != issued[field]:
                raise ValueError(f"voucher {field} does not match the 402")
        proc = subprocess.run(
            [self.binary, "verify", artifact_id],
            cwd=self.root,
            env={**os.environ, **self.env},
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise ValueError("treeship verify rejected the voucher")
        self.redeemed.add(artifact_id)
        resource = f"{offer['service']}-{len(self.delivered) + 1}"
        record = {**offer, "voucher": artifact_id, "resource": resource}
        self.delivered.append(record)
        return {"delivered": True, "resource": resource, "settlement": "not performed"}

    @staticmethod
    def _send(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)


def _get(base: str, offer: dict[str, Any], voucher: str | None) -> tuple[int, dict[str, Any]]:
    query = urlencode(
        {"payee": offer["payee"], "service": offer["service"], "amount": offer["amount_minor"]}
    )
    req = Request(f"{base}/v1/resource?{query}")
    if voucher:
        req.add_header("X-Local-Voucher", voucher)
    try:
        with urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except HTTPError as err:
        return err.code, json.loads(err.read().decode())


async def run(root: Path, binary: str) -> int:
    config = root / ".treeship" / "config.json"
    home = str(root)
    config_path = str(config)
    iso = {"HOME": home, "TREESHIP_CONFIG": config_path, "TREESHIP_ALLOW_INSECURE_KEY_PERMS": "1"}
    env = {**os.environ, **iso}
    init = subprocess.run(
        [binary, "init", "--name", "payer-402-demo", "--config", config_path],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )
    if init.returncode != 0 and not config.is_file():
        sys.exit(init.stderr.strip() or init.stdout.strip() or "treeship init failed")

    ts = Treeship(cli_path=binary, env=iso, cwd=root)
    session_root = open_demo_session(
        ts, name="commerce:402-demo", actor=ACTOR, env=iso, cwd=root
    )
    receipts = TreeshipReceipts(
        ts,
        actor=ACTOR,
        session_id=f"demo-{uuid.uuid4().hex}",
        role="payer",
        parent_id=session_root,
    )
    seller = _Seller(root, binary, iso)
    base = seller.start()
    vouchers: list[dict[str, Any]] = []
    deliveries: list[dict[str, Any]] = []
    withheld: dict[str, Any] | None = None
    spent = 0
    try:
        budget_id = await receipts.attest(
            "payment.budget.approved",
            {
                "principal": PRINCIPAL,
                "task": "Plan a sample campaign",
                "amount_minor": BUDGET_MINOR,
                "currency": CURRENCY,
                "actor_binding": "asserted",
                "settlement": "not performed",
            },
        )
        if not budget_id:
            raise SystemExit("the budget receipt was not signed")
        print(f"budget            {BUDGET_MINOR / 100:.2f} {CURRENCY}  {budget_id}")
        print(f"principal         {PRINCIPAL}  actor binding asserted, same ship key")
        print(f"seller            {base}")

        for offer in OFFERS:
            status, body = _get(base, offer, None)
            if status != 402:
                raise SystemExit(f"{offer['payee']} answered {status}, expected 402")
            nxt = spent + offer["amount_minor"]
            label = f"{offer['payee']} {offer['service']} {offer['amount_minor']}"
            if nxt > BUDGET_MINOR:
                withheld_id = await receipts.attest(
                    "payment.voucher.withheld",
                    {
                        "scheme": SCHEME,
                        "payee": offer["payee"],
                        "service": offer["service"],
                        "amount_minor": offer["amount_minor"],
                        "currency": CURRENCY,
                        "budget_minor": BUDGET_MINOR,
                        "spent_minor": spent,
                        "voucher_signed": False,
                        "reason": "amount would exceed the approved budget",
                        "settlement": "not performed",
                    },
                )
                withheld = {
                    "artifact_id": withheld_id,
                    "payee": offer["payee"],
                    "service": offer["service"],
                    "amount_minor": offer["amount_minor"],
                    "voucher_signed": False,
                }
                print(f"  withhold          {label}  spent {spent}  no voucher  {withheld_id}")
                continue
            voucher_id = await receipts.attest(
                "payment.voucher.sign",
                {
                    "scheme": SCHEME,
                    "challenge": body["challenge"],
                    "payee": offer["payee"],
                    "service": offer["service"],
                    "amount_minor": offer["amount_minor"],
                    "currency": CURRENCY,
                    "budget_minor": BUDGET_MINOR,
                    "spent_before": spent,
                    "spent_after": nxt,
                    "settlement": "not performed",
                },
            )
            if not voucher_id:
                raise SystemExit(f"voucher for {offer['payee']} was not signed")
            paid, delivered = _get(base, offer, voucher_id)
            if paid != 200 or not delivered.get("delivered"):
                raise SystemExit(f"{offer['payee']} did not deliver: {paid} {delivered}")
            delivery_id = await receipts.attest(
                "payment.delivery",
                {
                    "payee": offer["payee"],
                    "service": offer["service"],
                    "amount_minor": offer["amount_minor"],
                    "currency": CURRENCY,
                    "voucher": voucher_id,
                    "resource": delivered["resource"],
                    "settlement": "not performed",
                },
            )
            spent = nxt
            vouchers.append({"artifact_id": voucher_id, **offer})
            deliveries.append({"artifact_id": delivery_id, "resource": delivered["resource"], **offer})
            print(f"  voucher           {label}  {voucher_id}")
            print(f"  delivery          {delivered['resource']}  {delivery_id}")
    finally:
        seller.stop()

    if withheld is None or withheld["voucher_signed"] is not False:
        raise SystemExit("the run signed every payment; the one past the budget should be unsigned")
    if spent != 450 or len(vouchers) != 3 or len(seller.delivered) != 3:
        raise SystemExit(f"unexpected totals spent={spent} vouchers={len(vouchers)} delivered={len(seller.delivered)}")

    out = root / "402-out"
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "status": "ok",
        "scheme": SCHEME,
        "budget_minor": BUDGET_MINOR,
        "spent_minor": spent,
        "currency": CURRENCY,
        "budget": budget_id,
        "vouchers": vouchers,
        "deliveries": deliveries,
        "withheld": withheld,
        "settlement": "not performed",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    sealed = close_session(
        ts,
        summary=(
            f"402 demo: budget {BUDGET_MINOR} minor, {len(vouchers)} vouchers, "
            f"one withheld, settlement not performed."
        ),
        headline="Local HTTP 402 under one budget",
        env=iso,
        cwd=root,
    )
    print(f"spent             {spent} of {BUDGET_MINOR} {CURRENCY} minor")
    print(f"package           {sealed.get('package')}")
    print("settlement         not performed. Validation, redemption, escrow, and payout are a network's step.")
    return 0 if receipts.dropped == 0 else 2


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=None, help="isolated ship directory (default: a temp dir)")
    args = parser.parse_args()
    binary = os.environ.get("TREESHIP_BIN", "treeship")
    if args.root:
        args.root.mkdir(parents=True, exist_ok=True)
        code = asyncio.run(run(args.root, binary))
    else:
        with tempfile.TemporaryDirectory(prefix="ts-402-") as tmp:
            code = asyncio.run(run(Path(tmp), binary))
    raise SystemExit(code)


if __name__ == "__main__":
    try:
        main()
    except TreeshipError as err:
        sys.exit(str(err))
