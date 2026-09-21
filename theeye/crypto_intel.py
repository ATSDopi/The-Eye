"""Crypto address intelligence — 100% free public explorers, no API keys.

Detects the chain from the address format, then queries:
  - blockcypher  : btc, ltc, doge, dash, eth — balance, tx count (no key)
  - mempool.space: btc — confirmed/unconfirmed balance + tx count
  - blockchain.info: btc — final_balance, total received
  - ethplorer    : eth — ETH balance + ERC-20 token count (freeKey tier)
  - solana rpc   : sol — lamports balance via public JSON-RPC
  - monero       : format only — balances are private by design
"""

from __future__ import annotations

import asyncio
import re

import httpx

from .engine import USER_AGENTS
from .models import SiteResult, Status

UA = {"User-Agent": USER_AGENTS[0]}

BTC_RE = re.compile(r"^(bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
LTC_RE = re.compile(r"^(ltc1[a-z0-9]{11,71}|[LM][a-km-zA-HJ-NP-Z1-9]{25,33})$")
DOGE_RE = re.compile(r"^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$")
XMR_RE = re.compile(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")
SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

CHAINS = {  # chain -> blockcypher coin code (None = not supported there)
    "bitcoin": "btc", "litecoin": "ltc", "dogecoin": "doge",
    "dash": "dash", "ethereum": "eth",
}


def detect_chain(address: str) -> str | None:
    a = address.strip()
    if ETH_RE.match(a):
        return "ethereum"
    if BTC_RE.match(a):
        return "bitcoin"
    if LTC_RE.match(a):
        return "litecoin"
    if DOGE_RE.match(a):
        return "dogecoin"
    if XMR_RE.match(a):
        return "monero"
    if SOL_RE.match(a) and not BTC_RE.match(a):
        return "solana?"          # base58 is ambiguous — mark uncertain
    return None


def _r(module: str, status: Status, reason: str, data: dict | None = None,
       url: str | None = None) -> SiteResult:
    return SiteResult(site=module, status=status, reason=reason,
                      enriched=data or {}, url=url, query=module)


def check_detect(address: str) -> SiteResult:
    chain = detect_chain(address)
    if not chain:
        return _r("detect", Status.ILLEGAL,
                  "unrecognised address format (btc/eth/ltc/doge/xmr/sol)")
    r = _r("detect", Status.FOUND, f"chain: {chain}", {"chain": chain})
    if chain == "monero":
        r.reason = "monero address — balances are private by design"
    if chain.endswith("?"):
        r.reason = f"possible {chain[:-1]} address (ambiguous base58 format)"
    return r


async def check_blockcypher(client: httpx.AsyncClient, address: str,
                            chain: str) -> SiteResult:
    coin = CHAINS.get(chain)
    if not coin:
        return _r("blockcypher", Status.UNKNOWN,
                  f"{chain} not supported by blockcypher")
    try:
        resp = await client.get(
            f"https://api.blockcypher.com/v1/{coin}/main/addrs/{address}/balance",
            headers=UA, timeout=15)
    except Exception as e:
        return _r("blockcypher", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("blockcypher", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if "error" in js:
        return _r("blockcypher", Status.ILLEGAL, js["error"][:80])
    data = {
        "balance": js.get("final_balance"),
        "total_received": js.get("total_received"),
        "total_sent": js.get("total_sent"),
        "tx_count": js.get("n_tx"),
        "unconfirmed_balance": js.get("unconfirmed_balance"),
        "unit": "satoshi/wei",
    }
    used = (js.get("n_tx") or 0) > 0
    return _r("blockcypher", Status.FOUND if used else Status.NOT_FOUND,
              f"{js.get('n_tx', 0)} tx · balance {js.get('final_balance')} "
              f"· received {js.get('total_received')} (base units)", data)


async def check_mempool(client: httpx.AsyncClient, address: str,
                        chain: str) -> SiteResult:
    if chain != "bitcoin":
        return _r("mempool.space", Status.UNKNOWN, "bitcoin only")
    try:
        resp = await client.get(f"https://mempool.space/api/address/{address}",
                                headers=UA, timeout=15)
    except Exception as e:
        return _r("mempool.space", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("mempool.space", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    cs, ms = js.get("chain_stats", {}), js.get("mempool_stats", {})
    funded = cs.get("funded_txo_sum", 0) + ms.get("funded_txo_sum", 0)
    spent = cs.get("spent_txo_sum", 0) + ms.get("spent_txo_sum", 0)
    tx = cs.get("tx_count", 0) + ms.get("tx_count", 0)
    data = {"balance_btc": round((funded - spent) / 1e8, 8),
            "tx_count": tx, "funded_btc": round(funded / 1e8, 8),
            "spent_btc": round(spent / 1e8, 8)}
    return _r("mempool.space", Status.FOUND if tx else Status.NOT_FOUND,
              f"{tx} tx · balance {data['balance_btc']} BTC", data,
              url=f"https://mempool.space/address/{address}")


async def check_blockchain_info(client: httpx.AsyncClient, address: str,
                                chain: str) -> SiteResult:
    if chain != "bitcoin":
        return _r("blockchain.info", Status.UNKNOWN, "bitcoin only")
    try:
        resp = await client.get(
            f"https://blockchain.info/rawaddr/{address}",
            params={"limit": 0}, headers=UA, timeout=15)
    except Exception as e:
        return _r("blockchain.info", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("blockchain.info", Status.UNKNOWN, f"HTTP {resp.status_code}")
    try:
        js = resp.json()
    except Exception:
        return _r("blockchain.info", Status.UNKNOWN, "bad json")
    data = {"balance_btc": js.get("final_balance", 0) / 1e8,
            "tx_count": js.get("n_tx"),
            "total_received_btc": js.get("total_received", 0) / 1e8}
    used = (js.get("n_tx") or 0) > 0
    return _r("blockchain.info", Status.FOUND if used else Status.NOT_FOUND,
              f"{data['tx_count']} tx · received {data['total_received_btc']} BTC",
              data, url=f"https://www.blockchain.com/explorer/addresses/btc/{address}")


async def check_ethplorer(client: httpx.AsyncClient, address: str,
                          chain: str) -> SiteResult:
    if chain != "ethereum":
        return _r("ethplorer", Status.UNKNOWN, "ethereum only")
    try:
        resp = await client.get(
            f"https://api.ethplorer.io/getAddressInfo/{address}",
            params={"apiKey": "freeKey", "showETHTotals": "true"},
            headers=UA, timeout=15)
    except Exception as e:
        return _r("ethplorer", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("ethplorer", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if "error" in js:
        return _r("ethplorer", Status.ILLEGAL,
                  str(js["error"].get("message", "?"))[:80])
    eth = js.get("ETH", {})
    tokens = js.get("tokens", [])
    data = {"balance_eth": eth.get("balance"),
            "tx_count": js.get("countTxs"),
            "token_count": len(tokens),
            "tokens": [t.get("tokenInfo", {}).get("symbol")
                       for t in tokens[:15]]}
    used = (js.get("countTxs") or 0) > 0 or (eth.get("balance") or 0) > 0
    tok = f" · {len(tokens)} token(s)" if tokens else ""
    return _r("ethplorer", Status.FOUND if used else Status.NOT_FOUND,
              f"{js.get('countTxs', 0)} tx · {eth.get('balance', 0):.6f} ETH{tok}",
              data, url=f"https://ethplorer.io/address/{address}")


async def check_solana(client: httpx.AsyncClient, address: str,
                       chain: str) -> SiteResult:
    if not chain.startswith("solana"):
        return _r("solana rpc", Status.UNKNOWN, "solana only")
    payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance",
               "params": [address]}
    try:
        resp = await client.post("https://api.mainnet-beta.solana.com",
                                 json=payload, headers=UA, timeout=15)
    except Exception as e:
        return _r("solana rpc", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("solana rpc", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if "error" in js:
        return _r("solana rpc", Status.ILLEGAL,
                  str(js["error"].get("message", "?"))[:80])
    lamports = js.get("result", {}).get("value", 0)
    return _r("solana rpc", Status.FOUND if lamports else Status.NOT_FOUND,
              f"balance {lamports / 1e9:.6f} SOL",
              {"balance_sol": lamports / 1e9})


CHECKS = [check_blockcypher, check_mempool, check_blockchain_info,
          check_ethplorer, check_solana]
MODULES = ["detect"] + [fn.__name__[6:] for fn in CHECKS]


async def run_crypto_scan(address: str, timeout: float = 15.0,
                          proxy: str | None = None) -> list[SiteResult]:
    det = check_detect(address)
    if det.status == Status.ILLEGAL:
        return [det]
    chain = det.enriched["chain"]
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy,
                                 follow_redirects=True) as client:
        rest = await asyncio.gather(
            *(fn(client, address.strip(), chain) for fn in CHECKS))
    # hide modules that don't apply to this chain
    rest = [r for r in rest
            if not (r.status == Status.UNKNOWN and " only" in r.reason)]
    if chain == "monero":
        rest.append(_r("note", Status.UNKNOWN,
                       "monero has no public balance explorer — "
                       "address format valid, ledger opaque"))
    return [det, *rest]
