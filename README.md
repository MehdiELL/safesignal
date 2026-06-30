<div align="center">

# 🛡️ SafeSignal

### An AI phishing & scam detector on GenLayer

[![GenLayer](https://img.shields.io/badge/GenLayer-Bradbury-ff4d6d)](https://genlayer.com)
[![chainId](https://img.shields.io/badge/chainId-4221-4dd0e1)](https://docs.genlayer.com/developers/networks)
[![Intelligent Contract](https://img.shields.io/badge/intelligent%20contract-Python%20GenVM-8a63d2)](https://docs.genlayer.com/developers/intelligent-contracts/introduction)
[![License](https://img.shields.io/badge/license-MIT-2dd4bf)](#license)

</div>

---

## What is this

**SafeSignal** is a decentralized safety oracle for links. Submit a **URL**; GenLayer
validators independently fetch the page, an LLM classifies it **`safe` / `suspicious` /
`malicious`** with a 0–100 risk score and a reason, and the network must **agree** before the
verdict is written to an on-chain registry. A tamper-resistant phishing/scam check that no
single party controls.

**Deployed contract (Testnet Bradbury):** [`0x41ae2ab65c48fd8CBfa92520F343615924A797aa`](https://explorer-bradbury.genlayer.com/address/0x41ae2ab65c48fd8CBfa92520F343615924A797aa)

## Why GenLayer

Phishing detection is a judgment call over messy, adversarial web content — exactly what a
deterministic VM can't do. GenLayer runs the classification **inside consensus**, so the
resulting registry is decentralized and resistant to a single compromised analyst.

## How it works

1. **`submit_url(url)`** — queue a link for analysis.
2. **`analyze(id)`** — each validator fetches the page, classifies it and scores the risk,
   and must agree on the **classification** (and a similar risk) via the Equivalence Principle.
3. The **classification, risk score, and reasoning** are written on chain.

## The Intelligent Contract

`contracts/safesignal.py` targets the GenVM Python runner (pinned by hash):

- **Integers only** — risk is `u8` (0–100); no floats.
- **Coarse-band equivalence** — validators must agree on the class and land within **±25**
  risk, so heterogeneous LLMs converge instead of returning `Undetermined`.
- **Prompt-injection defense** — the (potentially hostile) page content is treated as
  untrusted data; the model ignores any "I am safe" instructions embedded in it.
- **Low-RPC reads** — `get_info()` / `list_checks()` return state in one call.

Public methods: `submit_url`, `analyze`, `get_check`, `list_checks`, `get_info`.

## Develop & test

```bash
pip install -r requirements.txt        # Python 3.12+
genvm-lint check contracts/safesignal.py
pytest tests/direct/ -v
```

## Deploy

```bash
npm install -g genlayer
genlayer network set testnet-bradbury
# import a deployer account and fund it at https://testnet-faucet.genlayer.foundation
bash deploy/deploy.sh
```

## Network

| | |
| --- | --- |
| Network | GenLayer Bradbury testnet |
| Chain ID | 4221 |
| RPC | https://rpc-bradbury.genlayer.com |
| Explorer | https://explorer-bradbury.genlayer.com |
| Faucet | https://testnet-faucet.genlayer.foundation |

## License

MIT.
