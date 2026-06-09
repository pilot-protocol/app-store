# app-store examples

Reference Pilot apps. Read these to learn the supervisor lifecycle
contract, the manifest schema, and the trust regimes.

| Example | What it shows |
|---|---|
| [`hello-world/`](hello-world/) | The smallest possible app: one IPC method, sideload-safe manifest, three-command build → install → call. Start here. |

For a production-scale example see the **wallet**
([`pilot-protocol/wallet`](https://github.com/pilot-protocol/wallet)):
multichain EVM payments, spend caps from manifest grants, hook
participation in `send-message` primitives, settler integration.
