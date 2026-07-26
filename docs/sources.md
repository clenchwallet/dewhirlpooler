# Behavioral Sources and Fixture Provenance

Retrieved July 25, 2026.

## Ashigaru protocol behavior

- [Ashigaru: Announcement — new Zerolink coinjoin coordinator](https://ashigaru.rs/news/announcement-whirlpool/)
  documents the supported native SegWit address type, 0.025 BTC and 0.25 BTC
  pools, fixed 5% Anti-Sybil fees, maximum of 20 premix outputs per Tx0, and
  participant range.
- [Whirlpool.Observer reference](https://whirlpoolstats.xyz/) describes the
  observed five-input/five-equal-output cycle, Tx0 preparation, doxxic change,
  and the normal mix of Tx0-funded and remix inputs.
- [Whirlpool.Observer recent-cycle API](https://whirlpoolstats.xyz/api/txs?page=1&per_page=5)
  linked the current round fixture to its two direct Tx0 inputs.

These sources describe public protocol and transaction behavior. No
third-party detection implementation was copied or translated.

## Samourai legacy pool behavior

- [Samourai Wallet: Changes to Whirlpool mixing fees effective March
  2021](https://medium.com/samourai-wallet/changes-to-whirlpool-mixing-fees-effective-march-2021-30c8a2a59aed)
  documents the 0.001, 0.01, 0.05, and 0.5 BTC pools; their flat coordinator
  fees; the March 2021 change from 250,000 to 175,000 sats for the 0.05 pool
  and from 2,500,000 to 1,750,000 sats for the 0.5 pool; and the Tx0 output
  limits.
- [Samourai Wallet's first public Whirlpool transaction
  announcement](https://x.com/SamouraiWallet/status/1118538598800871424)
  links the first announced mainnet round. Its public transaction
  `a554db794560458c102bab0af99773883df13bc66ad287c29610ad9bac138926`
  is confirmed at block 572,030; its public premix parents reach back to block
  571,189. The default historical index starts at block 571,000 to cover that
  observed launch boundary with margin.

## Public blockchain fixtures

The test fixtures contain only raw, publicly broadcast Bitcoin transactions:

- Ashigaru 0.025 BTC Tx0:
  `18c999772ed82bf7753bdce9021cfa68b505de36344ce81f77d0c436b7135892`
- Ashigaru 0.025 BTC round:
  `1394d9a5cc423dc71dc576e6b2f3e9639ae3096689d38f77857f809ef277816f`
- Legacy 0.05 BTC Tx0:
  `63679c9ec82f246811acbab0c04cc0fc77ba050e1b6c23661d78afcfc13cf8aa`

Raw hex was independently checked against a public block explorer and the
project's read-only Fulcrum integration. Unit tests read committed fixture
files and never contact a network.

## Public postmix-spend fixtures

- [Ashigaru Wallet 1.0.0 release notes](https://ashigaru.rs/news/release-wallet-v1-0-0/)
  document the fixed 0.001 BTC Ricochet service fee used as one entry signal.
- [Bitcoin Magazine: How To Spend Mixed Bitcoin Privately](https://bitcoinmagazine.com/guides/how-to-spend-mixed-bitcoin-privately)
  publishes worked Stonewall and Ricochet transaction examples.
- Mainnet Stonewall-shaped transaction:
  `f1592e0bec2af9e812d6ada0a46c267885d36358eab54f55098867a718828f53`
  with public input transactions
  `d8e3e8b6159a0f2f7c645323739f01e5be6ecb810cb3d0bed9949c4946024685`
  and
  `f0537c6554069e5ee28641a1f253640163efe9c3cbed8a85416f0544ccd32bec`.
  Its four outputs form exact pairs of 408,297 and 4,588,406 sats.
- Testnet Ricochet entry:
  `779cf99f370694cf5ac66062b3cbdaf9d2755f25e5ed46eae20f7870b224d986`
  with a 100,000-sat fee output and four serial hops:
  `68058a625adf7c9fabaf8b690490b3b6ffdf844abca2db785a5445014095d2ef`,
  `def5aa171c67da36b87fc3f191ac994639cf2b3ef5fab4cc5ad7fa943ac250da`,
  `36e100bbe053e9e8533d4f0f6d29d92887f53ae1e5735e2a3e5f1e5eadcc8ff9`,
  and
  `dd13e8d79a0b5ae43b610b14d31c72e709fbaf43b4c54c611122be4e54fa0eaf`.
  The derived testnet fee address is
  `tb1q740ynw2jj83gak0q38ktfkl65kwkata0jqlsj6`.

The fixture hex was retrieved from the public mempool.space mainnet and
testnet transaction endpoints on July 25, 2026, then committed for fully
offline unit tests. The implementation was derived from the documented public
behavior and transaction serialization; no wallet or chain-analysis
implementation was copied.

## Public Payjoin/Cahoots fingerprint evidence

- [Payjoin wallet-fingerprint analysis](https://payjoin.org/blog/2026/03/25/wallet-fingerprints-payjoin-privacy/)
  describes observable differences between inputs and cites the public
  Samourai testnet Payjoin used here.
- [Cluster-fingerprint follow-up](https://github.com/payjoin/payjoin.org/pull/143)
  describes how feerate, timing, value distribution, clustering cascades, and
  social-graph context can erode Payjoin ambiguity even when wallet-software
  fingerprints match. DeWhirlpooler does not claim that broader history
  analysis; it reports only bounded per-input groups in the selected
  transaction.
- [Unnecessary Input Heuristics and PayJoin Transactions](https://eprint.iacr.org/2022/589)
  defines the UIH1/UIH2 transaction-shape evidence.
The public testnet candidate is
`8dba6657ab9bb44824b3317c8cc3f333c2f465d3668c678691a091cdd6e5984c`,
with parents
`4c18c8880f70b34fb5fc693921fe35a40e355bdc297526452dee9cd9ac29c7fb`
and
`d0bbde77cd404773ef7f94a96033288883eb2dac2bc1b5ac6cfb36484c8c028d`.
Their raw hex was retrieved from the public mempool.space testnet API on
July 26, 2026. The strict local parser independently reproduced all three
transaction IDs. Offline tests resolve input values of 50,000 and 3,999,216
sats, output values of 9,752 and 4,039,216 sats, and a 248-sat miner fee. The
result is UIH1 with differing canonical ECDSA R lengths.

This evidence is consistent with Payjoin, marketed as Cahoots by Samourai, but
does not prove protocol use, wallet brand, ownership, payment, or change.

## Public historical CPFP evidence

The read-only historical index identifies candidate Whirlpool-round outputs
created and spent outside a round in the same block. One public pair is used as
an integration fixture:

- candidate parent round
  `058f865ee0a3cc7c4606552fa8adfc768678e536dc917e6eb45ebda2e464b36b`;
- direct child
  `6fca69f3510c98d8b1433e59fe36be2fadb61d53b6e11609ec45320b6a35d304`;
  and
- shared confirmation height 577,604.

Independent verbosity-3 block data gives the parent a 30,000-sat fee over 505
vB and the child a 15,598-sat fee over 110 vB. Their fee rates are 59.41 and
141.80 sat/vB, and the combined package rate is 74.14 sat/vB. This is public
same-block fee-lift evidence consistent with CPFP; it does not prove intent,
participant identity, or a deterministic coinjoin input-to-output link.

## Clean-room boundary

The parser and detector were written from the behavioral statements above and
the serialized public transactions. The project does not copy or vendor
Dumplings, Samourai, Ashigaru, Whirlpool.Observer, or other detector source
code.

The labels remain heuristics. They describe shapes and amounts visible to any
blockchain observer and do not prove ownership, identity, or coordination by a
specific person.

## Bitcoin Core block source

- [Bitcoin Core 28: `getblock`](https://bitcoincore.org/en/doc/28.0.0/rpc/blockchain/getblock/)
  documents verbosity 3 as full block transaction data including direct
  prevout information for inputs.
- [Bitcoin Core 28: `getblockhash`](https://bitcoincore.org/en/doc/28.0.0/rpc/blockchain/getblockhash/)
  maps an exact main-chain height to its block hash.

The historical index uses these read-only public-chain RPCs so aggregate
results can be reproduced from an operator's own node. It does not use wallet
RPC or a public block-explorer fallback.
