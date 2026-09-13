const PUBLIC_MATCH = Object.freeze({
  id: "opaque-match-1",
  seed_label: "Desk backup",
  seed_index: 0,
  address: "t1-public-fixture-address",
  pool: "transparent",
  path: "m/44'/133'/0'/0/7",
  account: 0,
  scope: "receive",
  index: 7,
});

function snapshot(overrides = {}) {
  return {
    id: "opaque-search-1",
    status: "complete",
    checked: 80,
    total: 80,
    target: PUBLIC_MATCH.address,
    network: "mainnet",
    profile: "zecwallet_lite",
    account_start: 0,
    account_count: 2,
    index_start: 0,
    index_count: 20,
    include_change: true,
    matches: [PUBLIC_MATCH],
    ...overrides,
  };
}

module.exports = { PUBLIC_MATCH, snapshot };
