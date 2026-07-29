"use strict";

const EXAMPLE_TXID =
  "18c999772ed82bf7753bdce9021cfa68b505de36344ce81f77d0c436b7135892";
const TXID_PATTERN = /^[0-9a-fA-F]{64}$/;
const LIMITS = {
  max_depth: { id: "max-depth", min: 1, max: 12 },
  max_transactions: { id: "max-transactions", min: 1, max: 500 },
  max_outputs: { id: "max-outputs", min: 1, max: 2000 },
  max_history_lookups: { id: "max-history-lookups", min: 1, max: 2000 },
};

let latestReport = null;
let graph = null;

const form = document.getElementById("trace-form");
const txidInput = document.getElementById("txid");
const analyzeButton = document.getElementById("analyze-button");
const exampleButton = document.getElementById("example-button");
const requestStatus = document.getElementById("request-status");
const errorAlert = document.getElementById("error-alert");
const partialAlert = document.getElementById("partial-alert");
const summaryGrid = document.getElementById("summary-grid");
const warningsPanel = document.getElementById("warnings");
const findingsList = document.getElementById("findings-list");
const detailPanel = document.getElementById("detail-panel");
const graphEmpty = document.getElementById("graph-empty");
const networkStatus = document.getElementById("network-status");
const networkContent = document.getElementById("network-content");
const networkSummary = document.getElementById("network-summary");
const poolList = document.getElementById("pool-list");
const poolHistoryHeading = document.getElementById("pool-history-heading");
const poolHistoryStatus = document.getElementById("pool-history-status");
const poolHistoryTable = document.getElementById("pool-history-table");
const poolHistoryBody = document.getElementById("pool-history-body");

const POOL_NAMES = {
  "ashigaru-0.025": "Ashigaru 0.025 BTC",
  "ashigaru-0.25": "Ashigaru 0.25 BTC",
  "samourai-legacy-0.001": "Samourai legacy 0.001 BTC",
  "samourai-legacy-0.01": "Samourai legacy 0.01 BTC",
  "samourai-legacy-0.05": "Samourai legacy 0.05 BTC",
  "samourai-legacy-0.5": "Samourai legacy 0.5 BTC",
};

function replaceChildren(element, ...children) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
  element.append(...children);
}

function paragraph(text, className = "") {
  const element = document.createElement("p");
  element.textContent = text;
  if (className) {
    element.className = className;
  }
  return element;
}

function readableName(value) {
  if (!value || typeof value !== "string") {
    return "Unknown";
  }
  return value
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function formatSats(value) {
  const sats = Number(value);
  if (!Number.isFinite(sats)) {
    return "Unknown";
  }
  return `${Math.trunc(sats).toLocaleString()} sats`;
}

function formatBtc(value) {
  const sats = Number(value);
  if (!Number.isFinite(sats)) {
    return "Unknown";
  }
  return `${(sats / 100000000).toLocaleString(undefined, {
    maximumFractionDigits: 8,
  })} BTC`;
}

function poolName(poolId) {
  return POOL_NAMES[poolId] || readableName(poolId);
}

function networkSummaryItem(label, value, detail = "") {
  const item = document.createElement("div");
  const labelElement = document.createElement("span");
  const valueElement = document.createElement("strong");
  labelElement.textContent = label;
  valueElement.textContent = value;
  item.append(labelElement, valueElement);
  if (detail) {
    const detailElement = document.createElement("small");
    detailElement.textContent = detail;
    item.appendChild(detailElement);
  }
  return item;
}

function renderNetworkOverview(overview) {
  const coverage =
    overview && typeof overview.coverage === "object"
      ? overview.coverage
      : {};
  const coordinator =
    overview && typeof overview.coordinator === "object"
      ? overview.coordinator
      : {};
  const pools = Array.isArray(overview && overview.pools)
    ? overview.pools
    : [];
  const lastHeight =
    coverage.last_height === null || coverage.last_height === undefined
      ? "Not started"
      : Number(coverage.last_height).toLocaleString();

  replaceChildren(
    networkSummary,
    networkSummaryItem(
      "Indexed blocks",
      Number(coverage.blocks_indexed || 0).toLocaleString(),
      `${Number(coverage.start_height || 0).toLocaleString()} through ${lastHeight}`,
    ),
    networkSummaryItem(
      "Gross coordinator fees",
      formatBtc(coordinator.gross_revenue_sats || 0),
      `${Number(coordinator.fee_output_count || 0).toLocaleString()} fee output(s)`,
    ),
    networkSummaryItem(
      "Known consolidation costs",
      formatSats(coordinator.known_mining_cost_sats || 0),
    ),
    networkSummaryItem(
      "Net known profit",
      formatBtc(coordinator.net_known_profit_sats || 0),
      "Gross fees minus fully attributable mining costs",
    ),
    networkSummaryItem(
      "Ambiguous fee spends",
      Number(coordinator.ambiguous_spend_count || 0).toLocaleString(),
      `${formatSats(coordinator.ambiguous_input_sats || 0)} tracked`,
    ),
    networkSummaryItem(
      "Pools tracked",
      pools.length.toLocaleString(),
      "Current and documented legacy denominations",
    ),
  );

  const buttons = pools.map((pool) => {
    const button = document.createElement("button");
    const name = document.createElement("strong");
    const liquidity = document.createElement("span");
    const detail = document.createElement("small");
    button.type = "button";
    button.className = "pool-button";
    button.dataset.poolId = String(pool.pool_id || "");
    button.setAttribute("aria-pressed", "false");
    name.textContent = poolName(pool.pool_id);
    liquidity.textContent = formatBtc(pool.liquidity_sats || 0);
    detail.textContent =
      `${Number(pool.utxo_count || 0).toLocaleString()} UTXO(s) · ` +
      `${formatSats(pool.entry_sats || 0)} entered · ` +
      `${formatSats(pool.exit_sats || 0)} exited at block ` +
      `${Number(pool.height || 0).toLocaleString()}`;
    button.append(name, liquidity, detail);
    button.addEventListener("click", () => {
      loadPoolHistory(button.dataset.poolId || "");
    });
    return button;
  });
  replaceChildren(
    poolList,
    ...(buttons.length
      ? buttons
      : [paragraph("No pool snapshots are indexed yet.", "empty-state")]),
  );
  networkStatus.textContent =
    `Indexed through block ${lastHeight}. The scan can continue in the background.`;
  networkStatus.classList.remove("unavailable");
  networkContent.hidden = false;

  if (buttons.length) {
    const initialIndex = pools.reduce(
      (bestIndex, pool, index) =>
        Number(pool.liquidity_sats || 0) >
        Number(pools[bestIndex].liquidity_sats || 0)
          ? index
          : bestIndex,
      0,
    );
    loadPoolHistory(buttons[initialIndex].dataset.poolId || "");
  }
}

function renderPoolHistory(poolId, snapshots) {
  const rows = snapshots.map((snapshot) => {
    const row = document.createElement("tr");
    [
      Number(snapshot.height || 0).toLocaleString(),
      formatBtc(snapshot.liquidity_sats || 0),
      formatSats(snapshot.entry_sats || 0),
      formatSats(snapshot.exit_sats || 0),
      Number(snapshot.tx0_count || 0).toLocaleString(),
      Number(snapshot.round_count || 0).toLocaleString(),
    ].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    });
    return row;
  });
  poolHistoryHeading.textContent = `${poolName(poolId)} recent blocks`;
  poolHistoryStatus.textContent = rows.length
    ? `Showing the newest ${rows.length.toLocaleString()} indexed block(s).`
    : "No indexed blocks are available for this pool yet.";
  replaceChildren(poolHistoryBody, ...rows);
  poolHistoryTable.hidden = rows.length === 0;
}

async function loadPoolHistory(poolId) {
  Array.from(poolList.querySelectorAll(".pool-button")).forEach((button) => {
    button.setAttribute(
      "aria-pressed",
      button.dataset.poolId === poolId ? "true" : "false",
    );
  });
  poolHistoryStatus.textContent = "Loading recent pool blocks…";
  poolHistoryTable.hidden = true;
  try {
    const response = await fetch(
      `/api/network/pools/${encodeURIComponent(poolId)}/history?limit=12`,
    );
    if (!response.ok) {
      throw new Error("request failed");
    }
    const history = await response.json();
    renderPoolHistory(
      typeof history.pool_id === "string" ? history.pool_id : poolId,
      Array.isArray(history.snapshots) ? history.snapshots : [],
    );
  } catch (_error) {
    poolHistoryStatus.textContent =
      "Recent blocks for this pool are not available yet.";
  }
}

async function loadNetworkOverview() {
  try {
    const response = await fetch("/api/network");
    if (!response.ok) {
      throw new Error("request failed");
    }
    renderNetworkOverview(await response.json());
  } catch (_error) {
    networkStatus.textContent =
      "Pool history is not available yet. The transaction tracer is still ready.";
    networkStatus.classList.add("unavailable");
    networkContent.hidden = true;
  }
}

function shortTxid(txid) {
  if (typeof txid !== "string" || txid.length < 16) {
    return txid || "Unknown";
  }
  return `${txid.slice(0, 8)}…${txid.slice(-8)}`;
}

function readRequest() {
  const txid = txidInput.value.trim();
  if (!TXID_PATTERN.test(txid)) {
    throw new Error(
      "Enter a transaction ID with exactly 64 hexadecimal characters.",
    );
  }

  const request = { txid: txid.toLowerCase() };
  Object.entries(LIMITS).forEach(([name, definition]) => {
    const value = Number(document.getElementById(definition.id).value);
    if (
      !Number.isInteger(value) ||
      value < definition.min ||
      value > definition.max
    ) {
      throw new Error(
        `Choose ${readableName(name).toLowerCase()} between ` +
          `${definition.min.toLocaleString()} and ${definition.max.toLocaleString()}.`,
      );
    }
    request[name] = value;
  });
  return request;
}

function showError(message) {
  errorAlert.textContent = message;
  errorAlert.hidden = false;
  requestStatus.textContent = "";
}

function clearError() {
  errorAlert.textContent = "";
  errorAlert.hidden = true;
}

function setBusy(isBusy) {
  analyzeButton.disabled = isBusy;
  exampleButton.disabled = isBusy;
  if (isBusy) {
    analyzeButton.textContent = "Analyzing…";
    requestStatus.textContent = "Following public transaction links…";
  } else {
    analyzeButton.textContent = "Analyze transaction";
    requestStatus.textContent = "";
  }
}

function addSummaryItem(label, value, secondary = "") {
  const item = document.createElement("div");
  const labelElement = document.createElement("span");
  const valueElement = document.createElement("strong");
  labelElement.textContent = label;
  valueElement.textContent = value;
  if (secondary) {
    const detail = document.createElement("small");
    detail.textContent = secondary;
    valueElement.appendChild(detail);
  }
  item.append(labelElement, valueElement);
  return item;
}

function renderSummary(report) {
  const summary =
    report && report.summary && typeof report.summary === "object"
      ? report.summary
      : {};
  replaceChildren(
    summaryGrid,
    addSummaryItem(
      "Transactions examined",
      Number(summary.transactions_examined || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Whirlpool rounds",
      Number(summary.whirlpool_rounds || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Later Tx0s",
      Number(summary.later_tx0s || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Postmix consolidations",
      Number(summary.postmix_consolidations || 0).toLocaleString(),
    ),
    addSummaryItem(
      "3+ coin payment consolidations",
      Number(
        summary.postmix_payment_consolidations || 0,
      ).toLocaleString(),
    ),
    addSummaryItem(
      "Cross-role address reuse",
      Number(summary.address_reuse_findings || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Whirlpool CPFP candidates",
      Number(summary.whirlpool_cpfp_findings || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Stonewall candidates",
      Number(summary.stonewall_spends || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Ricochet candidates",
      Number(summary.ricochet_spends || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Possible Payjoin / Cahoots fingerprint leak",
      Number(
        summary.postmix_payjoin_fingerprint_candidates || 0,
      ).toLocaleString(),
    ),
    addSummaryItem(
      "Possible payments",
      Number(summary.possible_payments || 0).toLocaleString(),
    ),
    addSummaryItem(
      "Still unspent",
      formatBtc(summary.unspent_sats || 0),
      `${formatSats(summary.unspent_sats || 0)} across ${Number(
        summary.unspent_output_count || 0,
      ).toLocaleString()} output(s)`,
    ),
  );

  partialAlert.hidden = !Boolean(report && report.truncated);
  renderWarnings(report && Array.isArray(report.warnings) ? report.warnings : []);
}

function renderWarnings(warnings) {
  if (!warnings.length) {
    replaceChildren(warningsPanel);
    return;
  }
  const list = document.createElement("ul");
  warnings.forEach((warning) => {
    const item = document.createElement("li");
    item.textContent =
      typeof warning === "string" ? warning : "The trace returned a warning.";
    list.appendChild(item);
  });
  replaceChildren(warningsPanel, list);
}

function confidenceBadge(confidence) {
  const normalized = ["high", "medium", "low"].includes(confidence)
    ? confidence
    : "unknown";
  const badge = document.createElement("span");
  badge.className = `confidence ${normalized}`;
  badge.textContent = `Confidence: ${readableName(normalized)}`;
  return badge;
}

const FINDING_LABELS = {
  later_tx0: "Change entered another Tx0",
  postmix_consolidation: "Postmix consolidation",
  postmix_payment_consolidation:
    "Possible 3+ coin payment consolidation",
  stonewall: "Possible Stonewall / StonewallX2",
  ricochet: "Possible Ricochet",
  address_reuse: "Address reused across Whirlpool roles",
  whirlpool_cpfp: "Possible Whirlpool CPFP",
  postmix_payjoin_fingerprint:
    "Possible Payjoin / Cahoots fingerprint leak",
  possible_payment: "Possible payment",
  unspent: "Still unspent",
};

const REUSED_ROLE_LABELS = {
  coordinator_fee: "Coordinator fee",
  tx0_premix: "Tx0 premix",
  whirlpool_coinjoin_output: "Whirlpool output",
  stonewall_equal_output: "Stonewall equal output",
};

const PAYJOIN_SIGNAL_LABELS = {
  prevout_script_type: "Previous-output script type",
  sequence: "Input sequence",
  ecdsa_r_length: "ECDSA signature R length",
  ecdsa_sighash: "ECDSA sighash",
  taproot_sighash_form: "Taproot sighash form",
};

function findingDetailLines(finding) {
  const lines = [];
  if (finding.kind === "postmix_payment_consolidation") {
    lines.push(
      `One-to-one matched inputs: ${Array.isArray(finding.outpoints) ? finding.outpoints.length : 0}`,
    );
    if (Array.isArray(finding.source_txids)) {
      finding.source_txids.forEach((txid) => {
        lines.push(`Source Tx0: ${txid}`);
      });
    }
  }
  if (
    finding.kind === "stonewall" &&
    Array.isArray(finding.repeated_output_values_sats)
  ) {
    finding.repeated_output_values_sats.forEach((value) => {
      lines.push(`Repeated output amount: ${formatSats(value)}`);
    });
  }
  if (finding.kind === "ricochet") {
    lines.push(`Ricochet service fee: ${formatSats(finding.service_fee_sats)}`);
    if (typeof finding.service_fee_address === "string") {
      lines.push(`Ricochet fee address: ${finding.service_fee_address}`);
    }
    const hops = Array.isArray(finding.hop_txids)
      ? finding.hop_txids.length
      : 0;
    lines.push(`Four observed hops: ${hops}`);
  }
  if (finding.kind === "address_reuse") {
    if (typeof finding.reused_address === "string") {
      lines.push(`Address: ${finding.reused_address}`);
    }
    const roles = Array.isArray(finding.reused_roles)
      ? finding.reused_roles.map(
          (role) => REUSED_ROLE_LABELS[role] || String(role),
        )
      : [];
    if (roles.length) {
      lines.push(`Roles: ${roles.join(", ")}`);
    }
  }
  if (finding.kind === "whirlpool_cpfp") {
    if (typeof finding.cpfp_parent_txid === "string") {
      lines.push(`Parent round: ${finding.cpfp_parent_txid}`);
    }
    if (Number.isInteger(finding.cpfp_block_height)) {
      lines.push(
        `Same confirmation block: ${finding.cpfp_block_height.toLocaleString()}`,
      );
    }
    lines.push(
      `Parent fee: ${formatSats(finding.cpfp_parent_fee_sats)} ` +
        `over ${Number(finding.cpfp_parent_vsize || 0).toLocaleString()} vB`,
    );
    lines.push(
      `Child fee: ${formatSats(finding.cpfp_child_fee_sats)} ` +
        `over ${Number(finding.cpfp_child_vsize || 0).toLocaleString()} vB`,
    );
    lines.push(
      "Fee rates (parent / child / package): " +
        `${finding.cpfp_parent_fee_rate || "unavailable"} / ` +
        `${finding.cpfp_child_fee_rate || "unavailable"} / ` +
        `${finding.cpfp_package_fee_rate || "unavailable"} sat/vB`,
    );
  }
  if (finding.kind === "postmix_payjoin_fingerprint") {
    const heuristic =
      finding.payjoin_unnecessary_input_heuristic === "uih1" ||
      finding.payjoin_unnecessary_input_heuristic === "uih2"
        ? finding.payjoin_unnecessary_input_heuristic.toUpperCase()
        : "none";
    lines.push(`Unnecessary-input clue: ${heuristic}`);
    const signals = Array.isArray(finding.payjoin_fingerprint_signals)
      ? finding.payjoin_fingerprint_signals.map(
          (signal) => PAYJOIN_SIGNAL_LABELS[signal] || String(signal),
        )
      : [];
    lines.push(
      `Input fingerprint differences: ${signals.length ? signals.join(", ") : "none"}`,
    );
    const groups = Array.isArray(finding.payjoin_input_clusters)
      ? finding.payjoin_input_clusters
      : [];
    const readableGroups = groups.map((group) => {
      const indices = Array.isArray(group)
        ? group
            .filter((index) => Number.isInteger(index) && index >= 0)
            .map((index) => Number(index) + 1)
        : [];
      return `inputs ${indices.join(", ")}`;
    });
    lines.push(
      `Observable input groups: ${groups.length}` +
        (readableGroups.length ? ` (${readableGroups.join("; ")})` : ""),
    );
    lines.push(
      "Consistent with Payjoin/Cahoots, not proof; observable groups are not proven owners.",
    );
  }
  return lines;
}

function renderFindings(report) {
  const findings = Array.isArray(report && report.findings)
    ? report.findings.filter((finding) =>
        Object.hasOwn(FINDING_LABELS, finding && finding.kind),
      )
    : [];
  if (!findings.length) {
    replaceChildren(
      findingsList,
      paragraph(
        "No matching later Tx0, postmix consolidation, Stonewall/Ricochet " +
          "or Payjoin/Cahoots shape, possible payment, or tracked unspent " +
          "output was observed within these limits.",
        "empty-state",
      ),
    );
    return;
  }

  const cards = findings.map((finding) => {
    const card = document.createElement("article");
    card.className = "finding";
    const header = document.createElement("div");
    header.className = "finding-header";
    const heading = document.createElement("h3");
    heading.textContent = FINDING_LABELS[finding.kind];
    header.append(heading, confidenceBadge(finding.confidence));

    const explanation = paragraph(
      typeof finding.explanation === "string"
        ? finding.explanation
        : "This finding has no additional explanation.",
    );
    const txid = document.createElement("code");
    txid.textContent =
      typeof finding.txid === "string" ? finding.txid : "Unknown transaction";
    const details = document.createElement("div");
    details.className = "finding-details";
    findingDetailLines(finding).forEach((line) => {
      details.appendChild(paragraph(line));
    });
    card.append(header, explanation, details, txid);
    return card;
  });
  replaceChildren(findingsList, ...cards);
}

function graphRole(node) {
  if (!node || node.kind === "transaction") {
    return "transaction";
  }
  if (node.role === "doxxic_change") {
    return "doxxic_change";
  }
  if (node.role === "premix") {
    return "premix";
  }
  if (node.role === "coinjoin" || node.role === "postmix") {
    return "coinjoin";
  }
  if (node.role === "coordinator_fee") {
    return "coordinator_fee";
  }
  if (node.role === "stonewall_equal_output") {
    return "stonewall_equal_output";
  }
  if (node.role === "ricochet_fee") {
    return "ricochet_fee";
  }
  if (node.role === "ricochet_hop") {
    return "ricochet_hop";
  }
  if (node.role === "possible_payment") {
    return "possible_payment";
  }
  return "unclassified";
}

function nodeLabel(node) {
  if (node.kind === "transaction") {
    return shortTxid(node.txid);
  }
  return `Output ${Number.isInteger(node.output_index) ? node.output_index : "?"}`;
}

function renderGraph(report) {
  const nodes = Array.isArray(report && report.nodes) ? report.nodes : [];
  const edges = Array.isArray(report && report.edges) ? report.edges : [];
  graphEmpty.hidden = nodes.length > 0;

  if (graph) {
    graph.destroy();
    graph = null;
  }
  if (!nodes.length || typeof window.cytoscape !== "function") {
    if (nodes.length) {
      graphEmpty.textContent = "The graph could not be loaded in this browser.";
      graphEmpty.hidden = false;
    }
    return;
  }

  const elements = [
    ...nodes.map((node) => ({
      data: {
        ...node,
        id: node.id,
        label: nodeLabel(node),
        graph_role: graphRole(node),
      },
    })),
    ...edges.map((edge) => ({
      data: {
        ...edge,
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.kind === "possible_coinjoin_link" ? "possible" : "",
      },
    })),
  ];

  graph = window.cytoscape({
    container: document.getElementById("transaction-graph"),
    elements,
    minZoom: 0.12,
    maxZoom: 3,
    wheelSensitivity: 0.18,
    style: [
      {
        selector: "node",
        style: {
          width: 28,
          height: 28,
          "background-color": "#687384",
          "border-color": "#bbb3a8",
          "border-width": 2,
          color: "#f4efe5",
          label: "data(label)",
          "font-family": "ui-monospace, monospace",
          "font-size": 8,
          "text-background-color": "#11100f",
          "text-background-opacity": 0.88,
          "text-background-padding": 3,
          "text-margin-y": 8,
          "text-valign": "bottom",
        },
      },
      {
        selector: 'node[kind = "transaction"]',
        style: {
          width: 88,
          height: 38,
          shape: "round-rectangle",
          "background-color": "#3a3c40",
          "border-color": "#d3cabd",
          "text-margin-y": 10,
        },
      },
      {
        selector: 'node[graph_role = "doxxic_change"]',
        style: { "background-color": "#f2a43a", "border-color": "#ffd28d" },
      },
      {
        selector: 'node[graph_role = "premix"]',
        style: { "background-color": "#8d73d6", "border-color": "#c7b7f0" },
      },
      {
        selector: 'node[graph_role = "coinjoin"]',
        style: { "background-color": "#4d8fd7", "border-color": "#a7cdf5" },
      },
      {
        selector: 'node[graph_role = "coordinator_fee"]',
        style: { "background-color": "#a96872", "border-color": "#e5b0b8" },
      },
      {
        selector: 'node[graph_role = "stonewall_equal_output"]',
        style: { "background-color": "#b87535", "border-color": "#f1bd79" },
      },
      {
        selector: 'node[graph_role = "ricochet_fee"]',
        style: { "background-color": "#ad5e79", "border-color": "#e9a5bc" },
      },
      {
        selector: 'node[graph_role = "ricochet_hop"]',
        style: { "background-color": "#447d8b", "border-color": "#9bcbd5" },
      },
      {
        selector: 'node[graph_role = "possible_payment"]',
        style: { "background-color": "#4f9b70", "border-color": "#a1ddb6" },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#7d776f",
          "target-arrow-color": "#7d776f",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          color: "#d9d0c4",
          label: "data(label)",
          "font-size": 8,
          "text-background-color": "#11100f",
          "text-background-opacity": 0.9,
          "text-background-padding": 2,
        },
      },
      {
        selector: 'edge[kind = "possible_coinjoin_link"]',
        style: {
          "line-style": "dashed",
          "line-color": "#a88cd4",
          "target-arrow-color": "#a88cd4",
        },
      },
      {
        selector: ":selected",
        style: {
          "border-color": "#ffc064",
          "border-width": 4,
          "line-color": "#ffc064",
          "target-arrow-color": "#ffc064",
        },
      },
    ],
    layout: graphLayout(),
  });

  graph.on("tap", "node", (event) => {
    renderDetails(event.target.data(), report);
  });
}

function graphLayout() {
  return {
    name: "cose",
    animate: false,
    fit: true,
    padding: 30,
    nodeRepulsion: 6500,
    idealEdgeLength: 80,
    edgeElasticity: 80,
    numIter: 650,
    randomize: true,
  };
}

function detailRow(label, value, monospace = false) {
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value;
  if (monospace) {
    description.className = "detail-value monospace";
  }
  return [term, description];
}

function transactionDetails(report, txid) {
  const transactions = Array.isArray(report && report.transactions)
    ? report.transactions
    : [];
  return transactions.find(
    (transaction) => transaction && transaction.txid === txid,
  );
}

function optionalSats(value) {
  return value === null || value === undefined
    ? "Unavailable"
    : formatSats(value);
}

function optionalPercent(value) {
  return value === null || value === undefined
    ? "Unavailable"
    : `${value}%`;
}

function renderDetails(node, report) {
  const list = document.createElement("dl");
  list.className = "detail-grid";
  const identity =
    node.kind === "output" && Number.isInteger(node.output_index)
      ? `${node.txid}:${node.output_index}`
      : node.txid;
  list.append(...detailRow("Item", identity || "Unknown", true));
  list.append(
    ...detailRow(
      "Role",
      readableName(node.role || node.transaction_kind || node.kind),
    ),
  );
  if (
    node.value_sats !== null &&
    node.value_sats !== undefined &&
    Number.isFinite(Number(node.value_sats))
  ) {
    list.append(
      ...detailRow(
        "Observed value",
        `${formatBtc(node.value_sats)} · ${formatSats(node.value_sats)}`,
      ),
    );
  }
  list.append(...detailRow("Status", readableName(node.status)));
  list.append(...detailRow("Confidence", readableName(node.confidence)));
  if (node.pool) {
    list.append(...detailRow("Pool / pattern", String(node.pool)));
  }
  if (node.script_type) {
    list.append(...detailRow("Output type", readableName(node.script_type)));
  }

  const transaction =
    node.kind === "transaction"
      ? transactionDetails(report, node.txid)
      : null;
  let heuristicNote = null;
  if (transaction && transaction.kind === "tx0") {
    list.append(
      ...detailRow(
        "Inputs grouped by this transaction",
        transaction.input_count === null ||
          transaction.input_count === undefined
          ? "Unavailable"
          : `${Number(transaction.input_count).toLocaleString()} input(s)`,
      ),
    );
    list.append(
      ...detailRow(
        "Grouped input value",
        optionalSats(transaction.input_value_sats),
      ),
    );
    list.append(
      ...detailRow("Tx0 miner fee", optionalSats(transaction.miner_fee_sats)),
    );
    list.append(
      ...detailRow(
        "Coordinator fee",
        optionalSats(transaction.coordinator_fee_sats),
      ),
    );
    list.append(
      ...detailRow(
        "Total Tx0 fee cost",
        optionalSats(transaction.total_fee_cost_sats),
      ),
    );
    list.append(
      ...detailRow(
        "Entered pool value",
        optionalSats(transaction.entered_pool_sats),
      ),
    );
    list.append(
      ...detailRow(
        "Fee cost / equal denominations",
        optionalPercent(transaction.fee_cost_percent),
      ),
    );
    list.append(
      ...detailRow(
        "Change entered another Tx0",
        transaction.doxxic_change_enters_later_tx0 ? "Yes" : "No",
      ),
    );
    heuristicNote = paragraph(
      "Inputs grouped by this transaction use the common-input-ownership " +
        "heuristic. The grouping is evidence, not proof that one person " +
        "controlled every input.",
      "possible-note",
    );
  } else if (transaction && transaction.kind === "whirlpool_round") {
    const roundSize = Number(transaction.round_size);
    list.append(
      ...detailRow(
        "Round size",
        Number.isInteger(roundSize)
          ? `${roundSize}:${roundSize}`
          : "Unavailable",
      ),
    );
    list.append(
      ...detailRow(
        "New entrants",
        transaction.new_entrant_ratio === null ||
          transaction.new_entrant_ratio === undefined
          ? "Unavailable"
          : `${Number(transaction.premix_input_count).toLocaleString()} ` +
              `(${transaction.new_entrant_ratio}%)`,
      ),
    );
    list.append(
      ...detailRow(
        "Remixers",
        transaction.remixer_ratio === null ||
          transaction.remixer_ratio === undefined
          ? "Unavailable"
          : `${Number(transaction.remix_input_count).toLocaleString()} ` +
              `(${transaction.remixer_ratio}%)`,
      ),
    );
    list.append(
      ...detailRow("Round miner fee", optionalSats(transaction.miner_fee_sats)),
    );
  }

  const possibleEdges = Array.isArray(report && report.edges)
    ? report.edges.filter(
        (edge) =>
          edge &&
          edge.kind === "possible_coinjoin_link" &&
          (edge.source === node.id || edge.target === node.id),
      )
    : [];
  const children = [list];
  if (heuristicNote) {
    children.push(heuristicNote);
  }
  if (possibleEdges.length) {
    children.push(
      paragraph(
        "This item touches a possible link across a coinjoin. The link shows " +
          "a plausible path, not proof that one participant controlled the output.",
        "possible-note",
      ),
    );
  }
  replaceChildren(detailPanel, ...children);
}

function renderReport(report) {
  latestReport = report;
  renderSummary(report);
  renderFindings(report);
  renderGraph(report);
  const rootNode = Array.isArray(report && report.nodes)
    ? report.nodes.find(
        (node) =>
          node &&
          node.kind === "transaction" &&
          node.txid === report.root_txid,
      )
    : null;
  if (rootNode) {
    renderDetails(rootNode, report);
  } else {
    replaceChildren(
      detailPanel,
      paragraph("Select a transaction or output in the graph.", "empty-state"),
    );
  }
}

async function submitTrace() {
  clearError();
  let request;
  try {
    request = readRequest();
  } catch (error) {
    showError(error.message);
    txidInput.focus();
    return;
  }

  setBusy(true);
  try {
    const response = await fetch("/api/trace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!response.ok) {
      throw new Error("request failed");
    }
    const report = await response.json();
    renderReport(report);
  } catch (_error) {
    showError(
      "The trace could not be completed. Check your node connection and try again.",
    );
  } finally {
    setBusy(false);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  submitTrace();
});

exampleButton.addEventListener("click", () => {
  txidInput.value = exampleButton.dataset.exampleTxid || EXAMPLE_TXID;
  submitTrace();
});

document.getElementById("zoom-in").addEventListener("click", () => {
  if (graph) {
    graph.zoom({
      level: Math.min(graph.maxZoom(), graph.zoom() * 1.2),
      renderedPosition: {
        x: graph.width() / 2,
        y: graph.height() / 2,
      },
    });
  }
});

document.getElementById("zoom-out").addEventListener("click", () => {
  if (graph) {
    graph.zoom({
      level: Math.max(graph.minZoom(), graph.zoom() / 1.2),
      renderedPosition: {
        x: graph.width() / 2,
        y: graph.height() / 2,
      },
    });
  }
});

document.getElementById("fit-graph").addEventListener("click", () => {
  if (graph) {
    graph.fit(undefined, 30);
  }
});

document.getElementById("reset-graph").addEventListener("click", () => {
  if (graph && latestReport) {
    graph.layout(graphLayout()).run();
  }
});

document.addEventListener("DOMContentLoaded", loadNetworkOverview);
