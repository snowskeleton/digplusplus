const form = document.getElementById("dig-form");
const domainInput = document.getElementById("domain");
const errorDiv = document.getElementById("error");
const resultsDiv = document.getElementById("results");
const traceCheckbox = document.getElementById("trace");
const serverInput = document.getElementById("server");
const shortCheckbox = document.getElementById("short");
const typeButtons = document.querySelectorAll(".type-tab:not(.check-tab)");
const checkButtons = document.querySelectorAll(".check-tab");

// activeMode tracks what's currently selected across both rows.
// { kind: "type", value: "A" } or { kind: "check", value: "spf" }
let activeMode = { kind: "type", value: "A" };

// Anonymous usage analytics (see metrics.js). No-op if the metrics script
// failed to load, so tracking can never break the app.
function track(eventName, props) {
  if (typeof window.track === "function") window.track(eventName, props);
}

traceCheckbox.addEventListener("change", () => {
  const disabled = traceCheckbox.checked;
  serverInput.disabled = disabled;
  shortCheckbox.disabled = disabled;
});

function clearActiveTab() {
  typeButtons.forEach((b) => b.classList.remove("active"));
  checkButtons.forEach((b) => b.classList.remove("active"));
}

function runActive() {
  if (!domainInput.value.trim()) return;
  if (activeMode.kind === "check") {
    runCheck(activeMode.value);
  } else {
    runQuery();
  }
}

typeButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    clearActiveTab();
    btn.classList.add("active");
    activeMode = { kind: "type", value: btn.dataset.type };
    if (domainInput.value.trim()) {
      runQuery();
    }
  });
});

function showError(message) {
  errorDiv.textContent = message;
  errorDiv.hidden = false;
}

function clearError() {
  errorDiv.hidden = true;
  errorDiv.textContent = "";
}

// Small DOM-building helper. Always uses textContent for dynamic values
// (never innerHTML) since answer data comes from arbitrary DNS
// responses and must never be interpreted as HTML.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    try {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      return true;
    } catch (fallbackErr) {
      return false;
    }
  }
}

function copyButton(getText, label = "Copy") {
  const btn = el("button", "copy-btn", label);
  btn.type = "button";
  btn.addEventListener("click", async () => {
    const ok = await copyText(getText());
    track("copy_record", { label: label });
    btn.textContent = ok ? "Copied!" : "Failed";
    btn.classList.toggle("copied", ok);
    setTimeout(() => {
      btn.textContent = label;
      btn.classList.remove("copied");
    }, 1200);
  });
  return btn;
}

// If a record's name is the exact domain that was queried, represent it
// as "@" (the common zone-file/DNS-host-UI shorthand for the apex).
function relativeName(name, domain) {
  const normalize = (s) => (s || "").replace(/\.$/, "").toLowerCase();
  return domain && normalize(name) === normalize(domain) ? "@" : name;
}

// The TTL a fresh record would carry (its originally configured value),
// falling back to the current TTL if the authoritative value is unknown.
function fullTtl(answer) {
  return answer.full_ttl != null ? answer.full_ttl : answer.ttl;
}

// "243/300" when the record has counted down from its configured TTL,
// or just "300" when there's nothing to compare against.
function ttlDisplay(answer) {
  const full = fullTtl(answer);
  return full !== answer.ttl ? `${answer.ttl}/${full}` : String(answer.ttl);
}

// Single-line, tab-separated representation of a record in the order most
// DNS host UIs expect when pasting in a new record: NAME  TYPE  TTL  VALUE.
// Uses the full/configured TTL so a re-added record starts at its intended value.
function digLine(answer, domain) {
  return `${relativeName(answer.name, domain)}\t${answer.type}\t${fullTtl(answer)}\t${answer.data}`;
}

function fieldRow(label, value) {
  const row = el("div", "field-row");
  row.appendChild(el("span", "field-label", label));
  row.appendChild(el("span", "field-value mono", value));
  return row;
}

function answerBlock(answer, domain) {
  const block = el("div", "answer-block");
  block.appendChild(copyButton(() => digLine(answer, domain)));
  block.appendChild(fieldRow("NAME", relativeName(answer.name, domain)));
  block.appendChild(fieldRow("TTL", ttlDisplay(answer)));
  block.appendChild(fieldRow(answer.type, answer.data));
  return block;
}

function answerList(answers, domain) {
  if (!answers.length) {
    return el("p", "empty-note", "No records found.");
  }
  const container = el("div");
  if (answers.length > 1) {
    const header = el("div", "card-header");
    header.appendChild(
      copyButton(() => answers.map((a) => digLine(a, domain)).join("\n"), "Copy all")
    );
    container.appendChild(header);
  }
  for (const a of answers) {
    container.appendChild(answerBlock(a, domain));
  }
  return container;
}

function renderLookupShort(data) {
  const container = el("div", "result-card");
  if (!data.answers.length) {
    container.appendChild(el("p", "empty-note", "No answers."));
    return container;
  }
  if (data.answers.length > 1) {
    const header = el("div", "card-header");
    header.appendChild(copyButton(() => data.answers.join("\n"), "Copy all"));
    container.appendChild(header);
  }
  const list = el("ul", "short-list");
  for (const answer of data.answers) {
    const li = el("li", "mono");
    li.appendChild(el("span", null, answer));
    li.appendChild(copyButton(() => answer));
    list.appendChild(li);
  }
  container.appendChild(list);
  return container;
}

function renderLookupFull(data) {
  const container = el("div", "result-card");
  if (data.provider) {
    container.appendChild(fieldRow("Provider", data.provider));
  }
  container.appendChild(answerList(data.answers, data.query.domain));

  const footer = el("div", "result-footer");
  const footerBits = [`rcode: ${data.rcode}`, `authoritative: ${data.authoritative ? "yes" : "no"}`];
  if (data.query_time_ms != null) {
    footerBits.push(`${data.query_time_ms} ms`);
  }
  footer.textContent = footerBits.join("  ·  ");
  container.appendChild(footer);

  return container;
}

function hopCard(hop, domain) {
  const card = el("div", "hop-card");

  const header = el("div", "hop-header");
  header.appendChild(el("span", "hop-step", `#${hop.step}`));
  header.appendChild(el("span", "mono", `${hop.server_name} (${hop.server})`));
  header.appendChild(el("span", null, `${hop.rcode} · ${hop.query_time_ms} ms`));
  card.appendChild(header);

  if (hop.cname) {
    const detail = el("p", "hop-detail mono");
    detail.appendChild(el("span", null, `CNAME → ${hop.cname}`));
    detail.appendChild(copyButton(() => hop.cname));
    card.appendChild(detail);
  } else if (hop.answers) {
    card.appendChild(answerList(hop.answers, domain));
  } else if (hop.referral) {
    const list = el("ul", "referral-list");
    for (const r of hop.referral) {
      list.appendChild(el("li", "mono", `NS ${r.ns}${r.glue ? " (" + r.glue + ")" : " (no glue)"}`));
    }
    card.appendChild(list);
  }

  return card;
}

function renderTrace(data) {
  const container = el("div", "result-card");
  const hops = el("div", "hop-list");
  for (const hop of data.hops) {
    hops.appendChild(hopCard(hop, data.query.domain));
  }
  container.appendChild(hops);

  const footer = el("div", "result-footer");
  if (data.error) {
    footer.classList.add("warn");
    footer.textContent = data.error;
  } else {
    footer.textContent = `total: ${data.total_time_ms} ms`;
  }
  container.appendChild(footer);

  return container;
}

const SPF_POLICY_LABELS = {
  hardfail: ["✅", "Hard fail (-all)"],
  softfail: ["⚠️", "Soft fail (~all)"],
  neutral: ["❌", "Neutral (?all) — nearly open"],
  allow_all: ["❌", "+all — allows anyone to send!"],
  unknown: ["⚠️", 'No explicit "all" qualifier'],
};

const DMARC_POLICY_LABELS = {
  none: ["⚠️", "none (monitoring only)"],
  quarantine: ["🔶", "quarantine"],
  reject: ["✅", "reject (strongest)"],
};

function esSection(title) {
  const section = el("div", "es-section");
  section.appendChild(el("h3", "es-heading", title));
  return section;
}

function renderSpf(spf) {
  const section = esSection("SPF (Sender Policy)");
  if (!spf.present) {
    section.appendChild(el("p", "empty-note", "No SPF record found."));
    return section;
  }
  section.appendChild(fieldRow("Record", spf.record));
  const [icon, label] = SPF_POLICY_LABELS[spf.policy] || SPF_POLICY_LABELS.unknown;
  section.appendChild(fieldRow("Policy", `${icon} ${label}`));
  return section;
}

function renderDmarc(dmarc) {
  const section = esSection("DMARC (Policy)");
  if (!dmarc.present) {
    section.appendChild(el("p", "empty-note", "No DMARC record found."));
    return section;
  }
  section.appendChild(fieldRow("Record", dmarc.record));
  if (dmarc.policy) {
    const [icon, label] = DMARC_POLICY_LABELS[dmarc.policy] || ["", dmarc.policy];
    section.appendChild(fieldRow("Policy", `${icon} ${label}`));
  }
  if (dmarc.rua) {
    section.appendChild(fieldRow("Reports to", dmarc.rua));
  }
  return section;
}

function renderDkim(dkim) {
  const section = esSection("DKIM (Common Selectors)");
  const records = dkim.records || [];
  if (records.length) {
    if (records.length > 1) {
      const header = el("div", "card-header");
      header.appendChild(copyButton(() => records.map((r) => digLine(r, null)).join("\n"), "Copy all"));
      section.appendChild(header);
    }
    records.forEach((r) => section.appendChild(answerBlock(r, null)));
  } else {
    section.appendChild(
      el(
        "p",
        "empty-note",
        `None of the ${dkim.selectors_checked} common selectors matched (DKIM may still be active).`
      )
    );
  }
  return section;
}

function renderWhois(whois) {
  const section = esSection("Registrar & Registration");
  if (!whois.present) {
    section.appendChild(el("p", "empty-note", "WHOIS data unavailable for this domain."));
    return section;
  }
  if (whois.registrar) section.appendChild(fieldRow("Registrar", whois.registrar));
  if (whois.registrar_url) section.appendChild(fieldRow("Registrar URL", whois.registrar_url));
  if (whois.created) section.appendChild(fieldRow("Created", whois.created));
  if (whois.updated) section.appendChild(fieldRow("Updated", whois.updated));
  if (whois.expires) section.appendChild(fieldRow("Expires", whois.expires));
  if (whois.registrant_org) section.appendChild(fieldRow("Registrant Org", whois.registrant_org));
  if (whois.registrant_country) section.appendChild(fieldRow("Registrant Country", whois.registrant_country));
  if (whois.privacy_protected) {
    section.appendChild(el("p", "empty-note", "Registrant details are privacy-protected."));
  }
  return section;
}

function clearResults() {
  resultsDiv.replaceChildren();
}

function showLoading() {
  clearResults();
  resultsDiv.appendChild(el("p", "empty-note", "Querying..."));
}

// POST JSON to an API endpoint. Resolves with the parsed body, or throws
// an Error whose message is safe to show the user (network failure or the
// server-provided error).
async function apiPost(url, body) {
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new Error("Network error: could not reach the server.");
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Something went wrong.");
  }
  return data;
}

async function runQuery() {
  clearError();
  showLoading();

  const payload = {
    domain: domainInput.value,
    type: activeMode.value,
    server: serverInput.value.trim() || null,
    short: shortCheckbox.checked,
    trace: traceCheckbox.checked,
  };

  track("dns_query", {
    type: payload.type,
    mode: payload.trace ? "trace" : payload.short ? "short" : "full",
    custom_server: Boolean(payload.server),
  });

  let data;
  try {
    data = await apiPost("/api/dig", payload);
  } catch (err) {
    clearResults();
    showError(err.message);
    track("lookup_error", { kind: payload.type, message: err.message });
    return;
  }

  clearResults();
  if (payload.trace) {
    resultsDiv.appendChild(renderTrace(data));
  } else if (payload.short) {
    resultsDiv.appendChild(renderLookupShort(data));
  } else {
    resultsDiv.appendChild(renderLookupFull(data));
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runActive();
});

const CHECK_RENDERERS = {
  registrar: renderWhois,
  spf: renderSpf,
  dmarc: renderDmarc,
  dkim: renderDkim,
};

async function runCheck(check) {
  clearError();
  showLoading();

  track("email_check", { check: check });

  let data;
  try {
    data = await apiPost(`/api/${check}`, { domain: domainInput.value });
  } catch (err) {
    clearResults();
    showError(err.message);
    track("lookup_error", { kind: check, message: err.message });
    return;
  }

  clearResults();
  const container = el("div", "result-card");
  container.appendChild(CHECK_RENDERERS[check](data));
  resultsDiv.appendChild(container);
}

checkButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    if (!domainInput.value.trim()) {
      showError("Enter a domain first.");
      return;
    }
    clearActiveTab();
    btn.classList.add("active");
    activeMode = { kind: "check", value: btn.dataset.check };
    runCheck(btn.dataset.check);
  });
});
