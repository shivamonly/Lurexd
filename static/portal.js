"use strict";

const portalState = {
  activeView: "dashboard",
  activeStep: 1,
  activeAnalysisTab: "email",
  targets: ["analyst@example.com"],
  templates: [],
  selectedTemplate: "microsoft_reset",
  events: [],
};

const simulationStatusFlow = ["Sent", "Opened", "Clicked", "Compromised"];
const simulationStatusColors = {
  Sent: "#38bdf8",
  Opened: "#facc15",
  Clicked: "#fb4568",
  Compromised: "#fda4af",
};

const demoStorageKey = "phishshield.portal.demo.v1";
const demoTemplates = [
  {
    key: "microsoft_reset",
    title: "Urgent Microsoft Reset",
    subject: "Action required: password reset pending",
    preview: "A familiar enterprise password reset notice with local-only tracking links.",
    accent: "blue",
  },
  {
    key: "netflix_billing",
    title: "Netflix Billing Failure",
    subject: "Your subscription payment could not be processed",
    preview: "Consumer billing pressure pattern for awareness training.",
    accent: "red",
  },
  {
    key: "payroll_update",
    title: "Payroll Deposit Update",
    subject: "Confirm direct deposit details before payroll cutoff",
    preview: "Finance-themed lure using urgency and sensitive-data language.",
    accent: "yellow",
  },
  {
    key: "shipping_notice",
    title: "Missed Delivery Notice",
    subject: "Delivery exception: address confirmation needed",
    preview: "Parcel-style notification with a dummy redirect for local education.",
    accent: "green",
  },
];

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function refreshIcons() {
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function formatTime(value) {
  if (!value) return "Not recorded";
  const parsed = new Date(value.endsWith("Z") ? value : `${value}Z`);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

async function requestJson(path, options = {}) {
  try {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok) {
      const apiError = new Error(formatApiError(data?.detail || "Request failed"));
      apiError.fromApi = Boolean(data);
      throw apiError;
    }
    if (!data) {
      throw new Error("Static host response");
    }
    return data;
  } catch (error) {
    if (error.fromApi) {
      throw error;
    }
    return handleDemoApiRequest(path, options, error);
  }
}

function formatApiError(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => item.msg || String(item)).join(", ");
  return "Request failed";
}

function readDemoData() {
  const stored = localStorage.getItem(demoStorageKey);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      localStorage.removeItem(demoStorageKey);
    }
  }

  const seeded = {
    nextLogId: 6,
    events: [
      createDemoEvent(1, "Quarterly Awareness Drill", "maya@northwind.example", "Sent"),
      createDemoEvent(2, "Quarterly Awareness Drill", "dev@northwind.example", "Opened"),
      createDemoEvent(3, "Payroll Resilience Test", "finance@northwind.example", "Clicked"),
      createDemoEvent(4, "Credential Hygiene Drill", "ops@northwind.example", "Compromised"),
      createDemoEvent(5, "Credential Hygiene Drill", "ana@northwind.example", "Opened"),
    ],
    detections: [
      { input_type: "email", risk_score: 72, summary: "Seeded demonstration: urgency and suspicious URL." },
      { input_type: "url", risk_score: 18, summary: "Seeded demonstration: low-risk URL scan." },
    ],
  };
  writeDemoData(seeded);
  return seeded;
}

function writeDemoData(data) {
  localStorage.setItem(demoStorageKey, JSON.stringify(data));
}

function createDemoEvent(logId, campaignName, targetEmail, status = "Sent") {
  return {
    log_id: logId,
    campaign_name: campaignName,
    target_email: targetEmail,
    status,
    timestamp: new Date().toISOString(),
  };
}

function decorateDemoEvent(event) {
  const baseUrl = window.location.origin;
  return {
    ...event,
    opened_at: simulationStatusFlow.indexOf(event.status) >= simulationStatusFlow.indexOf("Opened") ? event.timestamp : null,
    clicked_at: simulationStatusFlow.indexOf(event.status) >= simulationStatusFlow.indexOf("Clicked") ? event.timestamp : null,
    compromised_at: event.status === "Compromised" ? event.timestamp : null,
    simulated_link: `${baseUrl}/training.html?log_id=${event.log_id}`,
    tracking_pixel: `${baseUrl}/track/open/${event.log_id}.gif`,
  };
}

function getRequestBody(options) {
  if (!options.body) return {};
  try {
    return JSON.parse(options.body);
  } catch {
    return {};
  }
}

function calculateDemoMetrics(data) {
  const campaignNames = new Set(data.events.map((event) => event.campaign_name));
  const clickedEvents = data.events.filter((event) => ["Clicked", "Compromised"].includes(event.status)).length;
  const statusCounts = data.events.reduce((counts, event) => {
    counts[event.status] = (counts[event.status] || 0) + 1;
    return counts;
  }, {});
  return {
    total_campaigns: campaignNames.size,
    click_through_rate: data.events.length ? Math.round((clickedEvents / data.events.length) * 1000) / 10 : 0,
    threats_detected: data.detections.filter((item) => item.risk_score >= 50).length,
    status_counts: statusCounts,
    events: [...data.events].sort((a, b) => b.log_id - a.log_id).slice(0, 25).map(decorateDemoEvent),
  };
}

function updateDemoStatus(data, logId, nextStatus) {
  const event = data.events.find((item) => item.log_id === logId);
  if (!event) throw new Error("Simulation log not found");
  if (simulationStatusFlow.indexOf(nextStatus) >= simulationStatusFlow.indexOf(event.status)) {
    event.status = nextStatus;
    event.timestamp = new Date().toISOString();
  }
}

function launchDemoSimulation(payload) {
  if (!payload.safe_test_mode) {
    throw new Error("Safe Test Mode must remain enabled for local simulations.");
  }
  const template = demoTemplates.find((item) => item.key === payload.template_key);
  if (!template) {
    throw new Error("Unknown phishing template.");
  }
  const emailPattern = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  const emails = [...new Set((payload.target_emails || []).map((email) => String(email).trim().toLowerCase()).filter(Boolean))];
  if (!emails.length) throw new Error("Add at least one valid target email.");
  const invalid = emails.find((email) => !emailPattern.test(email));
  if (invalid) throw new Error(`Invalid target email: ${invalid}`);

  const data = readDemoData();
  const created = emails.map((email) => {
    const event = createDemoEvent(data.nextLogId, payload.campaign_name.trim(), email, "Sent");
    data.nextLogId += 1;
    data.events.push(event);
    return decorateDemoEvent(event);
  });
  writeDemoData(data);
  return { campaign_name: payload.campaign_name.trim(), template, created };
}

function addDemoFinding(findings, title, detail, score, evidence, category) {
  findings.push({
    title,
    detail,
    score,
    category,
    severity: score >= 15 ? "high" : score >= 9 ? "medium" : "low",
    evidence: evidence.slice(0, 5),
  });
}

function analyzeDemoThreat(content, inputType) {
  const findings = [];
  let parseWarning = null;

  if (inputType === "email" && !/^(from|reply-to|authentication-results|subject):/im.test(content)) {
    parseWarning = "Unable to parse headers. Proceeding with text-only lexical scan.";
  }
  if (/reply-to:/i.test(content) && /from:/i.test(content)) {
    const fromDomain = content.match(/from:.*@([^>\s]+)/i)?.[1]?.toLowerCase();
    const replyDomain = content.match(/reply-to:.*@([^>\s]+)/i)?.[1]?.toLowerCase();
    if (fromDomain && replyDomain && fromDomain.split(".").slice(-2).join(".") !== replyDomain.split(".").slice(-2).join(".")) {
      addDemoFinding(findings, "Mismatched Sender Domains", "Reply-To differs from the visible From header domain.", 18, [fromDomain, replyDomain], "Header Validator");
    }
  }
  if (/spf=(fail|softfail)/i.test(content)) {
    addDemoFinding(findings, "SPF Failure", "Authentication-Results reports SPF failure or soft failure.", 16, ["spf=fail"], "Header Validator");
  }
  if (/dkim=fail/i.test(content)) {
    addDemoFinding(findings, "DKIM Failure", "Authentication-Results reports DKIM failure.", 14, ["dkim=fail"], "Header Validator");
  }
  if (/\b(urgent|immediate|within 24 hours|act now|final notice|expires today)\b/i.test(content)) {
    addDemoFinding(findings, "Urgency Keywords Found", "Message language maps to social-engineering pressure patterns.", 13, ["urgency language"], "Lexical Analysis Engine");
  }
  if (/\b(password|login|sign in|credentials|mfa|2fa)\b/i.test(content)) {
    addDemoFinding(findings, "Credential Request Language", "The content asks for authentication-related action.", 12, ["credential language"], "Lexical Analysis Engine");
  }
  if (/\b(wire transfer|invoice|payment failed|billing failure|direct deposit|refund|gift card)\b/i.test(content)) {
    addDemoFinding(findings, "Financial Coercion Terms", "The content uses financial pressure language.", 12, ["financial language"], "Lexical Analysis Engine");
  }

  const urls = extractDemoUrls(content);
  urls.forEach((url) => inspectDemoUrl(url, findings));
  if (inputType === "url" && urls.length === 0) {
    addDemoFinding(findings, "Unparseable URL", "The submitted value did not resolve to a URL-like host.", 10, [content.slice(0, 80)], "Entropy & URL Scanner");
  }

  const riskScore = findings.length ? Math.min(100, findings.reduce((sum, item) => sum + item.score, 0)) : inputType === "url" ? 4 : 6;
  const result = {
    input_type: inputType,
    risk_score: riskScore,
    severity: riskScore >= 75 ? "Critical" : riskScore >= 50 ? "Elevated" : riskScore >= 25 ? "Guarded" : "Low",
    parse_warning: parseWarning,
    findings,
    urls,
    analyzed_at: new Date().toISOString(),
  };

  const data = readDemoData();
  data.detections.push({
    input_type: inputType,
    risk_score: riskScore,
    summary: findings.map((finding) => finding.title).slice(0, 4).join(", ") || "No major heuristic red flags found",
  });
  writeDemoData(data);
  return result;
}

function extractDemoUrls(content) {
  const matches = content.match(/https?:\/\/[^\s<>'"]+|www\.[^\s<>'"]+/gi) || [];
  if (!matches.length && content.includes(".") && !content.trim().includes(" ")) {
    matches.push(content.trim());
  }
  return [...new Set(matches)].map((url) => (url.match(/^[a-z][a-z0-9+.-]*:\/\//i) ? url : `https://${url}`));
}

function inspectDemoUrl(url, findings) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    addDemoFinding(findings, "Unparseable URL", "The submitted value did not resolve to a URL-like host.", 10, [url.slice(0, 80)], "Entropy & URL Scanner");
    return;
  }
  const host = parsed.hostname.toLowerCase();
  const evidence = [host];
  if (parsed.protocol === "http:") {
    addDemoFinding(findings, "Plain HTTP Link", "The link does not use HTTPS transport.", 5, evidence, "Entropy & URL Scanner");
  }
  if (/\d{1,3}(\.\d{1,3}){3}/.test(host)) {
    addDemoFinding(findings, "Raw IP Address Host", "Legitimate brand mail rarely routes users to bare IP addresses.", 18, evidence, "Entropy & URL Scanner");
  }
  if (/\.(zip|top|click|xyz|tk|ru|rest|support|gq)$/i.test(host)) {
    addDemoFinding(findings, "High-Risk Top-Level Domain", "The host uses a frequently abused top-level domain.", 11, evidence, "Entropy & URL Scanner");
  }
  if (/(micros0ft|rnicrosoft|paypa1|netf1ix|g00gle)/i.test(host)) {
    addDemoFinding(findings, "Look-Alike Brand Domain", "The host resembles a known brand but is not an expected registered domain.", 21, evidence, "Entropy & URL Scanner");
  }
}

function handleDemoApiRequest(path, options, originalError) {
  if (!path.startsWith("/api/")) {
    throw originalError;
  }

  const data = readDemoData();
  if (path === "/api/templates") {
    return { templates: demoTemplates };
  }
  if (path === "/api/metrics") {
    return calculateDemoMetrics(data);
  }
  if (path === "/api/events") {
    return { events: [...data.events].sort((a, b) => b.log_id - a.log_id).map(decorateDemoEvent) };
  }
  if (path === "/api/simulations") {
    return launchDemoSimulation(getRequestBody(options));
  }
  if (path === "/api/analyze/email") {
    return analyzeDemoThreat(getRequestBody(options).content || "", "email");
  }
  if (path === "/api/analyze/url") {
    return analyzeDemoThreat(getRequestBody(options).content || "", "url");
  }

  const statusMatch = path.match(/^\/api\/events\/(\d+)\/status$/);
  if (statusMatch) {
    const logId = Number(statusMatch[1]);
    updateDemoStatus(data, logId, getRequestBody(options).status);
    writeDemoData(data);
    return { ok: true, log_id: logId, status: getRequestBody(options).status };
  }

  throw originalError;
}

function setView(view) {
  portalState.activeView = view;
  $$(".view").forEach((panel) => panel.classList.toggle("active", panel.dataset.view === view));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.nav === view));
  const titles = {
    dashboard: "Command Center",
    simulation: "Simulation Studio",
    detection: "Threat Analytics Engine",
  };
  $("#viewTitle").textContent = titles[view];
  if (view === "dashboard") loadMetrics();
  if (view === "simulation") updateLaunchSummary();
}

function setStep(step) {
  portalState.activeStep = Number(step);
  $$(".step").forEach((button) => button.classList.toggle("active", Number(button.dataset.step) === portalState.activeStep));
  $$(".wizard-step").forEach((panel) => panel.classList.toggle("active", Number(panel.dataset.stepPanel) === portalState.activeStep));
  updateLaunchSummary();
}

function renderTargets() {
  const chips = $("#targetChips");
  chips.innerHTML = portalState.targets
    .map(
      (target) => `
        <span class="chip">
          ${escapeHtml(target)}
          <button type="button" aria-label="Remove ${escapeHtml(target)}" data-remove-target="${escapeHtml(target)}">
            <i data-lucide="x"></i>
          </button>
        </span>`
    )
    .join("");
  refreshIcons();
}

function addTargets(rawValue) {
  const pieces = rawValue
    .split(/[,\s]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  const emailPattern = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  pieces.forEach((email) => {
    if (emailPattern.test(email) && !portalState.targets.includes(email)) {
      portalState.targets.push(email);
    }
  });
  renderTargets();
  updateLaunchSummary();
}

async function loadTemplates() {
  const data = await requestJson("/api/templates");
  portalState.templates = data.templates;
  if (!portalState.templates.some((template) => template.key === portalState.selectedTemplate)) {
    portalState.selectedTemplate = portalState.templates[0]?.key;
  }
  renderTemplates();
  updatePreview();
}

function templateColor(template) {
  const colors = {
    blue: "#38bdf8",
    red: "#fb4568",
    yellow: "#facc15",
    green: "#34d399",
  };
  return colors[template.accent] || "#38bdf8";
}

function renderTemplates() {
  const carousel = $("#templateCarousel");
  carousel.innerHTML = portalState.templates
    .map((template) => {
      const selected = template.key === portalState.selectedTemplate ? "selected" : "";
      return `
        <article class="template-card ${selected}" data-template="${escapeHtml(template.key)}" style="--template-accent: ${templateColor(template)}">
          <div class="template-thumb"></div>
          <h3>${escapeHtml(template.title)}</h3>
          <p>${escapeHtml(template.preview)}</p>
        </article>`;
    })
    .join("");
}

function selectedTemplate() {
  return portalState.templates.find((template) => template.key === portalState.selectedTemplate) || portalState.templates[0];
}

function updatePreview() {
  const template = selectedTemplate();
  if (!template) return;
  $("#previewTitle").textContent = template.title;
  $("#previewSubject").textContent = template.subject;
  $("#previewCopy").textContent = template.preview;
  updateLaunchSummary();
}

function updateLaunchSummary() {
  const template = selectedTemplate();
  $("#summaryCampaign").textContent = $("#campaignName").value.trim() || "Untitled Campaign";
  $("#summaryTargets").textContent = String(portalState.targets.length);
  $("#summaryTemplate").textContent = template ? template.title : "Select one";
}

function statusClass(status) {
  return `status-${status.toLowerCase()}`;
}

function renderEvents(events) {
  portalState.events = events;
  const table = $("#eventsTable");
  if (!events.length) {
    table.innerHTML = `<tr><td colspan="4">No simulation events yet.</td></tr>`;
    return;
  }
  table.innerHTML = events
    .map(
      (event) => `
      <tr data-event-id="${event.log_id}">
        <td>${escapeHtml(event.campaign_name)}</td>
        <td>${escapeHtml(event.target_email)}</td>
        <td><span class="status-tag ${statusClass(event.status)}">${escapeHtml(event.status.toUpperCase())}</span></td>
        <td>${escapeHtml(formatTime(event.timestamp))}</td>
      </tr>`
    )
    .join("");
}

function renderStatusBars(counts) {
  const total = Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0) || 1;
  $("#statusBars").innerHTML = simulationStatusFlow
    .map((status) => {
      const count = counts[status] || 0;
      const width = Math.max(4, Math.round((count / total) * 100));
      return `
        <div class="status-row">
          <span>${status}</span>
          <span class="status-meter"><span style="--width: ${width}%; --bar-color: ${simulationStatusColors[status]}"></span></span>
          <strong>${count}</strong>
        </div>`;
    })
    .join("");
}

async function loadMetrics() {
  const data = await requestJson("/api/metrics");
  $("#metricCampaigns").textContent = data.total_campaigns;
  $("#metricCtr").textContent = data.click_through_rate;
  $("#metricThreats").textContent = data.threats_detected;
  renderEvents(data.events);
  renderStatusBars(data.status_counts || {});
}

function openEventModal(event) {
  const detailRows = [
    ["Campaign", event.campaign_name],
    ["Target", event.target_email],
    ["Current Status", event.status],
    ["Last Interaction Time", formatTime(event.timestamp)],
    ["Opened At", formatTime(event.opened_at)],
    ["Clicked At", formatTime(event.clicked_at)],
    ["Local Link", event.simulated_link],
    ["Tracking Pixel", event.tracking_pixel],
  ];
  $("#eventModalTitle").textContent = `${event.status} - ${event.target_email}`;
  $("#eventDetailList").innerHTML = detailRows
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join("");
  $("#eventModal").classList.remove("hidden");
}

async function advanceLatestEvent() {
  if (!portalState.events.length) return;
  const latest = portalState.events[0];
  const next = simulationStatusFlow[Math.min(simulationStatusFlow.indexOf(latest.status) + 1, simulationStatusFlow.length - 1)];
  await requestJson(`/api/events/${latest.log_id}/status`, {
    method: "POST",
    body: JSON.stringify({ status: next }),
  });
  await loadMetrics();
}

function showLaunchAlert(message, kind = "error") {
  const alert = $("#launchAlert");
  alert.textContent = message;
  alert.classList.remove("hidden", "warning");
  if (kind === "warning") alert.classList.add("warning");
}

async function launchSimulation() {
  const pendingTarget = $("#targetInput").value.trim();
  if (pendingTarget) {
    addTargets(pendingTarget);
    $("#targetInput").value = "";
  }
  const template = selectedTemplate();
  if (!template) {
    showLaunchAlert("Select a template before launch.");
    return;
  }
  if (!portalState.targets.length) {
    showLaunchAlert("Add at least one valid target email.");
    return;
  }
  try {
    const data = await requestJson("/api/simulations", {
      method: "POST",
      body: JSON.stringify({
        campaign_name: $("#campaignName").value.trim() || "Untitled Campaign",
        target_emails: portalState.targets,
        template_key: template.key,
        safe_test_mode: $("#safeToggle").checked,
      }),
    });
    const firstLink = data.created[0]?.simulated_link || "Simulation queued";
    showLaunchAlert(`Simulation launched locally. First safe link: ${firstLink}`, "warning");
    await loadMetrics();
  } catch (error) {
    showLaunchAlert(error.message);
  }
}

function setAnalysisTab(tab) {
  portalState.activeAnalysisTab = tab;
  $$("[data-analysis-tab]").forEach((button) => button.classList.toggle("active", button.dataset.analysisTab === tab));
  $("#emailInput").classList.toggle("hidden", tab !== "email");
  $("#urlInput").classList.toggle("hidden", tab !== "url");
}

function gaugeColor(score) {
  if (score >= 75) return "#fb4568";
  if (score >= 50) return "#f97316";
  if (score >= 25) return "#facc15";
  return "#34d399";
}

function renderAnalysis(result) {
  const gauge = $("#riskGauge");
  gauge.style.setProperty("--risk", result.risk_score);
  gauge.style.setProperty("--gauge-color", gaugeColor(result.risk_score));
  $("#riskScore").textContent = result.risk_score;
  $("#riskSeverity").textContent = result.severity;

  const warning = $("#parseWarning");
  if (result.parse_warning) {
    warning.textContent = result.parse_warning;
    warning.classList.remove("hidden");
  } else {
    warning.classList.add("hidden");
  }

  const findings = result.findings || [];
  $("#heuristicBreakdown").innerHTML = findings.length
    ? findings
        .map(
          (finding, index) => `
          <details class="finding" ${index === 0 ? "open" : ""}>
            <summary>
              <span>${escapeHtml(finding.title)}</span>
              <span class="score-pill ${escapeHtml(finding.severity)}">+${escapeHtml(finding.score)}</span>
            </summary>
            <div class="finding-body">
              <strong>${escapeHtml(finding.category)}</strong>
              <p>${escapeHtml(finding.detail)}</p>
              <ul>
                ${finding.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
              </ul>
            </div>
          </details>`
        )
        .join("")
    : `<details class="finding" open>
        <summary><span>No major heuristic red flags found</span><span class="score-pill low">+0</span></summary>
        <div class="finding-body"><p>The submitted content stayed below the configured risk thresholds.</p></div>
      </details>`;
}

async function analyzeCurrentInput() {
  const tab = portalState.activeAnalysisTab;
  const content = tab === "email" ? $("#emailInput").value.trim() : $("#urlInput").value.trim();
  if (!content) return;
  const result = await requestJson(`/api/analyze/${tab}`, {
    method: "POST",
    body: JSON.stringify({ content }),
  });
  renderAnalysis(result);
  await loadMetrics();
}

function clearAnalysis() {
  $("#emailInput").value = "";
  $("#urlInput").value = "";
  renderAnalysis({ risk_score: 0, severity: "Low", findings: [] });
  $("#parseWarning").classList.add("hidden");
}

function bindEvents() {
  $$(".nav-item, .brand").forEach((item) => {
    item.addEventListener("click", (event) => {
      event.preventDefault();
      setView(item.dataset.nav);
    });
  });

  $("#refreshButton").addEventListener("click", loadMetrics);
  $("#seedWalkButton").addEventListener("click", advanceLatestEvent);

  $$(".step").forEach((button) => button.addEventListener("click", () => setStep(button.dataset.step)));
  $$("[data-next-step]").forEach((button) => button.addEventListener("click", () => setStep(button.dataset.nextStep)));
  $$("[data-prev-step]").forEach((button) => button.addEventListener("click", () => setStep(button.dataset.prevStep)));

  $("#campaignName").addEventListener("input", updateLaunchSummary);
  $("#targetInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === "," || event.key === " ") {
      event.preventDefault();
      addTargets(event.currentTarget.value);
      event.currentTarget.value = "";
    }
  });
  $("#targetInput").addEventListener("blur", (event) => {
    addTargets(event.currentTarget.value);
    event.currentTarget.value = "";
  });
  $("#targetChips").addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-target]");
    if (!button) return;
    portalState.targets = portalState.targets.filter((target) => target !== button.dataset.removeTarget);
    renderTargets();
    updateLaunchSummary();
  });
  $("#safeToggle").addEventListener("change", (event) => {
    if (!event.currentTarget.checked) {
      event.currentTarget.checked = true;
      showLaunchAlert("Safe Test Mode is locked on for this local simulator.", "warning");
    }
  });

  $("#templateCarousel").addEventListener("click", (event) => {
    const card = event.target.closest("[data-template]");
    if (!card) return;
    portalState.selectedTemplate = card.dataset.template;
    renderTemplates();
    updatePreview();
  });
  $("#launchButton").addEventListener("click", launchSimulation);

  $("#eventsTable").addEventListener("click", (event) => {
    const row = event.target.closest("[data-event-id]");
    if (!row) return;
    const selected = portalState.events.find((item) => String(item.log_id) === row.dataset.eventId);
    if (selected) openEventModal(selected);
  });
  $("#closeModal").addEventListener("click", () => $("#eventModal").classList.add("hidden"));
  $("#eventModal").addEventListener("click", (event) => {
    if (event.target.id === "eventModal") $("#eventModal").classList.add("hidden");
  });

  $$("[data-analysis-tab]").forEach((button) => {
    button.addEventListener("click", () => setAnalysisTab(button.dataset.analysisTab));
  });
  $("#analyzeButton").addEventListener("click", analyzeCurrentInput);
  $("#clearAnalysisButton").addEventListener("click", clearAnalysis);
}

async function init() {
  bindEvents();
  renderTargets();
  await loadTemplates();
  await loadMetrics();
  await analyzeCurrentInput();
  refreshIcons();
}

init().catch((error) => {
  console.error(error);
  const table = $("#eventsTable");
  if (table) table.innerHTML = `<tr><td colspan="4">${escapeHtml(error.message)}</td></tr>`;
});
