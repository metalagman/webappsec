import { verifyOnlineDeployment } from "./{{ENGINE_MODULE}}";

const stateLabels = {
  pending: "ожидается",
  running: "проверяется",
  pass: "пройдено",
  fail: "ошибка",
  unavailable: "недоступно",
};

const checkElements = new Map(
  [...document.querySelectorAll("[data-check-id]")].map((element) => [element.dataset.checkId, element]),
);
const result = document.querySelector("#result");
const resultMark = document.querySelector("[data-result-mark]");
const resultTitle = document.querySelector("[data-result-title]");
const resultSummary = document.querySelector("[data-result-summary]");
const liveSummary = document.querySelector("[data-live-summary]");
const staleWarning = document.querySelector("[data-stale]");
const retry = document.querySelector("[data-retry]");
const diagnostics = document.querySelector("[data-diagnostics]");
const evidenceLinks = document.querySelector("[data-evidence-links]");
let activeController;
let runNumber = 0;

function setText(selector, value) {
  const element = document.querySelector(selector);
  if (element) element.textContent = value;
}

function renderCheck(check) {
  const element = checkElements.get(check.id);
  if (!element) return;
  element.dataset.state = check.state;
  element.querySelector("[data-check-state]").textContent = stateLabels[check.state] ?? check.state;
  element.querySelector("[data-check-detail]").textContent = check.detail;
}

function resetPage() {
  result.className = "result-card is-running";
  result.setAttribute("aria-busy", "true");
  resultMark.textContent = "···";
  resultTitle.textContent = "Проверка выполняется";
  resultSummary.textContent = "Получаем свежий snapshot и связываем его с текущим deployment.";
  liveSummary.textContent = "Проверка запущена.";
  staleWarning.hidden = true;
  evidenceLinks.hidden = true;
  diagnostics.textContent = "Проверка выполняется…";
  for (const element of checkElements.values()) {
    element.dataset.state = "pending";
    element.querySelector("[data-check-state]").textContent = stateLabels.pending;
    element.querySelector("[data-check-detail]").textContent = "Ожидается текущий запуск";
  }
  for (const key of ["release", "digest", "worker", "ci-time", "browser-time"]) {
    setText(`[data-identity="${key}"]`, "ожидается");
  }
}

function setEvidence(link, url) {
  link.href = url;
  link.rel = "noreferrer";
}

function renderIdentity(report, checkedAt) {
  if (!report.identity) return;
  setText('[data-identity="release"]', report.sourceRelease?.tag ?? "не определён");
  setText('[data-identity="digest"]', report.identity.manifestDigest);
  setText('[data-identity="worker"]', report.identity.workerVersion);
  setText('[data-identity="ci-time"]', report.verificationEvidence?.verifiedAt ?? "не определено");
  setText('[data-identity="browser-time"]', checkedAt);
  if (!report.sourceRelease || !report.deploymentEvidence || !report.verificationEvidence) return;
  setEvidence(document.querySelector('[data-evidence="source"]'), report.sourceRelease.url);
  setEvidence(document.querySelector('[data-evidence="deployment"]'), report.deploymentEvidence.url);
  setEvidence(document.querySelector('[data-evidence="verification"]'), report.verificationEvidence.url);
  setEvidence(document.querySelector('[data-evidence="run"]'), report.verificationEvidence.runUrl);
  evidenceLinks.hidden = false;
}

function renderFinal(report, checkedAt) {
  result.setAttribute("aria-busy", "false");
  result.className = `result-card is-${report.ok ? "pass" : report.error?.state ?? "fail"}`;
  resultMark.textContent = report.ok ? "✓" : report.error?.state === "unavailable" ? "?" : "×";
  if (report.ok) {
    resultTitle.textContent = "Deployment подтверждён";
    resultSummary.textContent = "CI evidence и свежие production-байты относятся к одной identity и прошли все обязательные проверки.";
    liveSummary.textContent = "Проверка завершена успешно.";
  } else if (report.error?.state === "unavailable") {
    resultTitle.textContent = "Проверка недоступна";
    resultSummary.textContent = "Обязательный источник или возможность браузера сейчас недоступны. PASS не выставлен.";
    liveSummary.textContent = "Проверка завершена: результат недоступен.";
  } else {
    resultTitle.textContent = "Проверка не пройдена";
    resultSummary.textContent = "Один из обязательных шагов обнаружил несоответствие. PASS не выставлен.";
    liveSummary.textContent = "Проверка завершена с ошибкой.";
  }
  staleWarning.hidden = !report.stale;
  renderIdentity(report, checkedAt);
  diagnostics.textContent = JSON.stringify({
    checkedAt,
    ok: report.ok,
    stale: report.stale,
    identity: report.identity,
    error: report.error ?? null,
    checks: report.checks,
  }, null, 2);
}

async function runVerification() {
  activeController?.abort(new DOMException("Superseded by retry", "AbortError"));
  activeController = new AbortController();
  const thisRun = ++runNumber;
  resetPage();
  try {
    const report = await verifyOnlineDeployment({
      signal: activeController.signal,
      onCheck(check) {
        if (thisRun === runNumber) renderCheck(check);
      },
    });
    if (thisRun === runNumber) renderFinal(report, new Date().toISOString());
  } catch (error) {
    if (thisRun !== runNumber || error?.name === "AbortError") return;
    const report = {
      ok: false,
      stale: false,
      identity: null,
      checks: [],
      error: { state: "unavailable", message: error?.message ?? "Неизвестная ошибка" },
    };
    renderFinal(report, new Date().toISOString());
  }
}

retry.addEventListener("click", runVerification);
runVerification();
