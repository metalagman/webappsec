import { verifyOnlineDeployment } from "./{{ENGINE_MODULE}}";

const locale = document.documentElement.lang.toLowerCase().startsWith("ru") ? "ru" : "en";

const messages = locale === "ru"
  ? {
      states: {
        pending: "ожидается",
        running: "проверяется",
        pass: "пройдено",
        fail: "ошибка",
        unavailable: "недоступно",
      },
      runningTitle: "Проверка выполняется",
      runningSummary: "Получаем свежий снимок CI и связываем его с текущим deployment.",
      runningLive: "Проверка запущена.",
      runningDiagnostics: "Проверка выполняется…",
      waitingDetail: "Ожидает выполнения",
      pendingValue: "ожидается",
      unknownRelease: "не определён",
      unknownTime: "не определено",
      passTitle: "Deployment подтверждён",
      passSummary: "CI-доказательства и свежие production-байты относятся к одной идентичности и прошли все обязательные проверки.",
      passLive: "Проверка завершена успешно.",
      unavailableTitle: "Проверка недоступна",
      unavailableSummary: "Обязательный источник или требуемый API браузера сейчас недоступны. Статус «пройдено» не выставлен.",
      unavailableLive: "Проверка завершена: результат недоступен.",
      failTitle: "Проверка не пройдена",
      failSummary: "На одном из обязательных шагов обнаружено несоответствие. Статус «пройдено» не выставлен.",
      failLive: "Проверка завершена с ошибкой.",
      unknownError: "Неизвестная ошибка",
    }
  : {
      states: {
        pending: "pending",
        running: "running",
        pass: "pass",
        fail: "fail",
        unavailable: "unavailable",
      },
      runningTitle: "Verification in progress",
      runningSummary: "Fetching the latest CI snapshot and binding it to the live deployment.",
      runningLive: "Verification started.",
      runningDiagnostics: "Verification in progress…",
      waitingDetail: "Queued for current run",
      pendingValue: "pending",
      unknownRelease: "unknown",
      unknownTime: "unknown",
      passTitle: "Deployment verified",
      passSummary: "CI evidence and live production bytes match the same release identity and passed every required check.",
      passLive: "Verification succeeded.",
      unavailableTitle: "Verification unavailable",
      unavailableSummary: "A required source or browser API is currently unavailable. PASS was not granted.",
      unavailableLive: "Verification finished: result unavailable.",
      failTitle: "Verification failed",
      failSummary: "A required check detected a mismatch. PASS was not granted.",
      failLive: "Verification failed.",
      unknownError: "Unknown error",
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
  element.querySelector("[data-check-state]").textContent = messages.states[check.state] ?? check.state;
  element.querySelector("[data-check-detail]").textContent = check.detail;
}

function resetPage() {
  result.className = "result-card is-running";
  result.setAttribute("aria-busy", "true");
  resultMark.textContent = "···";
  resultTitle.textContent = messages.runningTitle;
  resultSummary.textContent = messages.runningSummary;
  liveSummary.textContent = messages.runningLive;
  staleWarning.hidden = true;
  evidenceLinks.hidden = true;
  diagnostics.textContent = messages.runningDiagnostics;
  for (const element of checkElements.values()) {
    element.dataset.state = "pending";
    element.querySelector("[data-check-state]").textContent = messages.states.pending;
    element.querySelector("[data-check-detail]").textContent = messages.waitingDetail;
  }
  for (const key of ["release", "digest", "worker", "ci-time", "browser-time"]) {
    setText(`[data-identity="${key}"]`, messages.pendingValue);
  }
}

function setEvidence(link, url) {
  link.href = url;
  link.rel = "noreferrer";
}

function renderIdentity(report, checkedAt) {
  if (!report.identity) return;
  setText('[data-identity="release"]', report.sourceRelease?.tag ?? messages.unknownRelease);
  setText('[data-identity="digest"]', report.identity.manifestDigest);
  setText('[data-identity="worker"]', report.identity.workerVersion);
  setText('[data-identity="ci-time"]', report.verificationEvidence?.verifiedAt ?? messages.unknownTime);
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
    resultTitle.textContent = messages.passTitle;
    resultSummary.textContent = messages.passSummary;
    liveSummary.textContent = messages.passLive;
  } else if (report.error?.state === "unavailable") {
    resultTitle.textContent = messages.unavailableTitle;
    resultSummary.textContent = messages.unavailableSummary;
    liveSummary.textContent = messages.unavailableLive;
  } else {
    resultTitle.textContent = messages.failTitle;
    resultSummary.textContent = messages.failSummary;
    liveSummary.textContent = messages.failLive;
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
      locale,
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
      error: { state: "unavailable", message: error?.message ?? messages.unknownError },
    };
    renderFinal(report, new Date().toISOString());
  }
}

retry.addEventListener("click", runVerification);
runVerification();
