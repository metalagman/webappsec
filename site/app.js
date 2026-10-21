const accordion = document.querySelector("[data-accordion]");

if (accordion) {
  const layers = [...accordion.querySelectorAll(".layer")];
  for (const [index, layer] of layers.entries()) {
    if (index === 0) continue;
    const button = layer.querySelector(".layer-toggle");
    const panel = document.getElementById(button.getAttribute("aria-controls"));
    button.setAttribute("aria-expanded", "false");
    button.querySelector(".toggle-icon").textContent = "+";
    panel.hidden = true;
  }

  accordion.addEventListener("click", (event) => {
    const button = event.target.closest(".layer-toggle");
    if (!button) return;

    const panel = document.getElementById(button.getAttribute("aria-controls"));
    const expanded = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", String(!expanded));
    button.querySelector(".toggle-icon").textContent = expanded ? "+" : "−";
    button.closest(".layer").classList.toggle("is-open", !expanded);
    panel.hidden = expanded;
  });
}

const copyButton = document.querySelector("[data-copy]");
if (copyButton) {
  copyButton.addEventListener("click", async () => {
    const original = copyButton.textContent;
    try {
      await navigator.clipboard.writeText(copyButton.dataset.copy);
      copyButton.textContent = "Скопировано";
    } catch {
      copyButton.textContent = "Скопируйте из терминала";
    }
    window.setTimeout(() => {
      copyButton.textContent = original;
    }, 1600);
  });
}

document.documentElement.dataset.enhanced = "true";
