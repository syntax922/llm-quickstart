const showToast = (message) => {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("toast-show");
  }, 10);
  setTimeout(() => {
    toast.classList.remove("toast-show");
    setTimeout(() => toast.remove(), 300);
  }, 1800);
};

const copyText = async (text) => {
  if (!text) {
    showToast("Nothing to copy");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copied");
  } catch (err) {
    showToast("Copy failed");
  }
};

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", () => {
    const targetId = button.getAttribute("data-copy-target");
    const target = document.getElementById(targetId);
    copyText(target?.textContent || "");
  });
});

document.querySelectorAll("[data-action='copy-input']").forEach((button) => {
  button.addEventListener("click", () => {
    const targetId = button.getAttribute("data-target");
    const target = document.getElementById(targetId);
    copyText(target?.value || "");
  });
});

document.querySelectorAll("[data-action='reveal']").forEach((button) => {
  button.addEventListener("click", () => {
    const targetId = button.getAttribute("data-target");
    const target = document.getElementById(targetId);
    if (!target) {
      return;
    }
    const isPassword = target.type === "password";
    target.type = isPassword ? "text" : "password";
    button.textContent = isPassword ? "Hide" : "Reveal";
  });
});
