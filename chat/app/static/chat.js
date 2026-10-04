"use strict";

const translations = {
  en: {
    run: "Run ID", language: "Language", home: "AI Chat — home", newChat: "New chat",
    eyebrow: "YOUR AI ASSISTANT", heading: "What can I help with?",
    intro: "Ask a question, describe a task, or explore an idea.",
    plan: "Make a plan", topic: "Explore a topic", draft: "Draft a message",
    planPrompt: "Help me plan my workday",
    topicPrompt: "Explain how an AI firewall works in simple terms",
    draftPrompt: "Help me write a short professional email",
    conversation: "Conversation", message: "Message", placeholder: "Type a message…",
    send: "Send message", hint: "Enter to send · Shift + Enter for a new line",
    user: "You", assistant: "Assistant", waiting: "The assistant is preparing a response…",
    blocked: "I can’t complete this request because it is restricted by the safety policy. Try a different request.",
    timeout: "The response took too long. Please try sending your message again.",
    failure: "Couldn’t get a response. Please try again in a moment.",
  },
  pl: {
    run: "Identyfikator uruchomienia", language: "Język", home: "AI Chat — strona główna", newChat: "Nowy czat",
    eyebrow: "TWÓJ ASYSTENT AI", heading: "W czym mogę pomóc?",
    intro: "Zadaj pytanie, opisz zadanie lub poproś o pomoc w rozwinięciu pomysłu.",
    plan: "Zaplanuj dzień", topic: "Poznaj temat", draft: "Napisz wiadomość",
    planPrompt: "Pomóż mi zaplanować dzień pracy",
    topicPrompt: "Wyjaśnij prostymi słowami, jak działa zapora AI",
    draftPrompt: "Pomóż mi napisać krótki e-mail służbowy",
    conversation: "Rozmowa", message: "Wiadomość", placeholder: "Napisz wiadomość…",
    send: "Wyślij wiadomość", hint: "Enter — wyślij · Shift + Enter — nowy wiersz",
    user: "Ty", assistant: "Asystent", waiting: "Asystent przygotowuje odpowiedź…",
    blocked: "Nie mogę zrealizować tej prośby ze względu na zasady bezpieczeństwa. Spróbuj wysłać inną prośbę.",
    timeout: "Oczekiwanie na odpowiedź trwało zbyt długo. Spróbuj wysłać wiadomość ponownie.",
    failure: "Nie udało się uzyskać odpowiedzi. Spróbuj ponownie za chwilę.",
  },
};
let language = "en";
try {
  const saved = localStorage.getItem("chat-language");
  if (saved === "en" || saved === "pl") language = saved;
} catch { /* The chat also works when browser storage is unavailable. */ }
const t = key => translations[language][key];

const form = document.querySelector("#composer");
const prompt = document.querySelector("#prompt");
const messages = document.querySelector("#messages");
const welcome = document.querySelector("#welcome");
const status = document.querySelector("#status");
const send = document.querySelector("#send");
const reset = document.querySelector("#reset");
let history = [];
let pending = false;

function applyLanguage() {
  document.documentElement.lang = language;
  document.querySelector("#language").value = language;
  document.querySelectorAll("[data-i18n]").forEach(element => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach(element => {
    element.setAttribute("aria-label", t(element.dataset.i18nAria));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(element => {
    element.setAttribute("placeholder", t(element.dataset.i18nPlaceholder));
  });
  status.textContent = pending ? t("waiting") : "";
}

document.querySelector("#language").addEventListener("change", event => {
  language = event.target.value === "pl" ? "pl" : "en";
  try { localStorage.setItem("chat-language", language); } catch { /* Optional storage. */ }
  applyLanguage();
});
applyLanguage();

function appendMessage(role, text, error = false, translationKey = null) {
  const item = document.createElement("article");
  item.className = `message ${role}${error ? " error" : ""}`;
  const author = document.createElement("div");
  author.className = "author";
  author.dataset.i18n = role;
  author.textContent = t(role);
  const content = document.createElement("div");
  content.className = "content";
  if (translationKey) content.dataset.i18n = translationKey;
  content.textContent = translationKey ? t(translationKey) : text;
  item.append(author, content);
  messages.append(item);
  item.scrollIntoView({block: "end", behavior: "smooth"});
}

function setPending(value) {
  pending = value;
  send.disabled = value;
  reset.disabled = value;
  prompt.disabled = value;
  status.textContent = value ? t("waiting") : "";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = prompt.value.trim();
  if (pending || !text) return;
  welcome.hidden = true;
  appendMessage("user", text);
  prompt.value = "";
  setPending(true);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 150000);
  try {
    const response = await fetch("/v1/chat", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({messages: [...history, {role: "user", content: text}]}),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error("service");
    const data = await response.json();
    if (typeof data.run_id === "string") {
      const lastRun = document.querySelector("#last-run");
      lastRun.textContent = `${t("run")}: ${data.run_id}`;
    }
    const actions = new Set(["allow", "redact", "block", "review"]);
    if (typeof data.message?.content !== "string" ||
        !actions.has(data.input_decision?.action) ||
        (data.output_decision !== null && !actions.has(data.output_decision?.action))) {
      throw new Error("response");
    }
    const stopped = [data.input_decision, data.output_decision]
      .some(decision => decision && ["block", "review"].includes(decision.action));
    if (!stopped && !data.output_decision) throw new Error("response");
    if (stopped) {
      appendMessage("assistant", "", false, "blocked");
    } else {
      appendMessage("assistant", data.message.content);
      history.push({role: "user", content: text}, {role: "assistant", content: data.message.content});
    }
  } catch (error) {
    appendMessage("assistant", "", true, error.name === "AbortError" ? "timeout" : "failure");
    prompt.value = text;
  } finally {
    clearTimeout(timer);
    setPending(false);
    prompt.focus();
  }
});

prompt.addEventListener("keydown", event => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    form.requestSubmit();
  }
});

reset.addEventListener("click", () => {
  if (pending) return;
  history = [];
  document.querySelector("#last-run").textContent = "";
  messages.replaceChildren();
  welcome.hidden = false;
  prompt.value = "";
  status.textContent = "";
  prompt.focus();
});

document.querySelectorAll("[data-prompt-key]").forEach(button => {
  button.addEventListener("click", () => {
    prompt.value = t(button.dataset.promptKey);
    prompt.focus();
  });
});
