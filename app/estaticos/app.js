"use strict";

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-audit-toggle]").forEach((row) => {
    row.addEventListener("click", () => {
      const detail = document.getElementById(`detalle-${row.dataset.auditToggle}`);
      if (detail) detail.hidden = !detail.hidden;
    });
  });

  document.querySelectorAll(".js-confirm-delete").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.dataset.confirm || "¿Confirmar esta acción?";
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  const printButton = document.getElementById("btn-imprimir");
  if (printButton) printButton.addEventListener("click", () => window.print());

  const emissionDate = document.getElementById("fecha-emision");
  if (emissionDate) emissionDate.textContent = new Date().toLocaleString("es-MX");
});
