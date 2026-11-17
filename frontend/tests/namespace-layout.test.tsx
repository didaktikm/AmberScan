import { describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { renderToStaticMarkup } from "react-dom/server";
import { NamespacePicker } from "../src/NamespacePicker";

describe("namespace picker layout structure", () => {
  test("pins search and counts outside one scroll region with all content and actions", () => {
    const window = new Window();
    window.document.body.innerHTML = renderToStaticMarkup(
      <NamespacePicker
        selected={["saved-team"]}
        options={Array.from({ length: 150 }, (_, index) => ({
          name: `team-${index}`,
          system: false,
        }))}
        onChange={() => {}}
        onRefresh={() => {}}
        onLoadMore={() => {}}
        complete={false}
        stale
        hint="context-team"
        savedNames={["saved-team"]}
      />,
    );
    const picker = window.document.querySelector("fieldset")!;
    const header = picker.querySelector(".namespace-picker-header")!;
    const scroll = picker.querySelector(".namespace-picker-scroll")!;
    expect(picker.querySelectorAll(".namespace-picker-scroll").length).toBe(1);
    expect(header.querySelector('input[type="search"]')).not.toBeNull();
    expect(header.querySelector('[role="status"]')?.textContent).toContain(
      "Выбрано 1 из 100",
    );
    expect(scroll.contains(header)).toBe(false);
    expect(scroll.getAttribute("tabindex")).toBe("0");
    expect(scroll.querySelectorAll('input[type="checkbox"]').length).toBe(151);
    expect(
      scroll
        .querySelector('input[aria-label="Пространство имён saved-team"]')
        ?.hasAttribute("checked"),
    ).toBe(true);
    expect(
      scroll
        .querySelector('input[aria-label="Пространство имён team-0"]')
        ?.hasAttribute("checked"),
    ).toBe(false);
    expect(
      scroll
        .querySelector(".namespace-list")
        ?.closest(".namespace-picker-scroll"),
    ).toBe(scroll);
    expect(scroll.querySelector(".namespace-manual")).not.toBeNull();
    expect(scroll.querySelector("[id$='-help']")).not.toBeNull();
    for (const notice of scroll.querySelectorAll(".notice")) {
      expect(notice.closest("details")).toBeNull();
    }
    expect(scroll.textContent).toContain("Показан предыдущий список");
    expect(scroll.textContent).toContain("Загружен неполный список");
    expect(scroll.textContent).toContain("Выбрать все загруженные (150)");
    expect(scroll.textContent).toContain("Загрузить ещё пространства имён");
    expect(scroll.textContent).toContain("Добавить к выбору");
    window.close();
  });

  test("translates known phases without changing names or unknown Kubernetes values", () => {
    const markup = renderToStaticMarkup(
      <NamespacePicker
        selected={[]}
        options={[
          { name: "active-team", phase: "Active", system: false },
          { name: "deleting-team", phase: "Terminating", system: false },
          { name: "future-team", phase: "FuturePhase", system: false },
        ]}
        onChange={() => {}}
      />,
    );
    expect(markup).toContain("Активно");
    expect(markup).toContain("Удаляется");
    expect(markup).toContain("FuturePhase");
    expect(markup).toContain('aria-label="Пространство имён active-team"');
    expect(markup).toContain("RoleBinding");
    expect(markup).not.toContain(">Active<");
    expect(markup).not.toContain(">Terminating<");
  });

  test("keeps native disabled fieldset and visible forbidden-list warning", () => {
    const window = new Window();
    window.document.body.innerHTML = renderToStaticMarkup(
      <NamespacePicker
        selected={[]}
        options={[]}
        onChange={() => {}}
        forbidden
        disabled
      />,
    );
    expect(
      window.document.querySelector("fieldset")?.hasAttribute("disabled"),
    ).toBe(true);
    const warning = window.document.querySelector(
      ".namespace-picker-scroll .notice-warning",
    );
    expect(warning?.textContent).toContain(
      "Kubernetes запретил получение списка пространств имён (403)",
    );
    expect(warning?.closest("details")).toBeNull();
    window.close();
  });
});
