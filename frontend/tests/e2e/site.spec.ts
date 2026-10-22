import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const EVIDENCE = process.env.E2E_EVIDENCE_DIR ?? "../evidence/e2e";
const SCREENS = join(EVIDENCE, "screens");
mkdirSync(SCREENS, { recursive: true });

// Let finite animations and transitions finish so evidence and audits see settled states, not mid-frame ones.
async function settle(page: Page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running" || a.effect?.getTiming().iterations === Infinity), null, { timeout: 3000 }).catch(() => {});
}

async function shot(page: Page, name: string, fullPage = true) {
  await settle(page);
  await page.screenshot({ path: join(SCREENS, `${test.info().project.name}-${name}.jpg`), type: "jpeg", quality: 70, fullPage });
}

function watch(page: Page) {
  const problems: string[] = [];
  page.on("console", (m) => m.type() === "error" && problems.push(`console: ${m.text()}`));
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  page.on("response", (r) => {
    const url = new URL(r.url());
    if (r.status() >= 400 && url.origin === new URL(page.url() || r.url()).origin) problems.push(`HTTP ${r.status()} ${url.pathname}`);
  });
  return problems;
}

async function noOverflow(page: Page) {
  const [scroll, inner] = await page.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]);
  expect(scroll, "page must not scroll horizontally").toBeLessThanOrEqual(inner + 1);
}

async function axe(page: Page) {
  await settle(page);
  // @axe-core/playwright is typed against its own Playwright Page version; the runtime object is the same.
  const results = await new AxeBuilder({ page: page as never }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  // Name every failing element and axe's reason so a CI-only failure can be diagnosed from the log alone.
  expect(serious.map((v) => `${v.id}: ${v.nodes.map((n) => `${n.target.join(" ")} (${(n.failureSummary ?? "").replace(/\s+/g, " ").slice(0, 160)})`).join("; ")}`)).toEqual([]);
}

const drawer = (page: Page) => page.getByRole("complementary", { name: "Event details" });
const CAUSAL = /\b(caused|led to|resulted in|because of|triggered|due to)\b/i;

test("incidents: list, loom, legend and headline; accessible, no overflow", async ({ page }) => {
  const problems = watch(page);
  await page.goto("./");
  await expect(page.locator("#il-incident-title")).toBeVisible();
  await expect(page.locator(".il-loom .il-knot").first()).toBeVisible();
  await expect(page.getByRole("list", { name: "Loom legend" })).toBeVisible();
  await expect(page.locator(".il-runline")).toContainText("synthetic");
  await noOverflow(page);
  await axe(page);
  await shot(page, "incident");
  await shot(page, "incident-first-viewport", false);
  expect(problems).toEqual([]);
});

test("timeline entry opens its events in the drawer; Escape closes it", async ({ page }) => {
  const problems = watch(page);
  await page.goto("./");
  await page.locator(".il-step-main").first().click();
  const d = drawer(page);
  await expect(d.locator(".il-event").first()).toBeVisible();
  await expect(d.getByText(/Raw record/).first()).toBeVisible();
  await noOverflow(page);
  await axe(page);
  await shot(page, "drawer", false);
  await page.keyboard.press("Escape");
  await expect(d).toBeHidden();
  expect(problems).toEqual([]);
});

test("hypotheses: show a reading and an alternative on the loom", async ({ page }) => {
  await page.goto("./");
  const show = page.getByRole("button", { name: "Show on loom" }).first();
  await show.click();
  await expect(page.getByRole("button", { name: "Showing on loom" }).first()).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".il-loom .il-knot[data-dim='true']").first()).toBeAttached();
  await page.getByRole("button", { name: "Show its events on the loom" }).first().click();
  await expect(page.locator(".il-loom .il-knot[data-tone='benign']").first()).toBeAttached();
  await shot(page, "hypothesis", false);
});

test("graph view and entity focus", async ({ page }) => {
  await page.goto("./");
  await page.getByRole("group", { name: "View" }).getByRole("button", { name: "Graph" }).click();
  await expect(page.locator(".il-graph .il-g-node").first()).toBeVisible();
  await page.locator(".il-graph .il-g-node").first().click();
  await expect(page.locator(".il-graph .il-g-node[data-focus='true']")).toHaveCount(1);
  await noOverflow(page);
  await shot(page, "graph", false);
});

test("an incident with a gap shows the frayed thread and lowered confidence", async ({ page }) => {
  await page.goto("./");
  const id = await page.evaluate(async () => {
    const snap = await (await fetch("data/snapshot.json")).json();
    const inc = await (await fetch(`data/runs/${snap.latest_run_id}/incidents.json`)).json();
    return inc.incidents.find((i: { gaps: string[] }) => i.gaps.length > 0)?.incident_id as string;
  });
  expect(id, "the run has an incident that depends on an evidence gap").toBeTruthy();
  await page.goto(`./#/incidents/${id}`);
  await expect(page.locator(".il-loom .il-gap").first()).toBeAttached();
  await expect(page.getByText(/lowered from/).first()).toBeVisible();
  await expect(page.getByRole("list", { name: "Evidence gaps in this incident" })).toBeVisible();
  expect(await page.locator(".il-incident").innerText()).not.toMatch(CAUSAL);
  await noOverflow(page);
  await shot(page, "gap-incident", false);
});

test("an evidence chip opens that event", async ({ page }) => {
  await page.goto("./");
  const chip = page.locator(".il-step .il-evidence .il-chip-link.il-mono").first();
  const text = (await chip.textContent())?.trim() ?? "";
  await chip.click();
  await expect(drawer(page).locator(".il-event-id").first()).toContainText(text);
});

test("sections: every section by link, back button restores", async ({ page }) => {
  const problems = watch(page);
  await page.goto("./");
  const nav = page.getByRole("navigation", { name: "Sections" });
  for (const [label, id] of [["Detectors", "detectors"], ["Replay", "replay"], ["Ingest", "ingest"], ["Entities", "entities"]] as const) {
    await nav.getByRole("link", { name: label }).click();
    await expect(page).toHaveURL(new RegExp(`#/${id}$`));
    await expect(page.locator("[data-section-heading]")).toBeFocused();
  }
  await page.goBack();
  await expect(page).toHaveURL(/#\/ingest$/);
  await noOverflow(page);
  expect(problems).toEqual([]);
});

test("timeline section: every event on entity threads, window controls", async ({ page }) => {
  await page.goto("./#/timeline");
  await expect(page.locator(".il-runloom .il-tickmark").first()).toBeAttached();
  const before = await page.locator(".il-runloom .il-tickmark").count();
  await page.getByRole("group", { name: "Jump to a day" }).getByRole("button").nth(2).click();
  await expect.poll(async () => page.locator(".il-runloom .il-tickmark").count()).toBeLessThan(before);
  await page.getByRole("group", { name: "Entity kind" }).getByRole("button", { name: "Hosts" }).click();
  await noOverflow(page);
  await axe(page);
  await shot(page, "timeline", false);
});

test("entities: filter by kind and name", async ({ page }) => {
  await page.goto("./#/entities");
  await page.getByRole("group", { name: "Entity kind" }).getByRole("button", { name: /^host/ }).click();
  await page.getByRole("searchbox", { name: "Filter entities" }).fill("zzz-no-such-entity");
  await expect(page.getByText("No entity matches this filter.")).toBeVisible();
  await page.getByRole("searchbox", { name: "Filter entities" }).fill("");
  await noOverflow(page);
  await axe(page);
  await shot(page, "entities", false);
});

test("detectors: held-out synthetic metrics labelled as such", async ({ page }) => {
  await page.goto("./#/detectors");
  await expect(page.getByRole("note").filter({ hasText: "Synthetic, held-out" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Held-out detector metrics, synthetic" })).toBeVisible();
  await expect(page.getByRole("list", { name: "Held-out scenario outcomes" }).getByRole("listitem").first()).toBeVisible();
  await noOverflow(page);
  await axe(page);
  await shot(page, "detectors");
});

test("replay and ingest: checkpoint states, accounting identity, quarantine, gaps", async ({ page }) => {
  await page.goto("./#/replay");
  await expect(page.getByRole("region", { name: "Checkpoint states" })).toBeVisible();
  await axe(page);
  await shot(page, "replay", false);
  await page.goto("./#/ingest");
  await expect(page.locator(".il-section-head")).toContainText(/records received = .* events \+ .* duplicates merged \+ .* quarantined/);
  await expect(page.getByRole("region", { name: "Ingest by batch and source" })).toBeVisible();
  await noOverflow(page);
  await axe(page);
  await shot(page, "ingest");
});

test("keyboard: skip link and visible focus", async ({ page }) => {
  await page.goto("./");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#il-main")).toBeFocused();
  await page.keyboard.press("Tab");
  const outline = await page.evaluate(() => getComputedStyle(document.activeElement as Element).outlineStyle);
  expect(outline).not.toBe("none");
  await shot(page, "keyboard-focus", false);
});

test("light theme: the theme control applies and stays accessible", async ({ page }) => {
  await page.goto("./#/request");
  await page.getByRole("group", { name: "Colour theme" }).getByRole("button", { name: "Light" }).click();
  await page.waitForTimeout(500); // theme transitions settle before the audit
  await expect(page.locator(".il-root")).toHaveAttribute("data-theme", "light");
  await axe(page);
  const [fg, bg] = await page.locator(".il-btn-primary").first().evaluate((el) => [getComputedStyle(el).color, getComputedStyle(el).backgroundColor]);
  expect(fg).not.toBe(bg);
  await page.goto("./");
  await axe(page);
  await shot(page, "light", false);
});

test("reduced motion: no running animations, loom complete", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("./");
  await expect(page.locator(".il-loom .il-knot").first()).toBeVisible();
  const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
  expect(running).toBe(0);
  await shot(page, "reduced-motion", false);
});

test("states: loading, empty, error with retry, stale", async ({ page }) => {
  let release: () => void = () => {};
  const gate = new Promise<void>((r) => (release = r));
  await page.route("**/data/snapshot.json", async (route) => { await gate; await route.continue(); });
  await page.goto("./");
  await expect(page.getByRole("status").filter({ hasText: "Loading" })).toBeVisible();
  await shot(page, "state-loading", false);
  release();
  await expect(page.locator("#il-incident-title")).toBeVisible();
  await page.unroute("**/data/snapshot.json");

  await page.route("**/data/snapshot.json", async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), latest_run_id: null, runs_included: [] } });
  });
  await page.goto("./?empty");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("No published investigations yet.");
  await shot(page, "state-empty", false);
  await page.unroute("**/data/snapshot.json");

  let fail = true;
  await page.route("**/data/snapshot.json", async (route) => {
    if (fail) await route.fulfill({ status: 503, body: "unavailable" });
    else await route.continue();
  });
  await page.goto("./?error");
  await expect(page.getByRole("alert")).toContainText("The server answered 503");
  await shot(page, "state-error", false);
  fail = false;
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.locator("#il-incident-title")).toBeVisible();
  await page.unroute("**/data/snapshot.json");

  await page.route("**/data/snapshot.json", async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), generated_at: "2025-01-01T00:00:00Z" } });
  });
  await page.goto("./?stale");
  await expect(page.getByText(/older than its 14-day freshness window/)).toBeVisible();
  await shot(page, "state-stale", false);
});

test("pages: runs ledger, request form link, about, preview image", async ({ page }) => {
  const problems = watch(page);
  const preview = await page.request.get("./preview.jpg");
  expect(preview.status(), "portfolio preview image (portfolio-manifest.json preview_image)").toBe(200);
  await page.goto("./#/runs");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Every investigation run");
  await noOverflow(page);
  await page.goto("./#/request");
  await expect(page.getByRole("link", { name: /Open the run request form/ })).toHaveAttribute("href", /\/issues\/new\?template=run-request\.yml$/);
  await axe(page);
  await page.goto("./#/about");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("does not claim");
  await noOverflow(page);
  expect(problems).toEqual([]);
});
