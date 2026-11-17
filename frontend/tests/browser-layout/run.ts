// Run from any directory: bun /absolute/path/frontend/tests/browser-layout/run.ts
// Requires installed Chrome and existing frontend/node_modules; installs nothing.
// No production route, server, authentication, credentials, or Kubernetes access.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const directory = fileURLToPath(new URL(".", import.meta.url));
const chrome =
  process.env.CHROME_BIN ??
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const artifacts = await mkdtemp(join(tmpdir(), "workbench-browser-layout-"));
const build = await Bun.build({
  entrypoints: [resolve(directory, "fixture.tsx")],
  outdir: join(artifacts, "bundle"),
  target: "browser",
  format: "iife",
  minify: false,
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
});
if (!build.success) throw new Error(build.logs.join("\n"));
const javascript = await build.outputs
  .find((output) => output.path.endsWith(".js"))!
  .text();
const css = await build.outputs
  .find((output) => output.path.endsWith(".css"))!
  .text();
const cases = [
  { width: 360, height: 640, theme: "light" },
  { width: 768, height: 720, theme: "light" },
  { width: 1280, height: 800, theme: "light" },
  { width: 360, height: 400, theme: "light" },
  { width: 360, height: 480, theme: "light" },
  { width: 360, height: 640, theme: "dark" },
  { width: 1280, height: 400, theme: "dark" },
];
const reports: unknown[] = [];
let failed = false;
console.log(
  `Chrome: ${(await new Response(Bun.spawn([chrome, "--version"], { stdout: "pipe" }).stdout).text()).trim()}`,
);
console.log(`Artifacts: ${artifacts}`);
for (const config of cases) {
  const name = `${config.width}x${config.height}-${config.theme}`;
  const profile = await mkdtemp(join(tmpdir(), "workbench-chrome-profile-"));
  try {
    // Chromium's desktop window has a minimum width; a real iframe viewport avoids
    // mistaking --window-size for 360px content. Assertions verify innerWidth/Height.
    // Local srcdoc and CSP deny all network/resource loads. Same-origin sandbox
    // keeps Chromium's virtual clock shared with the result collector.
    const frame = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; font-src 'none'; form-action 'none'"><style>${css}</style></head><body><div id="fixture-root"></div><script>window.fixtureConfig=${JSON.stringify(config)};addEventListener('error',event=>parent.postMessage({browserLayout:true,config:window.fixtureConfig,pass:false,checks:[{name:'fixture script error',pass:false,detail:event.message}],snapshots:[]},'*'));${javascript.replaceAll("</script", "<\\/script")}</script></body></html>`;
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Isolated browser layout fixture</title><style>html,body{margin:0}iframe{display:block;border:0}</style></head><body><iframe title="Synthetic layout fixture" sandbox="allow-scripts allow-modals allow-same-origin" width="${config.width}" height="${config.height}"></iframe><pre id="result" data-status="pending"></pre><script>const frame=document.querySelector('iframe');addEventListener('message',event=>{if(event.source!==frame.contentWindow||!event.data.browserLayout)return;const result=document.getElementById('result');result.dataset.status='complete';result.dataset.result=btoa(unescape(encodeURIComponent(JSON.stringify(event.data))));});frame.srcdoc=${JSON.stringify(frame).replaceAll("<", "\\u003c")};</script></body></html>`;
    const path = join(artifacts, `${name}.html`);
    await writeFile(path, html);
    const args = [
      chrome,
      "--headless=new",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--disable-extensions",
      "--disable-default-apps",
      "--metrics-recording-only",
      "--host-resolver-rules=MAP * ~NOTFOUND",
      "--disable-features=OptimizationHints,MediaRouter",
      "--force-device-scale-factor=1",
      `--window-size=${Math.max(800, config.width)},${Math.max(800, config.height)}`,
      "--virtual-time-budget=8000",
      "--dump-dom",
      `file://${path}`,
    ];
    await writeFile(
      join(artifacts, `${name}.command.json`),
      JSON.stringify(args, null, 2),
    );
    const process = Bun.spawn(args, { stdout: "pipe", stderr: "pipe" });
    const deadline = setTimeout(() => process.kill(), 30000);
    const [dom, stderr, code] = await Promise.all([
      new Response(process.stdout).text(),
      new Response(process.stderr).text(),
      process.exited,
    ]);
    clearTimeout(deadline);
    await writeFile(join(artifacts, `${name}.dom.html`), dom);
    await writeFile(join(artifacts, `${name}.stderr.log`), stderr);
    const encoded = dom.match(/data-result="([A-Za-z0-9+/=]+)"/)?.[1];
    if (code !== 0 || !encoded)
      throw new Error(
        `${name}: Chrome exited ${code}; completed result absent=${!encoded}. See artifacts.`,
      );
    const report = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
    reports.push(report);
    await writeFile(
      join(artifacts, `${name}.json`),
      JSON.stringify(report, null, 2),
    );
    console.log(
      `${report.pass ? "PASS" : "FAIL"} ${name}: ${report.checks.filter((check: { pass: boolean }) => check.pass).length}/${report.checks.length} checks`,
    );
    for (const check of report.checks.filter(
      (check: { pass: boolean }) => !check.pass,
    ))
      console.error(`  ${check.name}: ${JSON.stringify(check.detail ?? null)}`);
    if (!report.pass) failed = true;
  } catch (error) {
    failed = true;
    reports.push({ config, pass: false, error: String(error) });
    console.error(String(error));
  } finally {
    await rm(profile, { recursive: true, force: true });
  }
}
await writeFile(
  join(artifacts, "results.json"),
  JSON.stringify(reports, null, 2),
);
console.log(`Structured results: ${join(artifacts, "results.json")}`);
process.exitCode = failed ? 1 : 0;
