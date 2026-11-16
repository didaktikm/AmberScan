"""Offline reports from normalized, projected observations only."""

import html
import json


def render_report(run: dict, format: str) -> tuple[str, str, str]:
    report = {
        "schema": "amberdata.run.v1",
        "notice": "Отчёт ограничен указанным scope и выполненными проверками. Отсутствие находок не доказывает безопасность. Импорт не подтверждает происхождение данных.",
        **run,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if format == "json":
        return encoded, "application/json", "json"
    if format == "markdown":
        # Escape HTML, and indent data instead of trusting scanner-provided Markdown.
        text = "# AmberData — отчёт обследования\n\n"
        text += html.escape(report["notice"]) + "\n\n"
        text += "## Данные запуска и доказательства\n\n"
        text += "\n".join("    " + html.escape(line) for line in encoded.splitlines())
        return text + "\n", "text/markdown", "md"
    page = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AmberData — отчёт обследования</title>
<style>body{font:15px system-ui,sans-serif;color:#151515;background:#f8f8f8;margin:0}header{background:#151515;color:white;padding:24px;border-bottom:4px solid #e85002}main{max-width:1100px;margin:auto;padding:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;border:1px solid #ddd;padding:20px;border-radius:8px}p{line-height:1.6}@media print{body{background:white}header{background:white;color:black}pre{font-size:10px}}</style>
</head><body><header><h1>AmberData · Kubernetes Security Workbench</h1></header><main><p>NOTICE</p><pre>REPORT</pre></main></body></html>"""
    page = page.replace("NOTICE", html.escape(report["notice"])).replace("REPORT", html.escape(encoded))
    return page, "text/html", "html"
