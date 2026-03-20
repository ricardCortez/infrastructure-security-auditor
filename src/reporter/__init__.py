"""Reporter package – HTML report generation.

Renders a professional, standalone HTML security report from Analyzer
output using a Jinja2 template. The output is a single self-contained
HTML file with inline CSS and no external CDN dependencies.

Classes:
    HTMLReporter: Renders and saves HTML reports from analysis data.

Example:
    >>> from src.reporter import HTMLReporter
    >>> reporter = HTMLReporter(analysis_data)
    >>> out = reporter.save("reports/server01_report.html")
    >>> print(f"Report saved: {out}")
"""

from src.reporter.html_generator import HTMLReporter

__all__ = ["HTMLReporter"]
