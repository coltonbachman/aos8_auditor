"""Reporting layer: machine JSON (source of truth) + human Markdown."""

from .diff import diff_reports, load_report, render_diff_text
from .html import render_html
from .json_report import collection_summary, write_collection_summary
from .report import render_markdown, write_report

__all__ = [
    "collection_summary",
    "write_collection_summary",
    "render_markdown",
    "render_html",
    "write_report",
    "diff_reports",
    "load_report",
    "render_diff_text",
]
