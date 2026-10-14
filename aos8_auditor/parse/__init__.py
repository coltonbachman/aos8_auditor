"""Parsing & data-model layer.

A single generic indentation + ``!``-terminated block parser (``config_tree``)
builds a ``ConfigNode`` tree from ``show running-config``; ``facts`` and
``model_builder`` then produce the typed ``ControllerModel`` / ``ControllerFacts``.
A logged, idempotent ``sanitizer`` pass runs first to strip transcript noise
(pagers, prompts, banners) and tolerate quoting artifacts.
"""
