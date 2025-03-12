# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import json

project = "Scribe Auth"
copyright = "2025, Scribe Labs Limited"
author = "Ailin Venerus"
with open("../.release-please-manifest.json") as f:
    release = json.load(f)["."]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx_markdown_builder",
]

templates_path = ["_templates"]
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "alabaster"
# html_static_path = ["_static"]

source_dir = "./scribeauth"

import os
import sys

sys.path.insert(0, os.path.abspath(".."))
