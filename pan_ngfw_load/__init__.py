"""pan-ngfw-load - PAN-OS load analysis from tech support files (offline) and the XML API (live).

Pipeline:  TSF bundle or live collection  ->  parsers  ->  Dataset (pandas tables, saved as CSV)
           ->  report sections (charts + text)  ->  PDF + findings.json

Add a new focus area by dropping a module into pan_ngfw_load/sections/ and listing it in
pan_ngfw_load/sections/__init__.py (see README.md).
"""

__version__ = "0.6.7"
