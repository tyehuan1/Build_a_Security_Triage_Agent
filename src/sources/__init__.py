"""Source access layer: raw retrieval from CVE, NVD, CISA KEV and Tavily with retry and cache fallback.

Sources return SourceResult objects (data + provenance receipt). They do not interpret
the data for the risk decision; that is the tool layer's job (src/tools/).
"""

from sources.base import SourceResult
from sources.cve import fetch_cve
from sources.kev import fetch_kev
from sources.nvd import fetch_nvd
from sources.tavily import search_tavily

__all__ = ["SourceResult", "fetch_cve", "fetch_nvd", "fetch_kev", "search_tavily"]
