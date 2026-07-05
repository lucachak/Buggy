from .tech        import detect  as detect_tech
from .js_analyzer import analyze as analyze_js
from .ports       import scan    as scan_ports
from .api         import discover as discover_apis

__all__ = ["detect_tech", "analyze_js", "scan_ports", "discover_apis"]
