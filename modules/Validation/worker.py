from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from modules.Validation.registry import ValidatorSpec
from modules.utils.http_client import configure_http


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--request", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    raw = request["spec"]
    spec = ValidatorSpec(
        raw["validator_id"], raw["name"], tuple(raw["cves"]), raw["risk"],
        raw["description"], raw["executor"], raw["implementation"],
        tuple(raw["methods"]), raw["timeout"], raw["reversible"],
        raw["requires_auth"], raw["enabled"], raw["source"],
    )
    spec.validate()
    configure_http(request["target"], active_tests=spec.risk != "safe", max_rate=5)
    module_name, function_name = spec.implementation.rsplit(".", 1)
    function = getattr(importlib.import_module(module_name), function_name)
    try:
        value = function({
            "target": request["target"], "timeout": spec.timeout,
            "output_dir": request["output_dir"], "validator_id": spec.validator_id,
            "cve_id": request.get("cve_id", ""),
        })
        result = {"status": "completed", "validator_id": spec.validator_id, "result": value}
    except Exception as exc:
        result = {"status": "failed", "validator_id": spec.validator_id,
                  "error": f"{type(exc).__name__}: {exc}"}
    Path(args.result).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
