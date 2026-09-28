"""Validate the paired display catalogs and direct C# resource references (stdlib only)."""
from pathlib import Path
import json
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REPORTING = ROOT / "SteamSentinel.Core" / "Reporting"
errors = []
counts = {}
catalogs = {}
for catalog in ("PresentationMessages", "StatusMessages"):
    languages = []
    for suffix in ("", ".zh-Hans"):
        path = REPORTING / f"{catalog}{suffix}.resx"
        entries = ET.parse(path).getroot().findall("data")
        mapping = {entry.attrib["name"]: entry.findtext("value") or "" for entry in entries}
        if len(entries) != len(mapping):
            errors.append(f"Duplicate keys in {path.name}")
        if any(not text.strip() for text in mapping.values()):
            errors.append(f"Empty values in {path.name}")
        languages.append(mapping)
    english, chinese = languages
    if english.keys() != chinese.keys():
        errors.append(f"Key mismatch in {catalog}")
    parameters = lambda value: sorted(re.findall(r"\{\d+(?:,[^}:]+)?(?::[^}]+)?\}", value))
    for key in english.keys() & chinese.keys():
        if parameters(english[key]) != parameters(chinese[key]):
            errors.append(f"Placeholder mismatch: {catalog}/{key}")
        if re.search(r"[\u4e00-\u9fff]", english[key]):
            errors.append(f"Untranslated English template: {catalog}/{key}")
    counts[catalog] = len(english)
    catalogs[catalog] = english

sources = []
for project in ("SteamSentinel.Core", "SteamSentinel.App", "SteamSentinel.Broker", "SteamSentinel.ArchiveWorker"):
    sources.extend(p for p in (ROOT / project).rglob("*.cs") if not {"bin", "obj"} & set(p.relative_to(ROOT).parts))
all_source = "\n".join(p.read_text(encoding="utf-8-sig") for p in sources)
xaml_source = "\n".join(p.read_text(encoding="utf-8-sig") for p in (ROOT / "SteamSentinel.App").rglob("*.xaml")
                       if not {"bin", "obj"} & set(p.relative_to(ROOT).parts))
references = set(re.findall(r'DisplayText\.(?:Get|Format)\("([^"\r\n]+)"\s*[,)]', all_source))
references.update(re.findall(r'MessageText\.Create\("([^"\r\n]+)"\s*[,)]', all_source))
references.update(re.findall(r'\{ui:Text ([\w.]+)\}', xaml_source))
rule_source = (ROOT / "SteamSentinel.Core" / "Rules" / "default-rules.json").read_text(encoding="utf-8-sig")
references.update(re.findall(r'"MessageId"\s*:\s*"([^"\r\n]+)"', rule_source))
for key in references - catalogs["PresentationMessages"].keys():
    errors.append(f"Missing display resource: {key}")
for key in set(re.findall(r'MessageText\.Status\("([^"\r\n]+)"\s*[,)]', all_source)) - catalogs["StatusMessages"].keys():
    errors.append(f"Missing structured status resource: {key}")
# Enum-derived keys are exhaustively checked by --resource-tests.
dynamic_prefixes = ("Amsi.Verdict.", "Execution.", "Run.", "Session.", "Backend.List.", "Backend.Join.",
                    "Resource.Assessment.", "Resource.Performance.", "Resource.Reason.")
# Retained for rendering reports saved before duplicate path checks were removed.
legacy_keys = {"Backend.Core.ContentScanner.Containers.ScanContainerFileAsync.04"}
unused = [key for key in catalogs["PresentationMessages"] if not key.startswith(dynamic_prefixes)
          and key not in legacy_keys and '"' + key + '"' not in all_source and key not in references]
if unused:
    errors.append("Unused display keys: " + ", ".join(sorted(unused)))
result = {"catalogs": counts, "totalPairs": sum(counts.values()), "directDisplayKeys": len(references), "errors": errors}
print(json.dumps(result, ensure_ascii=False, indent=2))
sys.exit(bool(errors))
