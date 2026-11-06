# Fish completions for sicil(1). IDs and package names come from the recorded findings
# in the default database. Kernel IDs are left out: there are hundreds of them.

function __sicil_findings --description 'List recorded IDs, CVEs or packages'
    sicil report --all --json 2>/dev/null | python3 -c '
import json, sys

kind = sys.argv[1]
report = json.load(sys.stdin)
sections = ("red", "yellow", "unverified", "looks_closed", "kernels", "not_found", "closed")
findings = [finding for name in sections for finding in report.get(name, [])]
seen = {}
for finding in findings:
    if kind == "packages":
        seen[finding["package"]] = ""
    for found in finding.get("ids", []):
        if kind == "ids":
            seen[found] = finding["detail"].get("severity") or ""
        elif kind == "cves":
            seen[found.rpartition(":")[2]] = finding["package"]
for value, description in seen.items():
    print(f"{value}\t{description}")
' $argv[1] 2>/dev/null
end

set -l commands run report show
set -l in_report '__fish_seen_subcommand_from report'
set -l in_show '__fish_seen_subcommand_from show'

complete -c sicil -f
complete -c sicil -s h -l help -d 'Show help and exit'

complete -c sicil -n "not __fish_seen_subcommand_from $commands" -a run -d 'Check the sources and record what changed'
complete -c sicil -n "not __fish_seen_subcommand_from $commands" -a report -d 'Show the recorded findings'
complete -c sicil -n "not __fish_seen_subcommand_from $commands" -a show -d 'Show one record against the installed version'

complete -c sicil -n "__fish_seen_subcommand_from $commands" -l db -r -F -d 'Database path'

complete -c sicil -n $in_report -l all -d 'Also show closed findings'
complete -c sicil -n $in_report -l json -d 'Print JSON, with the complete lists'
complete -c sicil -n $in_report -s p -l package -x -a '(__sicil_findings packages)' -d 'Package name; wildcards work'
complete -c sicil -n $in_report -l cve -x -a '(__sicil_findings cves)' -d 'CVE ID; wildcards work'
complete -c sicil -n $in_report -s s -l severity -x -a 'low medium high critical unknown' -d 'This level and above'
complete -c sicil -n $in_report -s c -l min-cvss -x -d 'This CVSS score and above'
complete -c sicil -n $in_report -l unused -x -d 'Not used for this many days'
complete -c sicil -n $in_report -l used -x -d 'Used within this many days'
complete -c sicil -n $in_report -l installed-min -x -d 'Installed version this or newer'
complete -c sicil -n $in_report -l installed-max -x -d 'Installed version this or older'
complete -c sicil -n $in_report -l record-min -x -d 'Version in the record this or newer'
complete -c sicil -n $in_report -l record-max -x -d 'Version in the record this or older'
complete -c sicil -n $in_report -l status -x -a 'open unverified looks-closed' -d 'Finding status'

complete -c sicil -n $in_show -a '(__sicil_findings ids)'
complete -c sicil -n $in_show -s f -l field -x -a 'desc installed status severity cvss epss kev range record fixed last-used url' -d 'Print one field bare'
