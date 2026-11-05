# Sicil

Checks once a day whether the packages on this CachyOS machine have known security
problems, and combines that with how recently Yoklama saw each package used. It only
reads and reports: it never installs or removes anything, and it needs no root.

```sh
bin/sicil run                               # check the sources, record what changed
bin/sicil report [--all] [--json]           # show the findings, no network
python3 -B -m unittest discover -s tests    # tests, no network
```

Besides the Arch tracker and the AUR it reads CVE records from cvelistV5, EPSS scores
and the CISA KEV catalog. Needs `arch-audit`, `pactree` (pacman-contrib) and `yoklama`. State is kept in
`~/.local/state/sicil/sicil.db`.
