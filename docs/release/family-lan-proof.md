# The family-LAN proof on real interfaces (PRD-001 R28)

`scripts/family-lan-proof.sh` proves the family LAN (ADR-013) on real utun interfaces on one
Mac. It needs root once, for one process (`vox lan helper`, which creates the utuns), so the
decider runs it by hand. Agents never run it with sudo.

## Run it

From a checkout of the release's tree, as your own account:

    sudo scripts/family-lan-proof.sh

That one command:

1. builds `target/release/vox` as you (never as root), or uses the binary you name:
   `sudo scripts/family-lan-proof.sh /path/to/vox`;
2. starts an anchor and three members (alice, bob, carol) in fresh temporary profiles, as
   you; it never opens your own vox profile;
3. starts `vox lan helper` as root (the only root process) and one `vox lan up` per member,
   as you, each on its own utun;
4. runs the six claims and prints `PASS` or `FAIL` for each;
5. stops everything it started by PID, on every exit (normal end, error, Ctrl-C, the
   terminal closing), and proves the teardown: no utun and no route of the run's is left.

It takes a few minutes: production Argon2id on four profiles and a real proof of work per
join.

## Read the result

Each claim prints one line. A `FAIL` names its side:

- `FAIL  PRODUCT: …` — vox did the wrong thing; the line quotes what it did.
- `FAIL  CANNOT MEASURE: …` — a setup step the claims stand on failed (quoted), so the run
  proves nothing either way; an interruption (Ctrl-C, the terminal closing) says so here too.
- `FAIL  APPARATUS: …` — the script stopped on an error of its own before every claim ran.

The summary ends with `RESULT: PASS` or `RESULT: FAIL` and the path of the log:

    paste this file back: /tmp/vox-lan-proof.XXXXXX/family-lan-proof.log

Paste that file back. It holds everything the run printed, the run's test passphrases and
fingerprints, and nothing of your own profile.

## Undo

Nothing, normally: the trap tears everything down, on a normal end, an error, Ctrl-C or the
terminal closing, and the `teardown` line says whether it worked. If the script itself was
killed outright (`kill -9`, a power cut) or the teardown line is a FAIL, undo by hand, in this
order:

1. **Stop what it started.** List them:

       pgrep -lf 'vox (node|serve|lan)|probe\.py|tcpdump -l -n -i utun'

   then `kill <pid>` each one that is yours, and `sudo kill <pid>` the `vox lan helper` (it runs
   as root). Check again with the same `pgrep`: it must print nothing of the run's.
2. **Check the interfaces.** A utun goes when the process holding it exits, so step 1 removes
   it. `ifconfig -l` lists what exists; the run printed its own (`alice: vox lan up on utunN …`)
   and the ones that existed before (`before: …`). Any of the run's still there means a process
   from step 1 is still running.
3. **Remove a route left behind.** The run printed the room's LAN (`LAN 10.x.y.0/24
   fdxx:…::/64`). If `netstat -rn` still shows a route to either:

       sudo route -n delete -net 10.x.y.0/24
       sudo route -n delete -inet6 fdxx:…::/64

   with the addresses the run printed.
4. **Remove its directory**, the one it printed last (`/tmp/vox-lan-proof.XXXXXX`):
   `rm -rf /tmp/vox-lan-proof.XXXXXX`, naming that exact directory. It holds test profiles and
   passphrases only.

Your own vox profile (`~/Library/Application Support/vox`) is never touched, so there is
nothing to undo there.

## Without root first

    scripts/family-lan-proof.sh --preflight [/path/to/vox]

runs every step before the root one (the anchor, the three profiles, trust, `vox serve` and
both joins) as you, with no sudo anywhere. It then starts `vox lan up` with exactly the
arguments the root run gives it, which can only be refused for want of a helper (it asks for
the helper before anything else, so this checks that the arguments are accepted, not what it
does with them). Then it tears down and stops. It is the check that the staging works before
the one root run.

## What only the root run proves

`crates/vox-tui/tests/family_lan_proof.rs` proves the LAN engine's claims without root, with
the test answering on the helper socket itself and a socketpair standing in for the utun.
These stay unproven until the root run:

- `vox lan helper` running as root and creating a real utun for each member;
- each `vox lan up` opening the room with the passphrase file and taking its utun;
- claims 1–6 crossing real interfaces and the kernel's routing (ping, UDP echo, mDNS,
  broadcast, the untrusted member, the whitelist);
- the teardown of real utuns and their routes.
