#!/usr/bin/env python3
"""ADR-024 M24.1 spike analysis: every derived figure, from the run logs and traces, with its method.

Method (printed with the output):
- RESULT: the run's own RESULT line, verbatim (means over the last two thirds of the timeline).
- Trace time is milliseconds since the sending `vox forward` process started its controller code.
  "Judged" trace lines are those at trace time >= T0_MS (default 17000): past the unshaped warm-up
  (about 6 s) plus the 10 s windowed base round trip, so the base is the shaped link's.
- Loss share: sum of lost bytes on judged L lines / (that + sum of acked bytes on judged S lines).
- Queue rise at a loss: the qd field (last finished round's minimum minus the windowed base, in us)
  on judged L lines; nearest-rank percentiles.
- Delay-classified: share of judged L lines with delayq 1.
- Timeline: the TL lines (500 ms windows of the sink's counters); min/max over the given span.
- Lateness: the largest "late N ms" on any TL line of the run.
"""
import re, sys, glob, os

RUNS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")
T0_MS = int(os.environ.get("T0_MS", "17000"))


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = max(0, min(len(xs) - 1, int(round(p / 100.0 * len(xs) + 0.5)) - 1))
    return xs[k]


def run(name):
    log = os.path.join(RUNS, name + ".log")
    tr = os.path.join(RUNS, name + ".trace")
    out = {"name": name}
    text = open(log).read() if os.path.exists(log) else ""
    m = re.search(r"^RESULT.*$", text, re.M)
    out["result"] = "\n    ".join(re.findall(r"^RESULT.*$", text, re.M)) or "(no RESULT line)"
    late = [int(x) for x in re.findall(r"late (\d+) ms", text)]
    out["late_max"] = max(late) if late else None
    lost = acked = 0
    qd = []
    delayq = n_l = 0
    if os.path.exists(tr):
        for line in open(tr):
            f = line.split()
            if len(f) < 3 or int(f[1]) < T0_MS:
                continue
            kv = {f[i]: f[i + 1] for i in range(3, len(f) - 1)}
            if f[0] == "S":
                acked += int(kv.get("acked", 0))
            elif f[0] == "L":
                lost += int(f[-1])
                n_l += 1
                if kv.get("qd", "-1") != "-1":
                    qd.append(int(kv["qd"]))
                delayq += kv.get("delayq") == "1"
    out["share"] = lost / (lost + acked) if lost + acked else None
    out["qd"] = qd
    out["delayq"] = delayq / n_l if n_l else None
    out["losses"] = n_l
    return out, text


def timeline(text, label, t_from, t_to):
    vals = []
    for m in re.finditer(r"^TL (\S+) t=([\d.]+) vox ([\d.]+) comp ([\d.]+)", text, re.M):
        if m.group(1) == label and t_from <= float(m.group(2)) <= t_to:
            vals.append((float(m.group(2)), float(m.group(3))))
    return vals


if __name__ == "__main__":
    print(__doc__.split("Method")[1].strip().replace("(printed with the output):", "Method:"))
    print(f"T0_MS = {T0_MS}\n")
    for name in sys.argv[1:]:
        r, text = run(name)
        print(f"== {name}")
        print(f"    {r['result']}")
        if r["share"] is not None:
            print(f"    loss share (judged): {100 * r['share']:.2f}%  over {r['losses']} loss events")
        if r["qd"]:
            q = [x / 1000 for x in r["qd"]]
            print(
                f"    queue rise at a loss (judged, ms): p10 {pct(q,10):.2f} p50 {pct(q,50):.2f} "
                f"p90 {pct(q,90):.2f} p99 {pct(q,99):.2f}  n={len(q)}"
            )
            print(f"    delay-classified (judged): {100 * r['delayq']:.1f}%")
        print(f"    emulator lateness, max over the run: {r['late_max']} ms")
    for spec in os.environ.get("TL", "").split(";"):
        if not spec:
            continue
        name, label, a, b = spec.split(",")
        _, text = run(name)
        v = timeline(text, label, float(a), float(b))
        if v:
            print(
                f"== timeline {name} {label} t={a}..{b} s: min {min(x for _, x in v):.1f} "
                f"max {max(x for _, x in v):.1f} Mbit/s over {len(v)} windows"
            )
