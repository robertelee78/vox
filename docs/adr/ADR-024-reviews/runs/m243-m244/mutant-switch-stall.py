# MUTANT (never committed): tier 3 stalls at the switch — ProbeBw window gain 1.0, no ack height,
# so a seeded BBR never sends more than its estimate and sticks at the 4-packet floor.
p='crates/vox-core/src/transport/vox_bbr.rs'
s=open(p).read()
def rep(a,b):
    global s
    assert a in s, a[:70]; s=s.replace(a,b,1)
rep("""        self.cwnd_gain = K_DERIVED_HIGH_CWNDGAIN;""","""        self.cwnd_gain = 1.0; // MUTANT""")
rep("""            target_window += self.ack_aggregation.max_ack_height.get();""","""            // MUTANT: no ack height""")
open(p,'w').write(s)
