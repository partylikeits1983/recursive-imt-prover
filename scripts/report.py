#!/usr/bin/env python3
"""Report component diagnostics; never label these as aggregation results."""
import json, statistics, sys
from pathlib import Path
p=Path(sys.argv[1]); d=json.loads(p.read_text()); rows=d['samples']
out=['# Component measurement report', '', '**NOT a recursive aggregation benchmark. Client authorization is missing from the transition proof.**', '',
     f"Depth {d['depth']}; one discarded warmup, {len(rows)} measured samples. Median [min, max].", '',
     f"Machine: {d['machine']['cpu']}, {int(d['machine']['ram_bytes'])/2**30:.0f} GiB RAM; Rayon threads {d['machine']['rayon_threads']}. Compiler: {d['machine']['rustc'].splitlines()[0]}. Native CPU tuning off. OS: {d['machine']['os']}", '',
     '| Component | ms median [range] |', '|---|---:|']
for field,title in [('client_witness_ms','Client witness'),('client_prove_ms','Client full-ZK proving'),('client_verify_ms','Native client verification'),('transition_trace_ms','Transition trace'),('transition_prove_ms','Transition-only FRI proving'),('transition_verify_ms','Transition verification'),('sequential_component_ms','Sequential component sum'),('idealized_client_parallel_component_ms','Idealized parallel component sum (not measured parallel execution)')]:
    values=[x for r in rows for x in (r[field] if isinstance(r[field],list) else [r[field]])]
    out.append(f'| {title} | {statistics.median(values):.3f} [{min(values):.3f}, {max(values):.3f}] |')
out+=['','Cold costs (one measurement each, not folded into warm numbers):','']
for k,v in d['cold'].items(): out.append(f'- {k}: {v:.3f} ms')
children=[sum(r['child_proof_bytes']) for r in rows]; transitions=[r['transition_proof_bytes'] for r in rows]
out+=['',f"Two child proof bytes: median {statistics.median(children):,.0f}, range {min(children):,}–{max(children):,}.",f"Transition-only proof bytes: median {statistics.median(transitions):,.0f}, range {min(transitions):,}–{max(transitions):,}.",
      '**These prove different relations. This is not proof compression or a two-to-one aggregation result.**','',
      f"Peak process high-water RSS: {max(r['process_high_water_bytes'] for r in rows)/2**20:.1f} MiB. Cumulative process peak; phase-specific peaks were not isolated.",'',
      'Circuit costs: `'+json.dumps(d['costs'],sort_keys=True)+'`.','',
      'Statement sizes: `'+json.dumps(d['statement'],sort_keys=True)+'`.','',
      'No recursive SPARK/WHIR costs, aggregate-only latency, quantum bound, complete composed soundness, or Ethereum gas result exists. Depths 4/16/32 are not benchmarked as complete systems; larger-batch and outer-WHIR experiments are deferred until recursion is complete.','',
      'Raw measurements: ['+p.name+']('+p.name+'), ['+p.with_suffix('.csv').name+']('+p.with_suffix('.csv').name+').',
      'Profile/security settings and exact upstream SHAs are stored in JSON. Notes, masks and proof randomness are fresh OS-random samples. Fixture construction, I/O, encoding, process startup and compilation are excluded from warm sums. Setup is explicitly reported above.']
p.with_suffix('.md').write_text('\n'.join(out)+'\n')
print(p.with_suffix('.md'))
