#!/usr/bin/env python3
"""Compare identical TODO 296 harnesses built against baseline and changed cores."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--before-root', type=Path, required=True)
    parser.add_argument('--after-root', type=Path, required=True)
    parser.add_argument('--before-target', type=Path, required=True)
    parser.add_argument('--before-alloc-target', type=Path)
    parser.add_argument('--after-target', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--label', default='step1')
    parser.add_argument('--held-outputs', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    roots = {'before': args.before_root, 'after': args.after_root}
    targets = {'before': args.before_target, 'after': args.after_target}
    alloc_targets = {'before': args.before_alloc_target or args.before_target, 'after': args.after_target}
    fixture_files = ['examples/allocation_baseline.rs', 'examples/allocation_profile.rs',
                     'examples/support/allocation_fixture.rs']
    for name in fixture_files:
        if (args.before_root/name).read_bytes() != (args.after_root/name).read_bytes():
            raise SystemExit(f'Different measurement source: {name}')
    metadata = {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'repeats': args.repeats, 'sides': {},
                'profile': 'release, opt-level=z, thin LTO, codegen-units=1, panic=abort',
                'features': [], 'warmup_seconds': 1, 'measurement_seconds': 3, 'samples': 30}
    for side in roots:
        root, target = roots[side], targets[side]
        binaries = {'allocation_baseline':target/'release/examples/allocation_baseline',
                    'allocation_profile':alloc_targets[side]/'release/examples/allocation_profile'}
        metadata['sides'][side] = {
            'root': str(root), 'target': str(target),
            'base_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
            'binary_sha256': {k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in binaries.items()},
            'source_sha256': {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in [*fixture_files,
                'src/crypto/messaging/double_ratchet/storage.rs','src/cfe/envelope.rs',
                'src/orchestration/session_lifecycle.rs','src/uniffi_bindings.rs']},
        }
    (args.output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    for trial in range(1,args.repeats+1):
        for side in ['before','after']:
            with (args.output/f'{side}-alloc-{trial}.jsonl').open('w') as out, (args.output/f'{side}-alloc-{trial}.stderr').open('w') as err:
                subprocess.run([str(alloc_targets[side]/'release/examples/allocation_profile')],cwd=roots[side],stdout=out,stderr=err,check=True)
            if args.held_outputs:
                with (args.output/f'{side}-held-{trial}.jsonl').open('w') as out:
                    subprocess.run([str(alloc_targets[side]/'release/examples/allocation_profile'),'--held-outputs'],cwd=roots[side],stdout=out,check=True)
    selected = r'save/SF/k(0|100|500|900)_p0$|save/SF/k500_p3$|payload/PE/(50|65536)$'
    for trial in range(1,args.repeats+1):
        order = ['before','after'] if trial%2 else ['after','before']
        for side in order:
            label = f'{args.label}-{side}-{trial}'
            print('START',label,flush=True)
            env = dict(os.environ,CARGO_TARGET_DIR=str(targets[side]))
            command = [str(targets[side]/'release/examples/allocation_baseline'), '--bench',
                       '--noplot','--save-baseline',label,selected]
            with (args.output/f'{label}.log').open('w') as log:
                subprocess.run(command,cwd=roots[side],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
            criterion = targets[side]/'criterion'
            count=0
            for estimates in criterion.glob(f'**/{label}/estimates.json'):
                destination=args.output/'criterion'/estimates.parent.relative_to(criterion)
                destination.mkdir(parents=True,exist_ok=True)
                for name in ['estimates.json','sample.json','benchmark.json','tukey.json']:
                    if estimates.with_name(name).exists(): shutil.copyfile(estimates.with_name(name),destination/name)
                count+=1
            if count!=7: raise SystemExit(f'Expected 7 timed cases, got {count}')
            print('FINISH',label,flush=True)
    memory={}
    for side in roots:
        runs=[{v['case']:v for v in map(json.loads,p.read_text().splitlines())}
              for p in sorted(args.output.glob(f'{side}-alloc-*.jsonl'))]
        if not all(run==runs[0] for run in runs): raise SystemExit(f'Non-identical {side} allocation runs')
        memory[side]=runs[0]
    times={}
    for path in (args.output/'criterion').glob('**/benchmark.json'):
        case=json.loads(path.read_text())['full_id']
        side=path.parent.name.split('-')[1]
        value=json.loads(path.with_name('estimates.json').read_text())['mean']['point_estimate']/1000
        times.setdefault(case,{}).setdefault(side,[]).append(value)
    rows=[]
    for case,sides in sorted(times.items()):
        if any(len(v)!=args.repeats for v in sides.values()): raise SystemExit(f'Missing repeats: {case}')
        row={'case':case}
        for side in roots:
            values=sides[side];m=memory[side][case]
            row.update({f'{side}_us':statistics.median(values),f'{side}_min_us':min(values),f'{side}_max_us':max(values),
                f'{side}_allocations':m['allocations'],f'{side}_allocated_bytes':m['allocated_bytes'],
                f'{side}_reallocations':m['reallocations'],f'{side}_realloc_requested_bytes':m['realloc_requested_bytes'],
                f'{side}_additional_peak_bytes':m['additional_peak_bytes'],f'{side}_live_delta':m['live_delta_after_drop']})
        row['time_reduction_percent']=(1-row['after_us']/row['before_us'])*100
        row['allocation_reduction_percent']=(1-row['after_allocations']/row['before_allocations'])*100
        if case.startswith('save/SF/'):
            if memory['before'][case]['metadata']['cfe'] != memory['after'][case]['metadata']['cfe']:
                raise SystemExit(f'Changed output size: {case}')
            if row['after_allocations']>=row['before_allocations'] or row['after_live_delta']!=0:
                raise SystemExit(f'Missing allocation effect: {case}')
        rows.append(row)
    if args.held_outputs:
        held={}
        for side in roots:
            runs=[{v['case']:v for v in map(json.loads,p.read_text().splitlines())}
                  for p in sorted(args.output.glob(f'{side}-held-[0-9]*.jsonl'))]
            if not all(run==runs[0] for run in runs): raise SystemExit(f'Non-identical held-output runs: {side}')
            held[side]=runs[0]
        for case,before in held['before'].items():
            after=held['after'][case]
            if after['output_len']!=before['output_len'] or after['live_bytes_with_output']>before['live_bytes_with_output']:
                raise SystemExit(f'Retained output regressed: {case}')
            if after['additional_peak_bytes']>=before['additional_peak_bytes']:
                raise SystemExit(f'No peak memory effect: {case}')
            # Rust capacity is exact after compaction, but malloc may keep a larger size class.
            # Record that tradeoff rather than treating capacity as physical memory evidence.
        (args.output/'held-comparison.json').write_text(json.dumps(held,indent=2)+'\n')
    (args.output/'comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
    with (args.output/'comparison.csv').open('w') as out:
        writer=csv.DictWriter(out,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    metadata['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    (args.output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    for row in rows:
        print(f"{row['case']}: {row['before_us']:.3f} -> {row['after_us']:.3f} us; {row['before_allocations']} -> {row['after_allocations']} allocations")


if __name__=='__main__':
    main()
