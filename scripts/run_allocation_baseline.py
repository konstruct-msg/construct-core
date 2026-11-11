#!/usr/bin/env python3
"""Collect TODO 296 baseline artifacts; builds must finish before this script starts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--time-target', type=Path, required=True)
    parser.add_argument('--alloc-target', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=5)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    timing = args.time_target / 'release/examples/allocation_baseline'
    if not timing.is_file():
        raise SystemExit(f'Build the Criterion example first: {timing}')
    profile = args.alloc_target / 'release/examples/allocation_profile'
    sources = ['Cargo.toml', 'examples/allocation_baseline.rs',
               'examples/support/allocation_fixture.rs', 'examples/allocation_profile.rs',
               'scripts/run_allocation_baseline.py']
    metadata = {
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'rustc': subprocess.check_output(['rustc', '-Vv'], cwd=ROOT, text=True),
        'uname': subprocess.check_output(['uname', '-a'], text=True).strip(),
        'features': [], 'profile': 'release opt-level=z thin-lto codegen-units=1 panic=abort',
        'time_binary': str(timing), 'allocation_binary': str(profile),
        'time_binary_sha256': hashlib.sha256(timing.read_bytes()).hexdigest(),
        'allocation_binary_sha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
        'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
        'clock': 'Criterion WallTime; PE timed blocks, setup excluded',
        'allocator': 'System for timing; separate System wrapper for requested heap counts',
        'reallocation_rule': 'successful realloc counted separately at new requested size; logical live size replaces old size',
        'peak_rule': 'maximum logical requested live heap above start; excludes allocator overhead and internal realloc transient copies',
        'warmup_seconds': 1, 'measurement_seconds': 3, 'samples': 30,
        'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for i in range(1, args.repeats + 1):
        with (output / f'alloc-{i}.jsonl').open('w') as out, (output / f'alloc-{i}.stderr').open('w') as err:
            subprocess.run([str(profile)], cwd=ROOT, stdout=out, stderr=err, check=True)
    with (output / 'delayed-sequence.log').open('w') as log:
        reproduction = subprocess.run([str(profile), '--reproduce-delayed-sequence'], cwd=ROOT,
                                      stdout=log, stderr=subprocess.STDOUT)
    metadata['delayed_sequence_exit_code'] = reproduction.returncode
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.time_target))
    # Full matrix once, then five independent A/A repeats of the priority cases.
    key_filter = r'payload/(P[134]|PE)/(50|65536)$|save/SF/k(0|500|900)_p0$|save/SF/k500_p3$'
    for run in range(args.repeats + 1):
        label = 'matrix' if run == 0 else f'aa-{run}'
        command = [str(timing), '--bench', '--noplot', '--save-baseline', label]
        if run:
            command.append(key_filter)
        print(f'START {label}', flush=True)
        with (output / f'{label}.log').open('w') as log:
            subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        criterion = args.time_target / 'criterion'
        copied = 0
        for estimates in criterion.glob(f'**/{label}/estimates.json'):
            destination = output / 'criterion' / estimates.parent.relative_to(criterion)
            destination.mkdir(parents=True, exist_ok=True)
            for name in ['estimates.json', 'sample.json', 'benchmark.json', 'tukey.json']:
                source = estimates.parent / name
                if source.exists():
                    shutil.copyfile(source, destination / name)
            copied += 1
        if not copied:
            raise SystemExit(f'No Criterion estimates found under {criterion}')
        print(f'FINISH {label}: {copied} cases', flush=True)
    metadata['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
