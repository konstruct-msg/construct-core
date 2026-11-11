#!/usr/bin/env python3
"""Join Criterion estimates with separate allocation counts, preserving raw runs."""
import argparse
import csv
import json
from pathlib import Path
import statistics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('results', type=Path)
    args = parser.parse_args()
    root = args.results
    allocation_runs = []
    for path in sorted(root.glob('alloc-*.jsonl')):
        allocation_runs.append({r['case']: r for r in map(json.loads, path.read_text().splitlines())})
    if len(allocation_runs) != 5 or not all(r == allocation_runs[0] for r in allocation_runs):
        raise SystemExit('Expected five identical allocation runs')
    times = {}
    for path in sorted((root / 'criterion').glob('**/benchmark.json')):
        benchmark = json.loads(path.read_text())
        estimate = json.loads(path.with_name('estimates.json').read_text())['mean']
        case = benchmark['full_id']
        run = path.parent.name
        times.setdefault(case, {})[run] = estimate
    if len(times) != 46:
        raise SystemExit(f'Expected 46 timed cases, found {len(times)}')
    rows = []
    for case, memory in allocation_runs[0].items():
        measurements = times[case]
        aa = [v['point_estimate'] / 1000 for k, v in measurements.items() if k.startswith('aa-')]
        matrix = measurements['matrix']
        row = {
            'case': case,
            'time_us': statistics.median(aa) if aa else matrix['point_estimate'] / 1000,
            'aa_runs': len(aa),
            'aa_min_us': min(aa) if aa else '',
            'aa_max_us': max(aa) if aa else '',
            'aa_spread_percent': (max(aa) - min(aa)) / statistics.median(aa) * 100 if aa else '',
            'matrix_mean_us': matrix['point_estimate'] / 1000,
            'matrix_ci95_low_us': matrix['confidence_interval']['lower_bound'] / 1000,
            'matrix_ci95_high_us': matrix['confidence_interval']['upper_bound'] / 1000,
            **{k: v for k, v in memory.items() if k not in ('case', 'metadata')},
            'all_requested_bytes': memory['allocated_bytes'] + memory['realloc_requested_bytes'],
            'metadata': memory['metadata'],
        }
        rows.append(row)
    (root / 'summary.json').write_text(json.dumps(rows, indent=2) + '\n')
    with (root / 'summary.csv').open('w') as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows({**r, 'metadata': json.dumps(r['metadata'], sort_keys=True)} for r in rows)
    by_case = {r['case']: r for r in rows}
    machine = json.loads((root / 'metadata.json').read_text()).get('machine', {})
    machine_label = (f"{machine.get('cpu', 'CPU не записан')}, {machine.get('ram_gib', '?')} ГиБ RAM, "
                     f"{machine.get('logical_cpus', '?')} CPU; ОС и rustc — в metadata.json. ")
    lines = ['## Результаты измерений на Mac', '',
        machine_label +
        'Рабочий suite 4, PQ epoch 1, default features, release `opt-level=z`, thin LTO, '
        '`codegen-units=1`, `panic=abort`. Product source — `42f5bdf`; измерительные examples добавлены отдельно.', '',
        'Время: Criterion, 1 с warm-up, 3 с измерений, 30 samples. В таблицах при наличии пяти '
        'A/A запусков показана медиана их средних; у остальных — среднее полной матрицы. '
        'Это не p50/p95 отдельных сообщений. Для полной матрицы 95% интервалы сохранены в CSV/JSON. '
        'Аллокации сняты отдельно, пять запусков дали одинаковые строки.', '',
        '### Разбор payload', '',
        '| Plaintext | Wire | P1 мкс | P3 мкс | P4 мкс | Приём PE мкс | P3 минус P1 как доля PE |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for size in [50, 512, 4096, 65536]:
        p1, p3, p4, pe = [by_case[f'payload/{p}/{size}'] for p in ['P1', 'P3', 'P4', 'PE']]
        share = (p3['time_us'] - p1['time_us']) / pe['time_us'] * 100
        lines.append(f"| {size} Б | {p1['metadata']['wire']} Б | {p1['time_us']:.3f} | {p3['time_us']:.3f} | {p4['time_us']:.3f} | {pe['time_us']:.2f} | {share:.1f}% |")
    lines += ['', 'P3 − P1 — разность отдельных микрозамеров, не измеренное ускорение нового кода. '
        'PE включает расшифрование, ACK/действия, session save и coordination save на обычном '
        'пути приёма; sender encryption и подготовка исключены. PE использует блоки до 128 '
        'сообщений на свежей живой паре, поэтому кэш ACK ограничен размером блока. '
        'Создание и уничтожение пары вне таймера; результаты события освобождаются внутри.', '',
        '| Plaintext | P1 аллокаций и байт | P4 аллокаций и байт | Пик P4 | Пик полного приёма PE |',
        '| --- | --- | --- | --- | --- |']
    for size in [50, 512, 4096, 65536]:
        p1, p4 = [by_case[f'payload/{p}/{size}'] for p in ['P1', 'P4']]
        pe = by_case[f'payload/PE/{size}']
        lines.append(f"| {size} Б | {p1['allocations']} / {p1['allocated_bytes']} Б | {p4['allocations']} / {p4['allocated_bytes']} Б | {p4['additional_peak_bytes']} Б | {pe['additional_peak_bytes']} Б |")
    lines += ['', 'P4 — модель копирования при разборе; пик всей операции показан в PE. '
        'Аллокации PE сняты на одном свежем событии, время PE — на блоках с ростом ACK-кэша, '
        'поэтому эти значения описывают разные положения в последовательности приёма. '
        'У PE отрицательная `live_delta_after_drop` допустима: событие и его входной буфер '
        'созданы до измерения и потребляются операцией. Счётчик видит Rust GlobalAlloc, '
        'не стек, прямые C malloc или память ОС.', '', '### Полный экспорт сессии SF', '',
        '| Classical и PQ skipped keys в каждом состоянии | Предыдущих | Время мкс | CFE байт | Новых аллокаций | Realloc | Запрошено всего байт | Дополнительный пик байт |',
        '| --- | --- | --- | --- | --- | --- | --- | --- |']
    for k, p in [(0, 0), (100, 0), (500, 0), (900, 0), (0, 3), (500, 3)]:
        r = by_case[f'save/SF/k{k}_p{p}']
        lines.append(f"| {k} + {k} | {p} | {r['time_us']:.2f} | {r['metadata']['cfe']} | {r['allocations']} | {r['reallocations']} | {r['all_requested_bytes']} | {r['additional_peak_bytes']} |")
    lines += ['', 'При 3 предыдущих состояниях K classical и K PQ ключей есть **в каждом из четырёх** '
        'состояний, а не суммарно. Все временные выделения SF освобождены после drop результата: '
        '`live_delta_after_drop = 0`. Пик — логический объём запрошенного heap сверх исходной '
        'фикстуры, без метаданных malloc и внутреннего пика realloc. Сумма запросов включает '
        'полный новый размер каждого realloc; она не равна одновременно живой памяти и не '
        'является измерением memcpy.', '',
        '### Этапы сохранения одного текущего состояния', '',
        '| K classical и K PQ | S1 копия в Serializable мкс | S2 копия в CFE record мкс | S3 MessagePack мкс | S4 CFE encode мкс | SF весь экспорт мкс |',
        '| --- | --- | --- | --- | --- | --- |']
    for k in [0, 100, 500, 900]:
        values = [by_case[f'save/{s}/k{k}_p0']['time_us'] for s in ['S1', 'S2', 'S3', 'S4', 'SF']]
        lines.append('| ' + str(k) + ' | ' + ' | '.join(f'{v:.2f}' for v in values) + ' |')
    lines += ['', 'S4 включает S3. S1/S2/S3/S4 с меткой `p3` измеряют только текущее состояние; '
        'SF измеряет весь record. Drop результатов, включая zeroize, входит во время. '
        'Сумма отдельных стадий служит ориентиром: она не заменяет стековый профиль полной операции.', '',
        '### Повторяемость ключевых случаев', '',
        '| Случай | Пять запусков от и до мкс | Размах относительно медианы |',
        '| --- | --- | --- |']
    for r in rows:
        if r['aa_runs']:
            if r['aa_runs'] != 5:
                raise SystemExit(f"Incomplete A/A repetitions for {r['case']}")
            lines.append(f"| {r['case']} | {r['aa_min_us']:.3f}–{r['aa_max_us']:.3f} | {r['aa_spread_percent']:.1f}% |")
    lines += ['', '### Проверка стенда и ограничения', '',
        'Калибровка счётчика проверяет отсутствие аллокаций, один буфер 128 Б и realloc '
        '16→32 Б. Три мутации отвергнуты проверками: пропущен один разбор, неверный plaintext, '
        'исчезли previous states после restore. Мутации применялись по одной, исходник восстановлен '
        'по SHA256; финальная немутированная версия повторно проверена.', '',
        'Каждое удерживаемое состояние отдельно успешно читает своё задержанное сообщение после '
        'CFE restore, обмен продолжается в обе стороны. **Совместная последовательность имеет '
        'воспроизводимый отказ уже на исходном ядре:** при K=500 и 3 previous states сначала '
        'читается задержанное сообщение текущего состояния, следующее задержанное сообщение '
        'предыдущего получает `MESSAGE_KEY_CONSUMED: PQ key 1/4 already used`. '
        'Команда: `cargo run --locked --offline --release --example allocation_profile -- '
        '--reproduce-delayed-sequence` (ожидаемый текущий exit code 1). Это отдельная находка '
        'baseline, не результат оптимизации. Причина требует отдельного разбора; продуктовый код '
        'не исправлялся. Отказ не следует скрывать общим утверждением о зелёных проверках.', '',
        'В этом прогоне измерены обычный приём и сохранение с накопленными ключами на Mac. '
        'Первый flight, pending PQ exchange/ciphertext, CLASSIC-контроль, другие opt-level, '
        'стековый профиль, индивидуальные хвосты задержки, FFI и secure store на телефоне '
        'остаются отдельными сериями; выводы о них из этих чисел не делаются.', '',
        '### Выбор следующего шага', '',
        'Для коротких сообщений цена двух лишних разборов сопоставляется с полной обработкой '
        'по таблице; большой абсолютный выигрыш на обычной переписке заранее не обещается. '
        'Для крупных payload устранение повторных копий заметно уменьшит объём временных '
        'выделений. При накопленных skipped keys первым кандидатом становится цепочка '
        'сохранения: у неё подтверждены тысячи аллокаций и рост с размером удерживаемых состояний. '
        'Начать с одного преобразования с перемещением либо заимствованной сериализации того же '
        'CFE, затем повторить SF и PE. Snapshot ratchet рассматривать отдельным изменением '
        'после фиксации корректности обработки предыдущих состояний.', '']
    (root / 'report.md').write_text('\n'.join(lines))
    print(f'Wrote {len(rows)} joined cases; 5 identical allocation runs and A/A time repetitions')


if __name__ == '__main__':
    main()
