"""
Расчёт метрик качества детектора по CSV с посекундными метриками.

Использование:
    python tools/metrics.py <csv_path> --start <HH:MM:SS> --end <HH:MM:SS> [--threshold 300]

Метрики:
    TP (True Positive)  — секунды атаки, где сработал алерт
    FN (False Negative) — секунды атаки без алерта
    FP (False Positive) — секунды нормы, где сработал алерт
    TN (True Negative)  — секунды нормы без алерта

    TPR (Recall) = TP / (TP + FN)
    FPR          = FP / (FP + TN)
    Precision    = TP / (TP + FP)
    F1           = 2·P·R / (P + R)
"""

import argparse
import csv
import sys


def load_metrics(path):
    """Читает CSV с метриками."""
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def is_alert(row, threshold):
    """
    Считает ли детектор эту секунду алертом.
    Используем правило HIGH_PPS: top_src_pps > threshold.
    """
    try:
        top_pps = float(row.get("top_src_pps") or 0)
    except (ValueError, TypeError):
        return False
    return top_pps > threshold


def in_attack_window(time_str, start, end):
    """
    Определяет, попадает ли секунда в окно атаки.
    Если окно не задано (start и end — None) — считаем, что атаки нет.
    """
    if start is None and end is None:
        return False  # окна нет → все секунды нормальные
    t = time_str.split()[-1] if " " in time_str else time_str
    if start and t < start:
        return False
    if end and t > end:
        return False
    return True


def compute(rows, start, end, threshold):
    tp = fn = fp = tn = 0
    details = []

    for row in rows:
        t = row.get("timestamp", "")
        alert = is_alert(row, threshold)
        attack = in_attack_window(t, start, end)

        if attack and alert:
            tp += 1
            label = "TP"
        elif attack and not alert:
            fn += 1
            label = "FN"
        elif not attack and alert:
            fp += 1
            label = "FP"
        else:
            tn += 1
            label = "TN"

        details.append(
            (t, row.get("pps"), row.get("syn_ratio"), row.get("top_src_pps"), label)
        )

    return tp, fn, fp, tn, details


def main():
    parser = argparse.ArgumentParser(description="Расчёт метрик качества детектора")
    parser.add_argument("csv_path", help="Путь к CSV с метриками")
    parser.add_argument("--start", default=None, help="Начало окна атаки (HH:MM:SS)")
    parser.add_argument("--end", default=None, help="Конец окна атаки (HH:MM:SS)")
    parser.add_argument(
        "--threshold",
        type=int,
        default=300,
        help="Порог PPS для HIGH_PPS (по умолчанию 300)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Печатать посекундную разметку"
    )
    args = parser.parse_args()

    rows = load_metrics(args.csv_path)
    if not rows:
        print("CSV пуст.")
        sys.exit(1)

    tp, fn, fp, tn, details = compute(rows, args.start, args.end, args.threshold)

    if args.verbose:
        print(f"{'time':>10} | {'pps':>8} | {'syn':>6} | {'top_pps':>8} | label")
        print("-" * 55)
        for t, pps, syn, top, label in details:
            t_short = t.split()[-1] if " " in t else t
            syn_str = f"{float(syn):.1%}" if syn else "-"
            top_str = f"{float(top):.1f}" if top else "0"
            print(f"{t_short:>10} | {pps:>8} | {syn_str:>6} | {top_str:>8} | {label}")
        print()

    total_attack = tp + fn
    total_normal = tn + fp

    tpr = tp / total_attack if total_attack else 0.0
    fpr = fp / total_normal if total_normal else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tpr
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"Файл: {args.csv_path}")
    print(f"Окно атаки: {args.start or '—'} … {args.end or '—'}")
    print(f"Порог PPS: {args.threshold}")
    print()
    print(f"TP={tp:3}  FN={fn:3}  FP={fp:3}  TN={tn:3}")
    print()
    print(f"TPR (Recall) = {tpr:.2%}")
    print(f"FPR          = {fpr:.2%}")
    print(f"Precision    = {precision:.2%}")
    print(f"F1-score     = {f1:.3f}")


if __name__ == "__main__":
    main()
