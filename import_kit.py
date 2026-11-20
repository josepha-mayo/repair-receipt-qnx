"""Make the reference input from the CC BY 4.0 KIT Automotive OBD-II archive."""

import argparse
import csv
from datetime import time
from decimal import Decimal
from io import TextIOWrapper
from pathlib import Path
from zipfile import ZipFile

MEMBER = "OBD-II-Dataset/2017-07-05_Seat_Leon_RT_S_Stau.csv"
# The distributed CSV double-encodes the degree symbol in this header.
SIGNALS = ("Engine RPM [RPM]", "Vehicle Speed Sensor [km/h]", "Engine Coolant Temperature [\u00c2\u00b0C]")
START_MS = 900_000
DURATION_MS = 90_000
STRIDE_MS = 1000


def milliseconds(text):
    clock = time.fromisoformat(text)
    return (clock.hour * 3600 + clock.minute * 60 + clock.second) * 1000 + clock.microsecond // 1000


def normalize(archive):
    with ZipFile(archive) as dataset, dataset.open(MEMBER) as source:
        reader = csv.DictReader(TextIOWrapper(source, encoding="utf-8-sig"))
        recording_start = None
        last_sample = -STRIDE_MS
        for row in reader:
            timestamp = milliseconds(row["Time"])
            if recording_start is None:
                recording_start = timestamp
            local_time = (timestamp - recording_start) % 86_400_000 - START_MS
            if local_time < 0 or local_time - last_sample < STRIDE_MS:
                continue
            if local_time > DURATION_MS:
                break
            if any(not row[field] for field in SIGNALS):
                continue
            values = [Decimal(row[field]) for field in SIGNALS]
            if any(not value.is_finite() or value != value.to_integral_value() for value in values):
                raise ValueError("Expected whole-number signals in the published recording.")
            yield local_time, *(int(value) for value in values)
            last_sample = local_time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    rows = list(normalize(args.archive))
    if not rows:
        raise ValueError("The reference window contains no complete samples.")
    with args.destination.open("w", encoding="ascii", newline="") as target:
        print(DURATION_MS, file=target)
        csv.writer(target, lineterminator="\n").writerows(rows)
    print(f"Wrote {len(rows)} normalized real OBD-II rows.")


if __name__ == "__main__":
    main()
