#!/usr/bin/env python3
"""Extract all unique topics from a HotCRP review preferences CSV file.
Run: python3 extract_topics.py revprefs.csv
Output: topics.txt (one topic per line, sorted)
"""
import csv, sys, os
from collections import Counter

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_topics.py <revprefs.csv>")
        sys.exit(1)

    fname = sys.argv[1]
    topic_counts = Counter()

    with open(fname, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        # Find the topics column index
        topics_idx = None
        for i, col in enumerate(header):
            if col.strip().lower() == 'topics':
                topics_idx = i
                break
        if topics_idx is None:
            print("ERROR: No 'topics' column found. Header:", header)
            sys.exit(1)

        for row in reader:
            if len(row) <= topics_idx:
                continue
            topics_str = row[topics_idx].strip()
            if not topics_str:
                continue
            for t in topics_str.split(';'):
                t = t.strip()
                if t:
                    topic_counts[t] += 1

    # Build tree structure (no counts — those are confidential)
    parents = {}
    for t in topic_counts:
        if ':' in t:
            parent, child = t.split(':', 1)
            parents.setdefault(parent.strip(), []).append(child.strip())
        else:
            parents.setdefault(t, [])

    outfile = os.path.join(os.path.dirname(fname) or '.', 'topics.txt')
    with open(outfile, 'w') as f:
        for parent in sorted(parents):
            f.write(f"{parent}\n")
            for child in sorted(parents[parent]):
                f.write(f"  {child}\n")

    print(f"Extracted {len(topic_counts)} unique topics.")
    print(f"Written to {outfile}")

if __name__ == '__main__':
    main()
