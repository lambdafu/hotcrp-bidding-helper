# HotCRP Bidding Helper

A local, single-page web app for efficiently triaging review preference bids on large conference submissions.

All data stays in your browser. No server, no build step, no dependencies to install.

## Quick Start

1. Open `index.html` in any modern browser
2. Export your review preferences CSV from HotCRP (Search > select all > Download > Review preferences)
3. Upload the CSV (drag & drop or click)
4. Optionally import a reviewer profile (see below)
5. Browse, filter, score, and set preferences
6. Export the modified CSV and upload it back to HotCRP

## Features

### Three-Column Layout
- **Left sidebar** — Topic tree with paper counts, checkboxes for filtering (OR logic), and per-topic score weights
- **Center** — Scrollable paper list with sortable column headers (ID, Title, Score, Preference)
- **Right sidebar** — TF-IDF keyword list with checkboxes for filtering (AND logic), search, and per-keyword score weights

### Composite Scoring
Each paper gets a score based on your topic weights and keyword weights:

```
score = sum(matching topic scores) + sum(keyword score * paper TF-IDF weight * 10)
```

Sort by score to surface papers most relevant to your expertise.

### Preference Buttons
| Value | Label | Color |
|-------|-------|-------|
| 3 | Want | dark green |
| 2 | Good | green |
| 1 | OK | light green |
| 0 | None | gray |
| -1 | Not | orange |
| -100 | Conflict | red |

### Keyboard Navigation
| Key | Action |
|-----|--------|
| j / Down | Next paper |
| k / Up | Previous paper |
| Enter | Toggle abstract |
| 3 / 2 / 1 / 0 | Set preference |
| - | Not (-1) |
| c | Conflict (-100) |
| ? | Help |

### Search & Highlighting
Full-text search across titles and abstracts with 300ms debounce. Matching terms, selected keywords (with all stemmed forms), and selected topics are highlighted in the paper list.

### Persistence
Preferences, topic scores, and keyword scores are saved to `localStorage` and restored on reload.

## Reviewer Profile Builder

`build_profile.py` analyzes your own published papers (PDFs) to generate a reviewer profile with topic scores and keyword weights. This profile can be imported into the web app to pre-fill scoring preferences.

**Privacy**: The profile builder only reads your own papers and a generic topic list. It never touches confidential submission data.

### Requirements

```
pip install pymupdf
```

### Usage

```bash
# Put your papers (PDFs) in a directory
python3 build_profile.py test-data/topics.txt my-papers/

# Output: reviewer_profile.json (next to the topics file)
```

Then in the web app, click **Import Profile** and select the JSON file.

You can also **Export Profile** from the web app to save your current topic/keyword scores.

## Utility Scripts

### test-data/generate_test_data.py
Generates a synthetic CSV with 200 test papers for development and testing.

```bash
python3 test-data/generate_test_data.py
# Output: test-data/test_revprefs.csv
```

### extract_topics.py
Extracts the topic tree from a real HotCRP CSV (useful for understanding the topic structure). Output contains only topic names, no submission counts.

```bash
python3 extract_topics.py revprefs.csv
# Output: topics.txt
```

## CSV Format

The app reads and writes standard HotCRP review preference CSVs:

```
paper,title,preference,abstract,topics
1234,"Paper Title",0,"Abstract text...","Topic A; Topic B: Subtopic"
```

Only the `preference` column is modified on export; all other data is preserved verbatim.

## Technical Details

- **Vue 3** (CDN) — reactivity for filtering, scoring, and UI state
- **PapaParse** (CDN) — robust CSV parsing with multiline quoted fields
- **TF-IDF** with simple suffix stemming (handles -s, -es, -ed, -ing, -tion/-sion)
- Stop words: English common + academic boilerplate + short prefixes
- Keywords: all terms with DF >= 3 and <= 60% of corpus; top 200 shown by default, all searchable
- Custom CSS checkboxes to avoid native checkbox/Vue reactivity conflicts
