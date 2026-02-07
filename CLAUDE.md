# CLAUDE.md

## Project Overview
Single-page bidding helper for HotCRP review preferences. The entire web app is in `index.html` (Vue 3 + PapaParse via CDN, no build step). A companion Python script `build_profile.py` generates reviewer profiles from PDFs.

## Architecture

### index.html
- Single file: HTML + CSS + Vue 3 Composition API
- Three-column CSS Grid layout: topic sidebar (280px) | paper list (flex) | keyword sidebar (230px)
- All state is reactive via Vue refs/reactive; persistence via localStorage

### Key data flow
1. CSV upload → PapaParse → `papers[]` array with parsed topics and TF-IDF vectors
2. Topic tree and keyword list are computed from the corpus on load
3. Composite score = Σ(topic scores) + Σ(keyword score × TF-IDF × 10)
4. Filters: topics (OR), keywords (AND), search (substring), preference dropdown
5. Export writes back the same CSV with only the preference column changed

### Stemmer
Both `index.html` and `build_profile.py` use the same simple suffix stemmer (plurals, -ed, -ing, -tion/-sion, -ment, -ness, -ful, -less, -able/-ible, -ize/-ise, -ity). They must stay in sync.

### Custom checkboxes
Native `<input type="checkbox">` caused glitchy behavior with Vue's reactive Sets (double-toggle flicker). Replaced with CSS-styled `<span class="cb">` elements driven purely by Vue's `:class` binding.

### Keyword sidebar
- All keywords with DF >= 3 and <= 60% of corpus are kept
- Top 200 shown by default; search box filters through all
- Selected keywords appear as chips above the search bar (always-visible, min-height reserved to avoid layout shift)

## build_profile.py
- Reads PDFs via PyMuPDF (`pip install pymupdf`), tokenizes + stems, computes TF-IDF
- Scores topics using keyword overlap between PDF corpus and enriched topic descriptions (in `TOPIC_DESCRIPTIONS` dict)
- Outputs JSON with `topicScores`, `keywordScores`, `keywordDisplay`
- **Privacy**: only processes the reviewer's own papers, never submission data

## File Structure
```
index.html                  # The entire web application
build_profile.py            # Profile builder from own PDFs
extract_topics.py           # Extracts topic tree from real HotCRP CSV
test-data/
  topics.txt                # Example topic tree (names only, no counts)
  generate_test_data.py      # Generates 200-paper test CSV
  test_revprefs.csv          # Generated test data
  profile-marcus.json        # Example reviewer profile
  papers-marcus/             # Example PDFs for profile building
```

## Common Tasks

### Testing changes to index.html
Open in browser, upload `test-data/test_revprefs.csv`, verify features. For the real dataset, use the actual CSV from HotCRP (not included for confidentiality).

### Rebuilding the reviewer profile
```bash
python3 build_profile.py test-data/topics.txt test-data/papers-marcus/
```

### Regenerating test data
```bash
python3 test-data/generate_test_data.py
```

## Gotchas
- The stemmer in `index.html` (JS) and `build_profile.py` (Python) must produce identical stems for profile import to work. If you change one, change the other.
- Keyword filtering uses AND (intersection) — selecting more keywords narrows results. Topic filtering uses OR (union) — selecting more topics widens results.
- `localStorage` keys are not namespaced per CSV file. Loading a new CSV clears all filter state but preserves persisted scores until overwritten.
- PapaParse and Vue are loaded via CDN. The app requires internet on first load (browser cache thereafter).
- The topics file intentionally contains no submission counts — those are confidential.
