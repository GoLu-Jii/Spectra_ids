# DGA detector handover

## Files

- Detector wrapper: `dga_detector.py`
- Existing model path: `DGA_XGBoost.pkl`
- Training source: `DGA_detector.ipynb`

The checked classifier file is 6,699,287 bytes, but XGBoost deserialization fails with `input stream corrupted`. Its presence does not make it a usable production model.

## Inference contract

Input is one normalized domain string at a time. The notebook extracts these features in this order:

`len_full`, `len_sld`, `entropy`, `tld_len`, `high_risk_tld`, `cv_ratio`, `digit_ratio`, `dict_match_ratio`, followed by 15 fitted character bigram TF-IDF columns named `ngram_<bigram>`.

The model was trained with `TfidfVectorizer(analyzer="char", ngram_range=(2, 2), max_features=15, lowercase=True)` fitted on training SLD values. That fitted vectorizer remains absent and has not been recreated. The NLTK lexical resource is now bundled at `lexical_resources/english_words.txt` using the notebook's lowercase, unique, 4–15 character filter; its hash and count are in `lexical_resources/metadata.json`. `build_dga_lexicon.py` regenerates it when the NLTK words corpus is installed.

No rolling calculation, grouping, event window, scaling, or column imputation was implemented. Domain normalization is lowercase and whitespace stripping; the SLD is the text before the first dot.

## Prediction and evidence

`0` means benign and `1` means DGA for the trained-model path, which remains unavailable because its classifier and fitted vectorizer are missing or unusable. `predict_lexical_fallback(domain)` is a separate rule-only path; it returns an uncalibrated risk score, matched signals, and base-feature evidence. It does not present that score as model confidence. The fixtures cover benign and suspicious inputs for this fallback.

The trained-model wrapper exposes domain, prediction, threshold, and confidence. The fallback identifies `detector_mode: lexical_heuristic_fallback` and sets `calibrated_probability` to null.

## Handover status

The lexical fallback can support basic ingestion triage but is not a trained DGA model and has no accuracy validation. The trained-model path remains blocked until the classifier artifact is repaired or recovered and the exact fitted TF-IDF vectorizer is supplied. TF-IDF work was explicitly skipped.
