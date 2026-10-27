# Getting real-malware features in Google Colab (the path to 10/10)

Goal: turn a raw PDF corpus into a small `features.csv` (a few MB) that Claude
trains + ablates. Colab does the heavy download + extraction on fast infra and a
throwaway VM, so your laptop never touches the malware and you never upload GBs.

Open https://colab.research.google.com → New notebook, then run these cells.

### Cell 1 — PDFSentry code + dependencies
```python
from google.colab import files
print("Upload PDFSentry.zip (the one Claude sent you):")
files.upload()                       # pick PDFSentry.zip
!unzip -o -q PDFSentry.zip
%cd PDFSentry
!pip install -q pikepdf lightgbm pandas scikit-learn
!pip install -q "git+https://github.com/FutureComputing4AI/EMBER2024.git"
import os; os.environ["PYTHONPATH"]="."
```

### Cell 2 — get the EMBER PDF model (for the ember_score column)
```python
from huggingface_hub import hf_hub_download
import shutil
os.makedirs("data/ember", exist_ok=True)
p = hf_hub_download("joyce8/EMBER2024-benchmark-models", "EMBER2024_PDF.model")
shutil.copy(p, "data/ember/EMBER2024_PDF.model")
```

### Cell 3 — get the raw PDFs
Fill the UNB form once (https://www.unb.ca/cic/datasets/pdfmal-2022.html) to get a
download link, then:
```python
!wget -q "PASTE_THE_DOWNLOAD_LINK_HERE" -O cic.zip
!unzip -o -q -P infected cic.zip -d cic     # password is often "infected"; drop -P if not needed
!find cic -maxdepth 3 -type d                # find the Malicious / Benign folders
```
(If UNB is awkward, any labelled raw PDF set works — just point the next cell at a
malicious folder and a benign folder.)

### Cell 4 — extract the feature table
```python
!python scripts/extract_corpus_features.py \
    --malicious cic/.../Malicious \
    --benign    cic/.../Benign \
    --ember-model data/ember/EMBER2024_PDF.model \
    --out features.csv
from google.colab import files
files.download("features.csv")       # a few MB — upload THIS to Claude
```

Upload `features.csv` to the chat. Claude runs `scripts/train_augmented_real.py`
and reports: EMBER-alone vs reachability-alone vs fusion, with 5-fold CV ROC/PR,
95% bootstrap CIs, and a paired significance test — the real-malware result.

Static only: `extract_corpus_features.py` parses PDFs, never executes them.
