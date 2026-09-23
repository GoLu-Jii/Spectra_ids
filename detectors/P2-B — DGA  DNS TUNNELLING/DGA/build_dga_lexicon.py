"""Export the notebook's exact NLTK English word filter to a bundled file."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
import nltk
from nltk.corpus import words

HERE=Path(__file__).resolve().parent
OUT=HERE/'lexical_resources'/'english_words.txt'

def main():
    lexicon=sorted({w.lower() for w in words.words() if 4<=len(w)<=15})
    OUT.parent.mkdir(parents=True,exist_ok=True)
    payload='\n'.join(lexicon)+'\n'; OUT.write_text(payload,encoding='utf-8')
    meta={'resource':'NLTK words corpus','filter':'lowercase, unique, word length 4 through 15','entries':len(lexicon),'sha256':hashlib.sha256(OUT.read_bytes()).hexdigest(),'nltk_version':nltk.__version__,'runtime_file':OUT.name}
    (OUT.parent/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(meta,indent=2))

if __name__=='__main__':main()
