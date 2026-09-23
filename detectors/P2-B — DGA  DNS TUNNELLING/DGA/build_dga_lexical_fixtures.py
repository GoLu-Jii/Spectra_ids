"""Generate feature-only DGA examples; no classifier prediction is implied."""
from __future__ import annotations
import json
from pathlib import Path
from dga_detector import DGADetector

HERE=Path(__file__).resolve().parent

def main():
    detector=DGADetector()
    fixtures=[]
    for label,case,domain in ((0,'benign','google.com'),(1,'suspicious','xj9q2m4v7k.example.xyz')):
        features=detector.transform_base([domain]).iloc[0].to_dict()
        fixtures.append({'case':case,'label':label,'domain':domain,'base_features':features,'classifier_prediction_available':False,'reason':'TF-IDF vectorizer is intentionally not created; classifier artifact is corrupt'})
    out=HERE/'fixtures'; out.mkdir(exist_ok=True)
    (out/'dga_lexical_feature_examples.json').write_text(json.dumps(fixtures,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(fixtures,indent=2))

if __name__=='__main__': main()
