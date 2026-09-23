"""Rebuild the DNS tunnelling classifier from the checked-in workspace CSVs."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score
from xgboost import XGBClassifier
from dns_tunnelling_detector import FEATURE_ORDER, DNSTunnellingDetector

HERE = Path(__file__).resolve().parent
DATA = HERE.parents[3]

def main() -> None:
    benign, malicious = DATA/'l2-benign.csv', DATA/'l2-malicious.csv'
    if not benign.exists() or not malicious.exists():
        raise FileNotFoundError('Expected l2-benign.csv and l2-malicious.csv in workspace root')
    frames=[]
    for path,label in ((benign,0),(malicious,1)):
        frame=pd.read_csv(path,usecols=lambda c:c in FEATURE_ORDER)
        if list(frame.columns)!=FEATURE_ORDER:
            frame=frame.reindex(columns=FEATURE_ORDER)
        frame['target']=label
        frames.append(frame)
    data=pd.concat(frames,ignore_index=True)
    X=data[FEATURE_ORDER].apply(pd.to_numeric,errors='coerce').fillna(0)
    y=data.target
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    model=XGBClassifier(n_estimators=200,max_depth=6,learning_rate=.1,tree_method='hist',random_state=42,n_jobs=-1,eval_metric='logloss')
    model.fit(Xtr,ytr)
    probs=model.predict_proba(Xte)[:,1]
    artifact=HERE/'dns_tunnelling_xgb_model.pkl'
    joblib.dump(model,artifact)
    meta={'model':'XGBClassifier','model_version':'2.0.0-rebuilt','detector_version':'2.0.0','feature_order':FEATURE_ORDER,'threshold':.5,'training_files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (benign,malicious)},'training_rows':len(Xtr),'holdout_rows':len(Xte),'holdout_accuracy':float(accuracy_score(yte,probs>=.5)),'holdout_roc_auc':float(roc_auc_score(yte,probs)),'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'runtime':{'python':'3.10+','xgboost':'3.4.1','pandas':'3.0.6','joblib':'1.6.0'}}
    (HERE/'dns_tunnelling_training_metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
    detector=DNSTunnellingDetector()
    fixtures=[]
    for label in (0,1):
        idx=int(next(i for i,value in enumerate(yte.to_numpy()) if int(value)==label))
        row=Xte.iloc[idx].to_dict(); pred,score,evidence=detector.predict(row)
        fixtures.append({'case':'benign' if label==0 else 'suspicious','label':label,'expected_prediction':label,'prediction':pred,'probability':score,'features':row,'evidence':evidence})
    (HERE/'fixtures').mkdir(exist_ok=True)
    (HERE/'fixtures/dns_tunnelling_inference_fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')
    print(json.dumps(meta,indent=2))

if __name__=='__main__': main()
