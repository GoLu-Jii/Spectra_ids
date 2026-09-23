"""Evaluate the saved C2 model against the provided 50 file; never fits a model."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
import joblib
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score
from train_c2_model import prepare_dataset, FEATURE_COLUMNS

HERE=Path(__file__).resolve().parent
WORKSPACE=HERE.parents[2]

def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description='Score the existing C2 model only; this command does not train')
    parser.add_argument('--capture',type=Path,default=WORKSPACE/'botnet_50 .2format')
    parser.add_argument('--model',type=Path,default=HERE/'botnet_c2_detector.pkl')
    parser.add_argument('--threshold',type=float,default=.20)
    parser.add_argument('--output',type=Path,default=HERE/'c2_existing_model_validation_report.json')
    args=parser.parse_args()
    if not args.model.exists():
        compressed=args.model.with_suffix(args.model.suffix+'.gz')
        if compressed.exists():
            import gzip
            with gzip.open(compressed,'rb') as f: model=joblib.load(f)
        else: raise FileNotFoundError(args.model)
    else: model=joblib.load(args.model)
    X,y=prepare_dataset(args.capture)
    probability=model.predict_proba(X[FEATURE_COLUMNS])[:,1]
    report={'capture':str(args.capture),'capture_sha256':sha256(args.capture),'model':str(args.model),'model_parameters':model.get_params(),'window_count':int(len(y)),'threshold':args.threshold,'scores':{},'top_features':sorted(zip(FEATURE_COLUMNS,map(float,model.feature_importances_)),key=lambda x:x[1],reverse=True)}
    for threshold in sorted({.01,.05,.10,args.threshold,.30,.50}):
        pred=probability>=threshold; tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
        report['scores'][str(threshold)]={'accuracy':float(accuracy_score(y,pred)),'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp),'false_positive_rate':float(fp/(fp+tn)) if fp+tn else 0.0,'malicious_recall':float(tp/(tp+fn)) if tp+fn else 0.0}
    report['roc_auc']=float(roc_auc_score(y,probability)) if len(set(y))==2 else None
    false_negatives=[int(i) for i in range(len(y)) if int(y[i])==1 and probability[i]<args.threshold]
    report['false_negative_indices_first20']=false_negatives[:20]
    report['note']='Inference-only validation; no fitting or threshold selection is performed.'
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('capture','window_count','threshold','scores','roc_auc','top_features')},indent=2))

if __name__=='__main__': main()
