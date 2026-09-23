"""Rebuild the causal 10-feature Exfiltration model from stateful CSVs."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.metrics import accuracy_score,roc_auc_score,f1_score
from xgboost import XGBClassifier
from exfiltration_adapter import RAW_COLUMNS,FEATURE_ORDER,HISTORY,context_features,ExfiltrationDetector

HERE=Path(__file__).resolve().parent
DATA=HERE.parents[2]
TRAIN=['stateful_features-_light_benign.pcap.csv','stateful_features-light_exe.pcap.csv','stateful_features-light_text.pcap.csv']
VAL=['stateful_features-benign_2.pcap.csv','stateful_features-light_audio.pcap.csv','stateful_features-light_video.pcap.csv']
TEST=['stateful_features-benign_1.pcap.csv','stateful_features-light_compressed.pcap.csv','stateful_features-light_image.pcap.csv']
FILES={p.name:p for p in DATA.rglob('stateful_features*.csv')}

def records(name):
    frame=pd.read_csv(FILES[name],usecols=RAW_COLUMNS)
    return frame[RAW_COLUMNS].to_dict('records')

def matrix(names):
    xs=[]; ys=[]; captures={}
    for name in names:
        rows=records(name); hist=[]; label=int('benign' not in name.lower()); captures[name]=rows
        for row in rows:
            xs.append(context_features(hist)); ys.append(label); hist.append(row)
    return pd.DataFrame(xs,columns=FEATURE_ORDER),np.asarray(ys,dtype='int8'),captures

def new_model():
    return XGBClassifier(n_estimators=73,learning_rate=.04,max_depth=5,min_child_weight=3,subsample=.9,colsample_bytree=.9,gamma=.1,reg_alpha=.1,reg_lambda=3,scale_pos_weight=3,objective='binary:logistic',eval_metric='aucpr',random_state=42,n_jobs=-1,tree_method='hist')

def main():
    missing=sorted(set(TRAIN+VAL+TEST)-FILES.keys())
    if missing: raise FileNotFoundError(f'Missing stateful capture CSVs: {missing}')
    Xtr,ytr,_=matrix(TRAIN); Xv,yv,_=matrix(VAL); Xt,yt,testcaps=matrix(TEST)
    model=new_model(); model.fit(Xtr,ytr,eval_set=[(Xv,yv)],verbose=False)
    vp=model.predict_proba(Xv)[:,1]; thresholds=np.arange(.01,1.0,.005); threshold=float(max(thresholds,key=lambda t:f1_score(yv,vp>=t,zero_division=0)))
    # Freeze artifact after selection, fitting the same configuration on train + validation captures.
    final=new_model(); final.set_params(n_estimators=max(1,int(getattr(model,'best_iteration',72))+1)); final.fit(pd.concat([Xtr,Xv],ignore_index=True),np.concatenate([ytr,yv]),verbose=False)
    prob=final.predict_proba(Xt)[:,1]; pred=(prob>=threshold).astype('int8')
    path=HERE/'dns_exfiltration_stateful_xgb_final.pkl'
    joblib.dump({'model':final,'features':FEATURE_ORDER,'threshold':threshold,'feature_count':len(FEATURE_ORDER),'history_records':HISTORY},path)
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    metadata={'model_version':'2.0.0-rebuilt','detector_version':'2.0.0','artifact':path.name,'artifact_sha256':digest(path),'feature_order':FEATURE_ORDER,'input_schema':RAW_COLUMNS,'state_semantics':{'scope':'one capture or ordered DNS stream; reset between captures','history':'previous up to 20 records; current excluded from current score','initial_context':'zeros'},'threshold':threshold,'threshold_selection':'maximum validation F1, thresholds 0.01 to 0.995 step 0.005','train_captures':TRAIN,'validation_captures':VAL,'test_captures':TEST,'test_accuracy':float(accuracy_score(yt,pred)),'test_roc_auc':float(roc_auc_score(yt,prob)),'test_rows':len(yt),'source_sha256':{n:digest(FILES[n]) for n in TRAIN+VAL+TEST},'runtime':{'xgboost':'3.4.1','pandas':'3.0.6','numpy':'2.5.3','joblib':'1.6.0'}}
    (HERE/'exfiltration_training_metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    fixtures=[]
    offset=0
    for label in (0,1):
        chosen=None; cursor=0
        for name in TEST:
            rows=testcaps[name]; source_label=int('benign' not in name.lower())
            local=prob[offset:offset+len(rows)]
            if source_label==label:
                for i,score in enumerate(local):
                    if i>=HISTORY and int(score>=threshold)==label:
                        chosen=(name,rows,i); break
            if chosen: break
            offset+=len(rows)
        if not chosen: raise RuntimeError(f'No correctly classified held-out example for label {label}')
        name,rows,i=chosen; detector=ExfiltrationDetector(threshold=threshold)
        history=rows[max(0,i-HISTORY):i]
        for row in history: detector.predict(row)
        record=rows[i]; output=detector.predict(record)
        fixtures.append({'case':'benign' if label==0 else 'suspicious','capture':name,'label':label,'expected_prediction':label,'prediction':output[0],'probability':output[1],'history_records':len(history),'history':history,'record':record,'evidence':output[2]})
        offset=0
    (HERE/'fixtures').mkdir(exist_ok=True); (HERE/'fixtures/exfiltration_stateful_inference_fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')
    print(json.dumps(metadata,indent=2))

if __name__=='__main__':main()
