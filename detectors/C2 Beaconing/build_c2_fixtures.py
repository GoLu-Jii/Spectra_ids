"""Build real labeled inference examples from the separate capture-52 holdout."""
from __future__ import annotations
import json
from pathlib import Path
import pandas as pd
from c2_beaconing_detector import C2BeaconingDetector

HERE=Path(__file__).resolve().parent

def main():
    detector=C2BeaconingDetector()
    df=pd.read_csv(HERE/'52.binetflow',usecols=['StartTime','Proto','SrcAddr','DstAddr','TotPkts','TotBytes','Label'])
    df['timestamp_unix']=pd.to_datetime(df.StartTime,errors='coerce').astype('int64')/1e9
    df['target']=df.Label.astype(str).str.lower().str.contains('botnet')
    examples=[]
    for label,name in ((0,'benign'),(1,'suspicious_botnet')):
        subset=df[df.target==bool(label)]
        candidates=[]
        for _,group in subset.groupby(['SrcAddr','DstAddr'],sort=False):
            group=group.sort_values('timestamp_unix')
            if len(group)>=2 and group.timestamp_unix.iloc[1]-group.timestamp_unix.iloc[0]<=300:
                candidates.append(group.iloc[:2])
        if not candidates: raise RuntimeError(f'No label {label} flow pair in capture 52')
        scored=[]
        for selected in candidates:
            flows=[{'start_time_unix':float(r.timestamp_unix),'bytes':float(r.TotBytes),'pkts':float(r.TotPkts),'proto':str(r.Proto),'flow_dir_reverse':False} for r in selected.itertuples()]
            feats=detector.extract_features(flows); _,score,_=detector.predict_features(feats); scored.append((score,flows,feats))
        score,flows,features=(max(scored,key=lambda x:x[0]) if label else min(scored,key=lambda x:x[0]))
        pred,score,evidence=detector.predict_features(features)
        examples.append({'case':name,'label':label,'expected_prediction':label,'prediction':pred,'probability':score,'flows':flows,'features':features,'evidence':evidence,'source':'52.binetflow capture holdout; not used for fitting'})
    out=HERE/'fixtures'; out.mkdir(exist_ok=True)
    (out/'c2_capture52_inference_fixtures.json').write_text(json.dumps(examples,indent=2)+'\n')
    print(json.dumps([{'case':e['case'],'label':e['label'],'prediction':e['prediction'],'probability':e['probability']} for e in examples],indent=2))

if __name__=='__main__': main()
