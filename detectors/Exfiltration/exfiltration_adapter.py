"""Stateful adapter for the Exfiltration context-only XGBoost artifact."""
from __future__ import annotations
import ast, re
from collections import deque
from pathlib import Path
from typing import Mapping
import joblib, numpy as np, pandas as pd

RAW_COLUMNS=['rr','A_frequency','NS_frequency','CNAME_frequency','SOA_frequency','NULL_frequency','PTR_frequency','HINFO_frequency','MX_frequency','TXT_frequency','AAAA_frequency','SRV_frequency','OPT_frequency','rr_type','rr_count','rr_name_entropy','rr_name_length','distinct_ns','distinct_ip','unique_country','unique_asn','distinct_domains','reverse_dns','a_records','unique_ttl','ttl_mean','ttl_variance']
FEATURE_ORDER=['rr_count_prev20_mean','ttl_range_prev20_mean','ttl_variance_prev20_std','ttl_mean_prev20_mean','rr_name_length_prev20_mean','PTR_frequency_prev20_mean','is_PTR_record_prev20_mean','reverse_dns_known_prev20_mean','ttl_unique_count_prev20_mean','rr_entropy_per_length_prev20_mean']
HISTORY=20

def _literal(v):
    if v is None or (isinstance(v,float) and np.isnan(v)): return None
    try: return ast.literal_eval(str(v))
    except (ValueError,SyntaxError): return None

def _count(v):
    x=_literal(v)
    return float(len(x)) if isinstance(x,(set,list,tuple,dict)) else (0.0 if x is None else 1.0)

def _base(r:Mapping[str,object])->dict[str,float]:
    missing=[k for k in RAW_COLUMNS if k not in r]
    if missing: raise ValueError('Missing Exfiltration fields: '+', '.join(missing))
    ttls=_literal(r['unique_ttl']); ttls=ttls if isinstance(ttls,(list,tuple)) else []
    ttls=[float(x) for x in ttls if str(x).replace('.','',1).isdigit()]
    types=_literal(r['rr_type']); types=set(map(str,types)) if isinstance(types,(set,list,tuple)) else set()
    entropy=float(r['rr_name_entropy']); length=float(r['rr_name_length']); ttlmean=float(r['ttl_mean']); ttlvar=float(r['ttl_variance'])
    return {'rr_count':float(r['rr_count']),'ttl_range':max(ttls)-min(ttls) if ttls else 0.0,'ttl_variance':ttlvar,'ttl_mean':ttlmean,'rr_name_length':length,'PTR_frequency':float(r['PTR_frequency']),'is_PTR_record':float('PTR' in types),'reverse_dns_known':float(str(r['reverse_dns']).lower()!='unknown'),'ttl_unique_count':float(len(set(ttls))),'rr_entropy_per_length':entropy/max(length,1.0)}

def context_features(history:list[Mapping[str,object]])->dict[str,float]:
    if not history: return dict.fromkeys(FEATURE_ORDER,0.0)
    f=pd.DataFrame([_base(r) for r in history[-HISTORY:]])
    return {'rr_count_prev20_mean':float(f.rr_count.mean()),'ttl_range_prev20_mean':float(f.ttl_range.mean()),'ttl_variance_prev20_std':float(f.ttl_variance.std(ddof=1)) if len(f)>1 else 0.0,'ttl_mean_prev20_mean':float(f.ttl_mean.mean()),'rr_name_length_prev20_mean':float(f.rr_name_length.mean()),'PTR_frequency_prev20_mean':float(f.PTR_frequency.mean()),'is_PTR_record_prev20_mean':float(f.is_PTR_record.mean()),'reverse_dns_known_prev20_mean':float(f.reverse_dns_known.mean()),'ttl_unique_count_prev20_mean':float(f.ttl_unique_count.mean()),'rr_entropy_per_length_prev20_mean':float(f.rr_entropy_per_length.mean())}

class ExfiltrationDetector:
    def __init__(self,model_path:str|Path|None=None,threshold:float|None=None):
        p=Path(model_path) if model_path else Path(__file__).with_name('dns_exfiltration_stateful_xgb_final.pkl')
        pkg=joblib.load(p); self.model=pkg['model']; self.feature_order=list(pkg['features']); self.threshold=float(pkg.get('threshold',.653) if threshold is None else threshold); self.history=deque(maxlen=HISTORY)
        if self.feature_order!=FEATURE_ORDER: raise ValueError('Exfiltration artifact schema mismatch')
    def reset(self): self.history.clear()
    def predict(self,record:Mapping[str,object]):
        missing=[name for name in RAW_COLUMNS if name not in record]
        if missing: raise ValueError('Missing Exfiltration input fields: '+', '.join(missing))
        features=context_features(list(self.history)); row=pd.DataFrame([[features[k] for k in self.feature_order]],columns=self.feature_order)
        score=float(self.model.predict_proba(row)[0,1]); pred=int(score>=self.threshold); used=len(self.history); self.history.append(dict(record))
        evidence={**features,'prediction':'Exfiltration (1)' if pred else 'Benign (0)','confidence':score,'threshold':self.threshold,'history_records_used':used,'history_capacity':HISTORY}
        return pred,score,evidence
