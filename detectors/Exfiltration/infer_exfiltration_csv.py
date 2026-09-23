"""Score an upstream-generated Exfiltration stateful feature CSV as JSONL."""
from __future__ import annotations
import argparse,json
from pathlib import Path
import pandas as pd
from exfiltration_adapter import ExfiltrationDetector,RAW_COLUMNS

def _json_default(value):
    return value.item() if hasattr(value,'item') else str(value)

def main():
    parser=argparse.ArgumentParser(description='Run stateful inference on one normalized capture CSV')
    parser.add_argument('input_csv',type=Path)
    parser.add_argument('output_jsonl',type=Path)
    parser.add_argument('--model',type=Path,default=Path(__file__).with_name('dns_exfiltration_stateful_xgb_final.pkl'))
    parser.add_argument('--threshold',type=float,default=None)
    parser.add_argument('--chunk-size',type=int,default=5000)
    args=parser.parse_args()
    detector=ExfiltrationDetector(args.model,args.threshold); detector.reset()
    row_number=0
    with args.output_jsonl.open('w',encoding='utf-8') as out:
        for frame in pd.read_csv(args.input_csv,chunksize=args.chunk_size):
            missing=[name for name in RAW_COLUMNS if name not in frame.columns]
            if missing: raise ValueError('Missing Exfiltration columns: '+', '.join(missing))
            for record in frame[RAW_COLUMNS].to_dict(orient='records'):
                pred,score,evidence=detector.predict(record)
                out.write(json.dumps({'row':row_number,'prediction':pred,'probability':score,'evidence':evidence},default=_json_default)+'\n')
                row_number+=1
    print(json.dumps({'input':str(args.input_csv),'output':str(args.output_jsonl),'rows_scored':row_number,'state_reset':'at file start','history_capacity':20}))

if __name__=='__main__':main()
