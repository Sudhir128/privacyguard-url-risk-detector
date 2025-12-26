import pandas as pd
import os,json
import logging

base_path=r"C:\Users\sudhi\Desktop\NEWONE\trackers\tracker-radar-118c975fb1800821bd55de5955ca71c2394db971\tracker-radar-118c975fb1800821bd55de5955ca71c2394db971\domains"

def load_tracker_domains(base_path):
    tracker_set = set()
    for root,dirs,files in os.walk(base_path,topdown=True):
        for file in files:
            if file.endswith('.json'):
                file_path=os.path.join(root,file)
                with open(file_path,'r',encoding='utf-8') as f:
                    datas=json.load(f)
                    domain=datas.get("domain")
                    if domain:
                        tracker_set.add(domain.lower()) 

    return tracker_set

tracker_domains=load_tracker_domains(base_path)
logging.info(f"Total tracker domains loaded: {len(tracker_domains)}")

if __name__ == "__main__":
    load_tracker_domains(base_path)