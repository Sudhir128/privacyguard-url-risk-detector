import browser_history as bh
import pandas as pd
from core.url_utils import is_tracker_url
from core.risk_engine import assign_score, risk_level
import core.tracker_loader as tl
from core.track_parameter_detector import track_parameter
import logging

data = bh.getbrowserhistory()
urls = data['url'].tolist()

tracker_urls = [is_tracker_url(url, tl.tracker_domains) for url in urls]
data['is_tracker'] = tracker_urls

param_features=data['url'].apply(track_parameter)
param_df = pd.DataFrame(list(param_features))
data = pd.concat([data, param_df], axis=1)

data['risk_score'] = data['is_tracker'].apply(lambda x: 10 if x else 1)
logging.info(str(data[['url', 'risk_score']]))

total_risk_score = data['risk_score'].sum()
logging.info(f"Total risk score: {total_risk_score}")

max_possible_risk = len(data) * 10
privacy_risk_percent = (total_risk_score / max_possible_risk) * 100
logging.info(f"Overall Risk percentage: {privacy_risk_percent:.2f}%")

final_risk = risk_level(privacy_risk_percent)

data['detailed_risk_score'] = data['url'].apply(assign_score)
logging.info(str(data[['url', 'detailed_risk_score']]))

total_detailed_score = data['detailed_risk_score'].sum()
logging.info(f"Total detailed risk score: {total_detailed_score}")

detailed_privacy_risk_percent = (total_detailed_score / (len(data) * 10)) * 100
logging.info(f"Detailed Overall Risk percentage: {detailed_privacy_risk_percent:.2f}%")

detailed_final_risk = risk_level(detailed_privacy_risk_percent)

