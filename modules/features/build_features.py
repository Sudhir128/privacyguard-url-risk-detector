from core.track_parameter_detector import track_parameter
from core.parameter_risk_engine import parameter_risk, risk_label
import core.tracker_loader as tl
import pandas as pd
from core.url_utils import is_tracker_url

def feature_builder(url):
    param_features=track_parameter(url)
    param_risk = parameter_risk(url)
    return pd.DataFrame([{
        'is_tracker': is_tracker_url(url,tl.tracker_domains),
        'active_param_count': param_features['active_param_count'],
        'analytics_param_count': param_features['analytics_param_count'],
        'technical_param_count': param_features['technical_param_count'],
        'unknown_param_count': param_features['unknown_param_count'],
        'parameter_risk_score': param_risk,
        'parameter_risk_label': risk_label(score=param_risk)
    }])

