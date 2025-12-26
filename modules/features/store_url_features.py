import core.url_analyser as url_analyser
from db.db import get_db,save_result
import core.url_analyser as url_analyser
from features.build_features import feature_builder


def store_url_feature():
    conn=get_db()
    curr=conn.cursor()
    for index, row in url_analyser.data.iterrows():
        features = feature_builder(row['url'])
        curr.execute("""
            INSERT INTO url_features (url, is_tracker, active_param_count, analytics_param_count,
            technical_param_count, unknown_param_count, parameter_risk_score, parameter_risk_label)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """, (
            row['url'],
            bool(features.at[0, 'is_tracker']),
            int(features.at[0, 'active_param_count']),
            int(features.at[0, 'analytics_param_count']),
            int(features.at[0, 'technical_param_count']),
            int(features.at[0, 'unknown_param_count']),
            int(features.at[0, 'parameter_risk_score']),
            str(features.at[0, 'parameter_risk_label'])
        ))  

    conn.commit()
    curr.close()
    conn.close()