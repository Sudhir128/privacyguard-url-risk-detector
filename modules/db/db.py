import psycopg2

def get_db():
    return psycopg2.connect(
        dbname="urlrisk",           
        user="urlriskuser",
        password="riskengine666",
        host="localhost",
        port=5432                  
    )

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_risk_log (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            detailed_risk_score INTEGER,
            risk_label TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
                   
        CREATE TABLE IF NOT EXISTS url_features(
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            is_tracker BOOLEAN,
            active_param_count INTEGER,
            analytics_param_count INTEGER,
            technical_param_count INTEGER,
            unknown_param_count INTEGER,
            parameter_risk_score INTEGER,
            parameter_risk_label TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
                   
        CREATE TABLE IF NOT EXISTS url_predictions (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            predicted_label TEXT NOT NULL,
            confidence FLOAT NOT NULL,
            verdict TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
    """)
    conn.commit()
    cursor.close()
    conn.close()

init_db()

def save_result(url, risk_score, detailed_risk_score, risk_label):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO url_risk_log (url, risk_score, detailed_risk_score, risk_label)
        VALUES (%s, %s, %s, %s);
    """, (url, risk_score, detailed_risk_score, risk_label))
    conn.commit()
    cursor.close()
    conn.close()

def save_prediction(url, label, confidence,verdict):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO url_predictions
        (url, predicted_label, confidence, verdict)
        VALUES (%s, %s, %s, %s);
    """, (
        url,
        label,
        confidence,
        verdict,
    ))
    conn.commit()
    cur.close()
    conn.close()
