from privacyguard.core.parameter_detector import (
    detect_parameters,
    parameter_value_risk,
    risk_label,
    track_parameter,
)


def test_track_parameter_empty_query():
    features = track_parameter("https://example.com/path")
    assert features["total_param_count"] == 0
    assert features["has_active_param"] == 0


def test_track_parameter_categorizes_active_params():
    features = track_parameter("https://example.com?utm_source=fb&fbclid=abc")
    assert features["active_param_count"] == 2
    assert features["has_active_param"] == 1


def test_track_parameter_categorizes_password_param_separately():
    # PASSWORD_PARAMETERS previously existed but was never checked anywhere.
    features = track_parameter("https://example.com?password=hunter2")
    assert features["has_password_param"] == 1
    assert features["password_param_count"] == 1
    assert features["has_unknown_param"] == 0


def test_track_parameter_unknown_param():
    features = track_parameter("https://example.com?foo=bar")
    assert features["has_unknown_param"] == 1
    assert features["unknown_param_count"] == 1


def test_parameter_value_risk_password_key_is_critical_regardless_of_value():
    assert parameter_value_risk("https://example.com/login?password=abc") == 10


def test_parameter_value_risk_jwt_value_is_critical():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQqqerJmNqRO1z"
    assert parameter_value_risk(f"https://example.com/callback?token={jwt}") == 10


def test_parameter_value_risk_api_key_pattern():
    url = "https://example.com/init?key=glpat-dummytokenfortesting"
    assert parameter_value_risk(url) == 10






def test_parameter_value_risk_no_params_is_zero():
    assert parameter_value_risk("https://example.com/path") == 0


def test_parameter_value_risk_plain_param_is_baseline():
    assert parameter_value_risk("https://example.com?q=hello") == 2


def test_risk_label_thresholds():
    assert risk_label(0) == "LOW"
    assert risk_label(5) == "MEDIUM"
    assert risk_label(7) == "HIGH"
    assert risk_label(9) == "CRITICAL"


def test_detect_parameters_combines_features_and_score():
    result = detect_parameters("https://example.com?password=hunter2&utm_source=fb")
    assert result["has_password_param"] == 1
    assert result["parameter_risk_score"] == 10
    assert result["parameter_risk_label"] == "CRITICAL"
