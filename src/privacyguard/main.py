import argparse
import json
import sys

from privacyguard.config import get_settings
from privacyguard.logging_config import setup_logging


def _cmd_scan(args) -> int:
    from privacyguard.db.connection import init_schema
    from privacyguard.db.models import save_scan
    from privacyguard.core.url_utils import extract_domain
    from privacyguard.ml.predict import predict_url

    init_schema()
    result = predict_url(args.url)
    save_scan(
        url=args.url,
        score=result["risk_score"],
        risk_label=result["risk_label"],
        domain=extract_domain(args.url),
        is_tracker=result["is_tracker"],
        is_phishing=result["is_phishing"],
        matched_brand=result["matched_brand"],
        predicted_label=result["predicted_label"],
        confidence=result["confidence"],
        verdict=result["verdict"],
        explanation=result["explanation"],
    )

    print(f"URL:        {result['url']}")
    print(f"Risk:       {result['risk_label']} ({result['risk_score']}/10)")
    print(f"Predicted:  {result['predicted_label']} (confidence {result['confidence']*100:.1f}%)")
    print(f"Verdict:    {result['verdict']}")
    print(f"Tracker:    {'yes' if result['is_tracker'] else 'no'}")
    print(f"Phishing:   {'yes' if result['is_phishing'] else 'no'}" + (f" (mimics {result['matched_brand']})" if result["matched_brand"] else ""))
    if result["explanation"]:
        print("Reasons:")
        for reason in result["explanation"]:
            print(f"  - {reason}")
    return 0


def _cmd_train(args) -> int:
    from privacyguard.ml.train import train_model

    metadata = train_model()
    print(json.dumps(metadata, indent=2))
    return 0


def _cmd_history(args) -> int:
    from privacyguard.db.connection import init_schema
    from privacyguard.db.models import create_session, save_scan
    from privacyguard.core.url_utils import extract_domain
    from privacyguard.browser.history import fetch_history
    from privacyguard.ml.predict import predict_url

    init_schema()
    df = fetch_history(browser=args.browser)
    urls = df["url"].tolist() if not df.empty else []

    if not urls:
        print("No browser history found (or the browser could not be read).")
        return 1

    session_id = create_session(source=f"browser:{args.browser or 'auto'}", total_urls=len(urls))
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for url in urls:
        result = predict_url(url)
        save_scan(
            url=url,
            score=result["risk_score"],
            risk_label=result["risk_label"],
            domain=extract_domain(url),
            is_tracker=result["is_tracker"],
            is_phishing=result["is_phishing"],
            matched_brand=result["matched_brand"],
            predicted_label=result["predicted_label"],
            confidence=result["confidence"],
            verdict=result["verdict"],
            explanation=result["explanation"],
            session_id=session_id,
        )
        counts[result["risk_label"]] += 1

    print(f"Scanned {len(urls)} URLs from browser history.")
    for label, count in counts.items():
        print(f"  {label}: {count}")
    return 0


def _cmd_serve(args) -> int:
    import uvicorn

    settings = get_settings()
    uvicorn.run("privacyguard.api.app:app", host=settings.api_host, port=settings.api_port, reload=False)
    return 0


def cli() -> int:
    parser = argparse.ArgumentParser(prog="privacyguard", description="Personal cyber-safety toolkit.")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a single URL")
    scan_parser.add_argument("url")

    subparsers.add_parser("train", help="Retrain the ML risk model")

    history_parser = subparsers.add_parser("history", help="Scan local browser history")
    history_parser.add_argument("--browser", default=None, choices=["chrome", "edge", "firefox", "brave"])

    subparsers.add_parser("serve", help="Launch the dashboard + API (same as no command)")

    args = parser.parse_args()
    setup_logging()

    handlers = {
        "scan": _cmd_scan,
        "train": _cmd_train,
        "history": _cmd_history,
        "serve": _cmd_serve,
        None: _cmd_serve,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(cli())
