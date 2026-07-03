"""Flask app: serves the dig++ frontend and a JSON DNS lookup/trace API."""

import logging
import os

from flask import Flask, jsonify, request

import dnstools

app = Flask(__name__, static_folder="static", static_url_path="")
logging.basicConfig(level=logging.INFO)


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/dig", methods=["POST"])
def api_dig():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "Request body must be JSON.", "code": "invalid_input"}), 400

    try:
        rdtype = dnstools.validate_rdtype(body.get("type"))
        domain = dnstools.validate_domain(body.get("domain"), rdtype)
        server = dnstools.validate_server(body.get("server"))
    except dnstools.InvalidInputError as exc:
        return jsonify({"error": str(exc), "code": "invalid_input"}), 400

    trace_mode = bool(body.get("trace"))
    short_mode = bool(body.get("short"))

    try:
        if trace_mode:
            result = dnstools.trace(domain, rdtype)
        else:
            result = dnstools.lookup(domain, rdtype, server=server, short=short_mode)
    except dnstools.DigError as exc:
        status = 504 if exc.code == "timeout" else 502
        return jsonify({"error": str(exc), "code": exc.code}), status
    except Exception:
        app.logger.exception("Unexpected error handling /api/dig")
        return jsonify({"error": "Internal server error.", "code": "internal_error"}), 500

    return jsonify(result)


def _domain_from_body():
    """Parse and validate {"domain": ...} from the request body.
    Returns (domain, None) on success or (None, error_response) on failure.
    """
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return None, (jsonify({"error": "Request body must be JSON.", "code": "invalid_input"}), 400)

    try:
        domain = dnstools.validate_domain(body.get("domain"))
    except dnstools.InvalidInputError as exc:
        return None, (jsonify({"error": str(exc), "code": "invalid_input"}), 400)

    return domain, None


def _check_route(name, check_fn):
    domain, error = _domain_from_body()
    if error:
        return error
    try:
        result = check_fn(domain)
    except Exception:
        app.logger.exception("Unexpected error handling /api/%s", name)
        return jsonify({"error": "Internal server error.", "code": "internal_error"}), 500
    return jsonify(result)


@app.route("/api/registrar", methods=["POST"])
def api_registrar():
    return _check_route("registrar", dnstools.check_registrar)


@app.route("/api/spf", methods=["POST"])
def api_spf():
    return _check_route("spf", dnstools.check_spf)


@app.route("/api/dmarc", methods=["POST"])
def api_dmarc():
    return _check_route("dmarc", dnstools.check_dmarc)


@app.route("/api/dkim", methods=["POST"])
def api_dkim():
    return _check_route("dkim", dnstools.check_dkim)


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
