import os
from flask import Blueprint, render_template, request, jsonify
from werkzeug.utils import secure_filename
import config
from dashboard.csv_parser import parse_csv
from dashboard.report_builder import build_comparison_report

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/", methods=["GET"])
def dashboard_home():
    return render_template("dashboard.html")

@dashboard_bp.route("/upload", methods=["POST"])
def upload_csv():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
        
    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "File must be a .csv"}), 400
        
    try:
        rows, warnings = parse_csv(file.stream)
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        return jsonify({"error": f"Failed to parse CSV: {e}"}), 422
        
    try:
        report = build_comparison_report(rows)
    except Exception as e:
        return jsonify({"error": f"Failed to build report: {e}"}), 500
        
    report["dataset"]["csv_filename"] = file.filename
    
    return jsonify(report)
