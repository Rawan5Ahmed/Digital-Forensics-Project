# app.py
import os
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from analysis_engine import parse_pcap, export_report

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pcap","pcapng"}

app = Flask(__name__, static_folder="static")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    return send_from_directory("static","index.html")

@app.route("/upload",methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error":"No file part"}),400
    file = request.files["file"]
    if file.filename=="":
        return jsonify({"error":"No selected file"}),400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        path = os.path.join(app.config["UPLOAD_FOLDER"],filename)
        file.save(path)

        summary, tcp_streams, dns_domains, http_requests, http_responses, alerts = parse_pcap(path)

        return jsonify({
            "summary": summary,
            "dns_domains": dns_domains,
            "http_requests": http_requests,
            "http_responses": http_responses,
            "alerts": alerts
        })
    return jsonify({"error":"File type not allowed"}),400

@app.route("/export",methods=["POST"])
def export():
    data = request.json
    format = data.get("format","csv")
    filename = f"report.{format}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    export_report(data,path,format=format)
    return jsonify({"message":"Report saved","file":filename})

if __name__=="__main__":
    app.run(debug=True)
