from flask import Flask, request, jsonify, render_template_string
from graph_agent import ask_agent

app = Flask(__name__)

HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Mini EDR LangGraph Investigation Agent</title>
</head>
<body style="font-family: Arial; margin: 40px;">
    <h2>Mini EDR LangGraph Investigation Agent</h2>
    <p>Ví dụ:</p>
    <ul>
        <li>Viết báo cáo cho các event alert từ 10:10 đến 10:20</li>
        <li>Viết báo cáo cho process powershell.exe từ 10:35 đến 10:37</li>
        <li>Tại sao PID 9652 bị ALERT?</li>
        <li>Giải thích event có EncodedCommand</li>
        <li>Giải thích event từ file_sensor</li>
    </ul>
    <textarea id="q" style="width:100%; height:100px;"></textarea><br>
    <button onclick="ask()">Ask</button>
    <pre id="a" style="white-space:pre-wrap; background:#111; color:white; padding:16px;"></pre>

<script>
async function ask() {
    document.getElementById("a").textContent = "Đang phân tích...";
    const q = document.getElementById("q").value;
    const res = await fetch("/ask", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({question:q})
    });
    const data = await res.json();
    document.getElementById("a").textContent = data.answer;
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/ask", methods=["POST"])
def ask():
    data = request.get_json(force=True)
    question = data.get("question", "")
    return jsonify({"answer": ask_agent(question)})

@app.route("/health")
def health():
    return jsonify({"status": "running"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9100)