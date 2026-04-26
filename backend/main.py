from fastapi import FastAPI, Form
from fastapi.responses import PlainTextResponse, HTMLResponse, RedirectResponse
from html import escape
import sqlite3

app = FastAPI()

# ===== DATABASE =====
conn = sqlite3.connect("project.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc TEXT,
    type TEXT,
    threat TEXT,
    confidence TEXT,
    score INTEGER,
    status TEXT,
    explanation TEXT,
    freq INTEGER DEFAULT 1
)
""")
conn.commit()

# ===== AI LOGIC =====
def analyze_ioc(ioc):
    ioc = ioc.lower()

    # Known malicious keywords
    if any(x in ioc for x in ["mal", "hack", "evil", "bad"]):
        return ("Domain", "Malware", "High", 90, "Known malicious pattern")

    # URL check
    if ioc.startswith("http"):
        if "login" in ioc or "secure" in ioc:
            return ("URL", "Phishing", "High", 85, "Possible phishing page")
        return ("URL", "Malware", "Medium", 70, "Suspicious URL behavior")

    # Domain check
    if "." in ioc and not all(p.isdigit() for p in ioc.split(".")):
        return ("Domain", "Phishing", "Medium", 60, "Suspicious domain")

    # IP check — fixed: checks all parts are digits and exactly 4 octets
    parts = ioc.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        if ioc.startswith("192.168.") or ioc.startswith("10."):
            return ("IP", "Low", "Low", 20, "Private IP address")
        return ("IP", "Malware", "High", 75, "Public suspicious IP")

    return ("Unknown", "Low", "Low", 10, "Low confidence IOC")

# ===== INSERT / UPDATE (FREQ) =====
def insert_or_update(ioc):
    t = analyze_ioc(ioc)

    cursor.execute("SELECT freq FROM threats WHERE ioc=?", (ioc,))
    row = cursor.fetchone()

    if row:
        cursor.execute("UPDATE threats SET freq=freq+1 WHERE ioc=?", (ioc,))
    else:
        cursor.execute(
            "INSERT INTO threats VALUES(NULL,?,?,?,?,?,?,?,?)",
            (ioc, *t, "Open", 1)
        )

    conn.commit()

# ================= LOGIN =================
@app.get("/", response_class=HTMLResponse)
def login():
    return """<html>
    <style>
    body{margin:0;height:100vh;display:flex;justify-content:center;align-items:center;
    background:url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b') center/cover;font-family:sans-serif;}
    .box{background:rgba(0,0,0,0.7);padding:40px;border-radius:15px;width:350px;text-align:center;}
    h2{color:#00d4ff;}
    input{width:100%;padding:12px;margin:10px 0;border-radius:8px;border:none;}
    button{width:100%;padding:12px;background:#00d4ff;border:none;border-radius:8px;}
    </style>
    <body>
    <div class="box">
    <h2>🔐 Threat Intelligence Login</h2>
    <form method="post" action="/login">
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
    </form>
    </div>
    </body></html>"""

@app.post("/login")
def login_post(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "admin123":
        return RedirectResponse("/dashboard", 302)
    return HTMLResponse("<h3 style='color:red;text-align:center'>Invalid Login</h3>")

# ================= DASHBOARD =================
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    cursor.execute("SELECT * FROM threats")
    data = cursor.fetchall()

    if not data:
        return RedirectResponse("/load")

    total = len(data)
    low    = len([d for d in data if d[5] < 40])
    medium = len([d for d in data if 40 <= d[5] < 70])
    high   = len([d for d in data if d[5] >= 70])

    cursor.execute("SELECT ioc,COUNT(*) FROM threats GROUP BY ioc ORDER BY COUNT(*) DESC LIMIT 1")
    top = cursor.fetchone()
    top_ioc = escape(top[0]) if top else "None"

    rows = ""
    for d in data:
        risk = "LOW" if d[5] < 40 else "MEDIUM" if d[5] < 70 else "HIGH"
        rows += f"""
        <tr>
        <td>{escape(d[1])}</td><td>{escape(d[2])}</td><td>{escape(d[3])}</td>
        <td>{escape(d[4])}</td><td>{d[5]}</td>
        <td class="{risk.lower()}">{risk}</td>
        <td>{escape(d[6])}</td>
        <td>{escape(d[7])}</td>
        <td>{d[8]}</td>
        </tr>
        """

    search_form = """
        <form action="/search" style="text-align:center;margin:10px;">
        <input name="q" placeholder="Search IOC" style="padding:8px;border-radius:6px;border:none;margin-right:5px;">
        <select name="risk" style="padding:8px;border-radius:6px;border:none;margin-right:5px;">
        <option value="">All</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        </select>
        <button style="padding:8px 16px;background:#00d4ff;border:none;border-radius:6px;">Search</button>
        </form>
    """

    return f"""<html>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
    body{{margin:0;background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);color:white;font-family:sans-serif;}}
    .nav{{text-align:center;padding:15px;background:black;}}
    .nav a{{color:#00d4ff;margin:15px;text-decoration:none;font-weight:bold;}}
    .cards{{display:flex;justify-content:center;gap:30px;margin:20px;}}
    .card{{background:rgba(255,255,255,0.1);padding:25px;border-radius:12px;width:200px;text-align:center;}}
    .main{{display:flex;justify-content:center;gap:40px;align-items:center;}}
    .chart-box{{width:220px;height:220px;background:rgba(0,0,0,0.5);padding:15px;border-radius:12px;}}
    table{{width:60%;border-collapse:collapse;}}
    th{{background:#00d4ff;color:black;padding:10px;}}
    td{{padding:10px;text-align:center;border-bottom:1px solid gray;}}
    .high{{color:red}} .medium{{color:orange}} .low{{color:lightgreen}}
    </style>
    <body>
    <div class="nav">
    <a href="/dashboard">Dashboard</a>
    <a href="/add">Add IOC</a>
    <a href="/feed">Feed</a>
    <a href="/alerts">Alerts</a>
    <a href="/report">Report</a>
    <a href="/load">Reload</a>
    </div>

    <h1 style="text-align:center;">🚀 Threat Intelligence Dashboard</h1>

    <div class="cards">
    <div class="card">Total<br><h2>{total}</h2></div>
    <div class="card">High Risk<br><h2>{high}</h2></div>
    <div class="card">Top IOC<br><h2>{top_ioc}</h2></div>
    </div>

    {search_form}

    <div class="main">
        <div class="chart-box">
            <canvas id="chart"></canvas>
        </div>
        <table>
        <tr>
        <th>IOC</th><th>Type</th><th>Threat</th><th>Confidence</th>
        <th>Score</th><th>Risk</th><th>Status</th><th>AI Reason</th><th>Freq</th>
        </tr>
        {rows}
        </table>
    </div>

    <script>
    new Chart(document.getElementById("chart"), {{
        type: "doughnut",
        data: {{
            labels: ["Low","Medium","High"],
            datasets: [{{
                data: [{low},{medium},{high}],
                backgroundColor:["#36a2eb","#ff6384","#ff9f40"]
            }}]
        }},
        options: {{
            responsive:true,
            maintainAspectRatio:false,
            cutout:"60%"
        }}
    }});
    </script>
    </body></html>"""

# ================= ADD =================
@app.get("/add", response_class=HTMLResponse)
def add_page():
    return """<html>
    <style>
    body{margin:0;height:100vh;display:flex;justify-content:center;align-items:center;
    background:url('https://images.unsplash.com/photo-1518770660439-4636190af475') center/cover;}
    .box{background:rgba(0,0,0,0.7);padding:40px;border-radius:15px;width:400px;text-align:center;color:white;}
    input{width:100%;padding:12px;margin:10px 0;border-radius:8px;border:none;}
    button{width:100%;padding:12px;background:#00d4ff;border:none;border-radius:8px;}
    </style>
    <body>
    <div class="box">
    <h2>➕ Add IOC</h2>
    <form method="post">
    <input name="ioc" placeholder="Enter IOC">
    <button>Add IOC</button>
    </form>
    <br><a href="/dashboard" style="color:#00d4ff;">⬅ Back</a>
    </div></body></html>"""

@app.post("/add")
def add_post(ioc: str = Form(...)):
    insert_or_update(ioc)
    return RedirectResponse("/dashboard", 302)

# ================= FEED =================
@app.get("/feed", response_class=HTMLResponse)
def feed_page():
    return """<html>
    <style>
    body{margin:0;height:100vh;display:flex;justify-content:center;align-items:center;
    background:url('https://images.unsplash.com/photo-1518770660439-4636190af475') center/cover;}
    .box{background:rgba(0,0,0,0.7);padding:40px;border-radius:15px;width:400px;text-align:center;color:white;}
    input{width:100%;padding:12px;margin:10px 0;border-radius:8px;border:none;}
    button{width:100%;padding:12px;background:#00d4ff;border:none;border-radius:8px;}
    </style>
    <body>
    <div class="box">
    <h2>📡 Threat Feed</h2>
    <form method="post">
    <input name="ioc" placeholder="Enter IOC">
    <button>Add Feed</button>
    </form>
    <br><a href="/auto-feed" style="color:#00d4ff;">⚡ Auto Feed</a>
    <br><a href="/dashboard" style="color:#00d4ff;">⬅ Back</a>
    </div></body></html>"""

@app.post("/feed")
def feed_post(ioc: str = Form(...)):
    insert_or_update(ioc)
    return RedirectResponse("/dashboard", 302)

@app.get("/auto-feed")
def auto_feed():
    sample_data = [
        "malicious.com", "http://bad.com", "192.168.1.1",
        "evil.net", "http://hack-site.com/login",
        "phishing-bank.com", "10.0.0.5",
        "secure-update.net", "fake-paypal.com",
        "dangerous.org"
    ]
    for i in sample_data:
        insert_or_update(i)
    return RedirectResponse("/dashboard", 302)

# ================= ALERTS =================
@app.get("/alerts", response_class=HTMLResponse)
def alerts():
    cursor.execute("SELECT * FROM threats WHERE score>=70")
    data = cursor.fetchall()

    rows = ""
    for d in data:
        rows += f"""
        <tr>
        <td>{escape(d[1])}</td>
        <td>{escape(d[2])}</td>
        <td>{escape(d[3])}</td>
        <td>{d[5]}</td>
        </tr>
        """

    return f"""
    <html>
    <style>
    body {{
        margin:0;
        height:100vh;
        display:flex;
        justify-content:center;
        align-items:center;
        font-family:sans-serif;
        color:white;
        background:url('https://images.unsplash.com/photo-1510511459019-5dda7724fd87') center/cover no-repeat;
    }}
    .container {{
        width:80%;
        max-width:900px;
        background:rgba(0,0,0,0.75);
        padding:40px;
        border-radius:20px;
        backdrop-filter:blur(10px);
        box-shadow:0 0 40px rgba(0,255,255,0.3);
        text-align:center;
    }}
    h1 {{ color:#00e6ff; margin-bottom:25px; font-size:30px; }}
    table {{ width:100%; border-collapse:collapse; margin-top:20px; font-size:18px; }}
    th {{ background:#00e6ff; color:black; padding:14px; font-size:18px; }}
    td {{ padding:14px; border-bottom:1px solid rgba(255,255,255,0.2); }}
    tr:hover {{ background:rgba(0,255,255,0.1); }}
    .back {{ display:inline-block; margin-top:20px; color:#00e6ff; text-decoration:none; font-size:16px; }}
    </style>
    <body>
    <div class="container">
        <h1>🚨 High Risk Alerts</h1>
        <table>
        <tr><th>IOC</th><th>Type</th><th>Threat</th><th>Score</th></tr>
        {rows}
        </table>
        <a class="back" href="/dashboard">⬅ Back</a>
    </div>
    </body>
    </html>
    """

# ================= REPORT =================
@app.get("/report", response_class=HTMLResponse)
def report():
    cursor.execute("SELECT * FROM threats")
    data = cursor.fetchall()

    total = len(data)
    high   = len([d for d in data if d[5] >= 70])
    medium = len([d for d in data if 40 <= d[5] < 70])
    low    = len([d for d in data if d[5] < 40])

    # Frequency tracking
    freq = {}
    for d in data:
        freq[d[1]] = freq.get(d[1], 0) + 1

    top_ioc  = escape(max(freq, key=freq.get)) if freq else "None"
    top_freq = freq[max(freq, key=freq.get)] if freq else 0

    # Threat type distribution
    malware  = len([d for d in data if d[3] == "Malware"])
    phishing = len([d for d in data if d[3] == "Phishing"])

    # Most common AI reason
    reasons = {}
    for d in data:
        reasons[d[7]] = reasons.get(d[7], 0) + 1
    top_reason = escape(max(reasons, key=reasons.get)) if reasons else "N/A"

    majority = "Malware" if malware > phishing else "Phishing"

    return f"""
    <html>
    <style>
    body {{
        margin:0;
        min-height:100vh;
        display:flex;
        justify-content:center;
        align-items:center;
        font-family:sans-serif;
        color:white;
        background:url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b') center/cover no-repeat;
    }}
    .card {{
        width:650px;
        background:rgba(0,0,0,0.75);
        padding:40px;
        border-radius:20px;
        backdrop-filter:blur(12px);
        box-shadow:0 0 40px rgba(0,255,255,0.3);
        text-align:center;
    }}
    h1 {{ color:#00e6ff; margin-bottom:25px; }}
    .box {{
        margin:10px 0;
        padding:12px;
        background:rgba(255,255,255,0.06);
        border-radius:10px;
    }}
    .highlight {{ color:#00e6ff; font-weight:bold; }}
    .btn-download {{
        display:inline-block;
        margin-top:24px;
        padding:12px 32px;
        background:#00e6ff;
        color:black;
        font-weight:bold;
        font-size:16px;
        border-radius:10px;
        text-decoration:none;
        transition:opacity 0.2s;
    }}
    .btn-download:hover {{ opacity:0.85; }}
    .back {{
        display:inline-block;
        margin-top:16px;
        margin-left:16px;
        color:#00e6ff;
        text-decoration:none;
        font-size:15px;
    }}
    </style>
    <body>
    <div class="card">
        <h1>📊 Threat Intelligence Report</h1>

        <div class="box">Total Threats: <span class="highlight">{total}</span></div>
        <div class="box">High Risk: <span class="highlight">{high}</span></div>
        <div class="box">Medium Risk: <span class="highlight">{medium}</span></div>
        <div class="box">Low Risk: <span class="highlight">{low}</span></div>

        <div class="box">Top IOC: <span class="highlight">{top_ioc}</span> (appeared {top_freq} times)</div>

        <div class="box">Malware: <span class="highlight">{malware}</span> | Phishing: <span class="highlight">{phishing}</span></div>

        <div class="box">Most Common AI Reason: <span class="highlight">{top_reason}</span></div>

        <div class="box">
            🚀 System detected <span class="highlight">{total}</span> threats.
            Majority are <span class="highlight">{majority}</span>.
            High risk threats require immediate action.
        </div>

        <br>
        <a href="/download" class="btn-download">📥 Download Report (CSV)</a>
        <a class="back" href="/dashboard">⬅ Back</a>
    </div>
    </body>
    </html>
    """

# ================= LOAD =================
@app.get("/load")
def load():
    cursor.execute("DELETE FROM threats")

    data = [
        ("8.8.8.8",           "IP",     "Malware",  "High",   80, "Open", "Known malicious IP",        1),
        ("phishing-site.net", "Domain", "Phishing", "Medium", 50, "Open", "Suspicious domain",         1),
        ("http://bad.com",    "URL",    "Malware",  "High",   80, "Open", "Malicious URL pattern",     1),
        ("192.168.50.5",      "IP",     "Phishing", "Low",    20, "Open", "Low confidence",            1),
        ("evil.com",          "Domain", "Malware",  "High",   90, "Open", "Repeated malicious domain", 1),
    ]

    cursor.executemany(
        "INSERT INTO threats(ioc,type,threat,confidence,score,status,explanation,freq) VALUES(?,?,?,?,?,?,?,?)",
        data
    )
    conn.commit()

    return RedirectResponse("/dashboard", 302)

# ================= SEARCH =================
@app.get("/search", response_class=HTMLResponse)
def search(q: str = "", risk: str = ""):
    cursor.execute("SELECT * FROM threats")
    data = cursor.fetchall()

    result = []
    for d in data:
        match = True
        if q and q.lower() not in d[1].lower():
            match = False
        if risk:
            if risk == "high"   and d[5] < 70:            match = False
            elif risk == "medium" and not (40 <= d[5] < 70): match = False
            elif risk == "low"    and d[5] >= 40:            match = False
        if match:
            result.append(d)

    rows = ""
    for d in result:
        rows += f"<tr><td>{escape(d[1])}</td><td>{escape(d[3])}</td><td>{d[5]}</td></tr>"

    return f"""
    <html>
    <body style="background:#0f2027;color:white;text-align:center;">
    <h2>🔎 Search Results</h2>
    <table border="1" style="margin:auto;">
    <tr><th>IOC</th><th>Threat</th><th>Score</th></tr>
    {rows}
    </table>
    <br><a href="/dashboard" style="color:#00d4ff;">⬅ Back</a>
    </body></html>
    """

# ================= DOWNLOAD =================
@app.get("/download")
def download():
    cursor.execute("SELECT * FROM threats")
    data = cursor.fetchall()

    content = "IOC,Type,Threat,Score,Frequency\n"
    for d in data:
        content += f"{d[1]},{d[2]},{d[3]},{d[5]},{d[8]}\n"

    return PlainTextResponse(
        content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=report.csv"}
    )