from flask import Flask, request, render_template, send_file
from detectors.url_analyzer import UrlAnalyzer
from detectors.webpage_analyzer import WebpageAnalyzer
from detectors.db_comparator import DbComparator
from detectors.technical_evaluator import TechnicalEvaluator
from detectors.content_analyzer import ContentAnalyzer
import os
import csv
import io
from datetime import datetime

# Define os caminhos corretos para templates e static
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')
static_dir = os.path.join(basedir, 'web', 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url'].strip()
        # normaliza esquema caso usuário não inclua — assume HTTPS por padrão
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        results = analyze_url(url)
        try:
            _save_history(url, results)
        except Exception:
            pass
        all_ok = all(r['status'] == 'OK' for r in results.values())
        return render_template('index.html', results=results, all_ok=all_ok)
    return render_template('index.html', results=None, all_ok=None)

def analyze_url(url):
    url_analyzer = UrlAnalyzer()
    webpage_analyzer = WebpageAnalyzer()
    db_comparator = DbComparator()
    technical_evaluator = TechnicalEvaluator()
    content_analyzer = ContentAnalyzer()

    url_analysis = url_analyzer.analyze(url)
    webpage_analysis = webpage_analyzer.analyze(url)
    db_comparison = db_comparator.compare(url)
    technical_analysis = technical_evaluator.evaluate(url)
    content_analysis = content_analyzer.analyze(url)

    return {
        'url_analysis': url_analysis,
        'webpage_analysis': webpage_analysis,
        'db_comparison': db_comparison,
        'technical_analysis': technical_analysis,
        'content_analysis': content_analysis
    }

def _ensure_history():
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), 'database'))
    os.makedirs(base, exist_ok=True)
    hist = os.path.join(base, 'history.csv')
    if not os.path.exists(hist):
        with open(hist, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp','url','url_status','webpage_status','db_status','technical_status','content_status'])
    return hist

def _save_history(url, results):
    hist = _ensure_history()
    with open(hist, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(),
            url,
            results['url_analysis']['status'],
            results['webpage_analysis']['status'],
            results['db_comparison']['status'],
            results['technical_analysis']['status'],
            results['content_analysis']['status']
        ])


@app.route('/history')
def history():
    hist = _ensure_history()
    with open(hist, newline='', encoding='utf-8') as f:
        reader = list(csv.reader(f))
    return render_template('history.html', rows=reader[1:])


@app.route('/export')
def export_history():
    hist = _ensure_history()
    return send_file(hist, as_attachment=True, download_name='history.csv')


@app.route('/stats')
def stats():
    hist = _ensure_history()
    counts = {
        'total': 0,
        'url_fail': 0,
        'webpage_fail': 0,
        'db_fail': 0,
        'technical_fail': 0,
        'content_fail': 0
    }
    with open(hist, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            counts['total'] += 1
            if row.get('url') == 'FAIL' or row.get('url_status') == 'FAIL':
                counts['url_fail'] += 1
            if row.get('webpage_status') == 'FAIL':
                counts['webpage_fail'] += 1
            if row.get('db_status') == 'FAIL':
                counts['db_fail'] += 1
            if row.get('technical_status') == 'FAIL':
                counts['technical_fail'] += 1
            if row.get('content_status') == 'FAIL':
                counts['content_fail'] += 1
    return counts

if __name__ == '__main__':
    app.run(debug=True)