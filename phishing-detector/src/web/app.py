from flask import Flask, render_template, request
from detectors.url_analyzer import UrlAnalyzer
from detectors.webpage_analyzer import WebpageAnalyzer
from detectors.db_comparator import DbComparator
from detectors.technical_evaluator import TechnicalEvaluator
from detectors.content_analyzer import ContentAnalyzer

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        results = analyze_url(url)
        return render_template('index.html', results=results)
    return render_template('index.html', results=None)

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

if __name__ == '__main__':
    app.run(debug=True)