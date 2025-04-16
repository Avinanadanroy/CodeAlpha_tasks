from flask import Flask, request, render_template_string
import subprocess
import re

app = Flask(__name__)

@app.route('/')
def home():
    return '''
        <html>
            <head><title>Command Injection Secure Demo</title></head>
            <body>
                <h2>Ping a Host</h2>
                <form action="/ping" method="GET">
                    <input type="text" name="host" placeholder="Enter IP or domain">
                    <input type="submit" value="Ping">
                </form>
            </body>
        </html>
    '''

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '')

    # Input validation: only allow alphanumeric, dots, hyphens
    if not re.match(r'^[\w\.\-]+$', host):
        return render_template_string('''
            <html><body>
                <h3>Invalid host input!</h3>
                <a href="/">Go Back</a>
            </body></html>
        ''')

    try:
        # Safe execution without shell
        result = subprocess.run(['ping', '-n', '1', host], capture_output=True, text=True, timeout=5)
        output = result.stdout
    except Exception as e:
        output = f"Error: {str(e)}"

    return render_template_string(f"""
        <html>
            <head><title>Ping Result</title></head>
            <body>
                <h3>Ping Output:</h3>
                <pre>{output}</pre>
                <a href="/">Go Back</a>
            </body>
        </html>
    """)

if __name__ == '__main__':
    app.run(debug=True)
