from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')

    # EXTREMELY VULNERABLE: Directly using user input in file path
    filepath = os.getcwd() + "/" + filename  # Avoiding os.path.join for demonstration

    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        return f"<h3>File Contents:</h3><pre>{content.decode('utf-8', errors='ignore')}</pre>"
    except FileNotFoundError:
        return f"<h3>Error:</h3><pre>File '{filename}' not found</pre>", 404
    except Exception as e:
        return f"<h3>Exception:</h3><pre>{str(e)}</pre>", 500

if __name__ == '__main__':
    app.run(debug=True)
# This code is intentionally vulnerable to demonstrate path traversal attacks.