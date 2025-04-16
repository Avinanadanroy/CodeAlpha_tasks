from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)

# Define a secure base directory for file access
SAFE_DIR = os.path.join(os.getcwd(), 'test_files')

@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')

    if not filename:
        return "Filename is required", 400

    # Resolve the absolute path
    requested_path = os.path.abspath(os.path.join(SAFE_DIR, filename))

    # Check that the requested file is within the SAFE_DIR
    if not requested_path.startswith(SAFE_DIR):
        return "Unauthorized file access attempt detected", 403

    # Check if the file exists
    if os.path.exists(requested_path):
        return send_file(requested_path, as_attachment=True)
    else:
        return "File not found", 404

@app.route('/')
def home():
    return '''
        <html>
            <head><title>Secure File Download</title></head>
            <body>
                <h2>Secure File Downloader</h2>
                <form method="get" action="/download">
                    <input type="text" name="filename" placeholder="Enter filename">
                    <input type="submit" value="Download">
                </form>
                <p>Available files are located in the <code>test_files</code> directory.</p>
            </body>
        </html>
    '''

if __name__ == '__main__':
    os.makedirs(SAFE_DIR, exist_ok=True)  # Ensure directory exists
    app.run(debug=True)
