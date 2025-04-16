from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/')
def home():
    return '''
        <html>
            <head><title>Command Injection Demo (Vulnerable)</title></head>
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

    # Highly vulnerable to command injection
    command = f"ping -n 1 {host}"  # Windows style. Use `-c 1` for Linux
    print(f"[DEBUG] Command Executed: {command}")

    # Direct execution of command
    os.system(f"{command} > temp_output.txt")  # Redirect output to file

    try:
        with open("temp_output.txt", "r") as f:
            output = f.read()
    except Exception as e:
        output = str(e)

    return render_template_string(f"""
        <html>
            <head><title>Ping Result</title></head>
            <body>
                <h3>Executed Command:</h3>
                <code>{command}</code>
                <h3>Command Output:</h3>
                <pre>{output}</pre>
                <a href="/">Go Back</a>
            </body>
        </html>
    """)

if __name__ == '__main__':
    app.run(debug=True)
