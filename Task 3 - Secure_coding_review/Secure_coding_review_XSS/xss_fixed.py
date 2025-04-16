from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

comments = []

@app.route('/')
def index():
    name = request.args.get('name', 'Guest')
    safe_name = escape(name)
    safe_comments = [escape(c) for c in comments]

    html = f'''
        <html>
            <head><title>XSS Secure Demo</title></head>
            <body>
                <h1>Hello, {safe_name}!</h1>
                <form method="POST" action="/comment">
                    <input type="text" name="comment" placeholder="Leave a comment">
                    <input type="submit" value="Submit">
                </form>
                <h2>Comments</h2>
                <ul>
                    {''.join(f"<li>{c}</li>" for c in safe_comments)}
                </ul>
                <script>
                    var user = "{safe_name}";
                    console.log("User is: " + user);
                </script>
            </body>
        </html>
    '''
    return render_template_string(html)

@app.route('/comment', methods=['POST'])
def comment():
    user_comment = request.form.get('comment', '')
    comments.append(user_comment)
    return "Comment added! <a href='/'>Go back</a>"

if __name__ == '__main__':
    app.run(debug=True)
