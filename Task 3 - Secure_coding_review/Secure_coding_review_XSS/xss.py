from flask import Flask, request, render_template_string

app = Flask(__name__)

comments = []

@app.route('/')
def index():
    name = request.args.get('name', 'Guest')

    html = f'''
        <html>
            <head><title>XSS Demo</title></head>
            <body>
                <h1>Hello, {name}!</h1>
                <form method="POST" action="/comment">
                    <input type="text" name="comment" placeholder="Leave a comment">
                    <input type="submit" value="Submit">
                </form>
                <h2>Comments</h2>
                <ul>
                    {''.join(f"<li>{c}</li>" for c in comments)}
                </ul>
                <script>
                    var user = "{name}";
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
