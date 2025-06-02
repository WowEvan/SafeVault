from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def form():
    return open("templates/webform.html").read()

@app.route('/submit', methods=['POST'])
def submit():
    username = request.form['username']
    email = request.form['email']
    return f"Received: {username} - {email}"

app.run(debug=True)