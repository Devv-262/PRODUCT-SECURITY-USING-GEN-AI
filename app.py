from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, this is a vulnerable Flask app!\n"

# Extra unsafe endpoint: YAML parsing from user input!
@app.route("/yaml", methods=['POST'])
def yaml_parse():
    data = request.data
    try:
        parsed = yaml.load(data)  # Unsafe in old PyYAML
        return str(parsed)
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
