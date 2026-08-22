from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/auth/password', methods=['POST'])
@app.route('/auth/pubkey', methods=['POST'])
def authenticate():
    # Return 200 OK with success flag and match response structure
    return jsonify({
        "success": True,
        "authenticatedUsername": request.json.get("username", "guestuser")
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)