"""BrainSpark exact-math microservice (SymPy). Run: python3 math_service.py"""
from flask import Flask, request, jsonify
from compute_core import compute

app = Flask(__name__)

@app.post('/compute')
def _compute():
    body = request.get_json(force=True) or {}
    action = body.pop('action', None)
    if not action:
        return jsonify({'ok': False, 'error': 'action required'}), 400
    try:
        return jsonify({'ok': True, **compute(action, **body)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 200  # 200 so the model can read the error and retry

@app.get('/health')
def _health():
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7001)
