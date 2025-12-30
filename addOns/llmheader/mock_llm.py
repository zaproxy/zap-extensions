import http.server
import socketserver
import json

PORT = 5000

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/analyze':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            print(f"Received headers: {data.get('headers')}")

            response_data = [
                {
                    "issue": "Mock Security Issue",
                    "severity": "High",
                    "confidence": "Medium",
                    "recommendation": "Fix it immediately."
                }
            ]
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving Mock LLM at port {PORT}")
    httpd.serve_forever()
