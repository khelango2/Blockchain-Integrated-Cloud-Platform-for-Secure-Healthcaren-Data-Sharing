import http.server
import socketserver
import os
import json
from urllib.parse import urlparse

PORT = 8002

class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        # Proxy POST requests to the backend
        if self.path.startswith('/api/'):
            self.proxy_to_backend()
        else:
            self.send_error(404, "Not Found")
    
    def do_GET(self):
        # Serve login page by default, or specific dashboards
        if self.path == '/':
            self.path = '/login.html'
        elif self.path == '/index.html':
            self.path = '/login.html'
        elif self.path.startswith('/api/'):
            self.proxy_to_backend()
            return
        return super().do_GET()
    
    def proxy_to_backend(self):
        """Proxy API requests to the backend server"""
        try:
            import urllib.request
            import urllib.parse
            
            print(f"PROXY DEBUG: {self.command} {self.path}")
            
            # Get request data
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else None
            
            # Construct backend URL
            backend_url = f"http://localhost:3000{self.path}"
            print(f"PROXY DEBUG: Forwarding to {backend_url}")
            
            # Create request
            req = urllib.request.Request(
                backend_url,
                data=post_data,
                headers=dict(self.headers),
                method=self.command
            )
            
            # Make request to backend
            with urllib.request.urlopen(req) as response:
                print(f"PROXY DEBUG: Backend response status: {response.getcode()}")
                self.send_response(response.getcode())
                
                # Copy headers
                for header, value in response.headers.items():
                    if header.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(header, value)
                
                self.end_headers()
                
                # Handle binary data properly for file downloads
                response_data = response.read()
                
                # Check if this is a file download
                content_type = response.headers.get('Content-Type', '')
                content_disposition = response.headers.get('Content-Disposition', '')
                
                print(f"PROXY DEBUG: Content-Type: {content_type}")
                print(f"PROXY DEBUG: Content-Disposition: {content_disposition}")
                print(f"PROXY DEBUG: Response data size: {len(response_data)}")
                
                if 'application/octet-stream' in content_type or 'attachment' in content_disposition:
                    # This is a file download - stream the binary data directly
                    print("PROXY DEBUG: Detected file download, streaming binary data")
                    self.wfile.write(response_data)
                else:
                    # Regular JSON response - write as text
                    print("PROXY DEBUG: Regular JSON response")
                    self.wfile.write(response_data)
                
        except Exception as e:
            print(f"PROXY ERROR: {str(e)}")
            self.send_error(500, f"Proxy error: {str(e)}")

if __name__ == "__main__":
    os.chdir('frontend')
    with socketserver.TCPServer(("", PORT), SecureHTTPRequestHandler) as httpd:
        print(f"Secure Doctor Dashboard running at http://localhost:{PORT}")
        print("Open http://localhost:8000 for secure healthcare access")
        httpd.serve_forever()
