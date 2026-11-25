"""Loopback Maven transport via Python TLS, restricted to official repositories.

For runners where Python HTTPS works but the historical JDK's transport stalls.
Artifact bytes pass through unchanged; URL, response status and SHA-256 are logged.
"""
from contextlib import contextmanager
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


@contextmanager
def official_transport(settings, downloads, event_log=None):
    origins = {"central": "https://repo.maven.apache.org/maven2/",
               "jenkins": "https://repo.jenkins-ci.org/public/",
               "incrementals": "https://repo.jenkins-ci.org/incrementals/"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            route, _, path = self.path.lstrip("/").partition("/")
            if route not in origins or ".." in path.split("/") or "?" in path:
                self.send_error(400)
                return
            url = origins[route] + path
            entry = {"url": url}
            headers_sent = False
            try:
                request = urllib.request.Request(url, method=self.command)
                with urllib.request.urlopen(request, timeout=25) as response:
                    self.send_response(response.status)
                    length = getattr(response, "headers", {}).get("Content-Length")
                    if length and str(length).isdigit():
                        self.send_header("Content-Length", str(length))
                    self.end_headers()
                    headers_sent = True
                    checksum, count = hashlib.sha256(), 0
                    while self.command != "HEAD":
                        data = response.read(65536)
                        if not data:
                            break
                        checksum.update(data)
                        count += len(data)
                        self.wfile.write(data)
                    entry.update(status=response.status, bytes=count, method=self.command)
                    if self.command == "GET":
                        entry["sha256"] = checksum.hexdigest()
            except (BrokenPipeError, ConnectionResetError):
                entry["client_disconnected"] = True
            except urllib.error.HTTPError as exc:
                entry.update(status=exc.code)
                try:
                    self.send_error(exc.code)
                except (BrokenPipeError, ConnectionResetError):
                    entry["client_disconnected"] = True
            except Exception as exc:
                entry.update(status=502, error=type(exc).__name__)
                if not headers_sent:
                    try:
                        self.send_error(502)
                    except (BrokenPipeError, ConnectionResetError):
                        entry["client_disconnected"] = True
            finally:
                downloads.append(entry)
                if event_log:
                    with event_log.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(entry) + "\n")

        def do_HEAD(self):
            self.do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    namespace = {"m": "http://maven.apache.org/SETTINGS/1.0.0"}
    # Maven's settings reader requires an unprefixed settings root.
    ET.register_namespace("", namespace["m"])
    tree = ET.parse(settings)
    for mirror in tree.findall("m:mirrors/m:mirror", namespace):
        url = mirror.find("m:url", namespace)
        route = "jenkins" if "jenkins" in url.text else "central"
        url.text = f"http://127.0.0.1:{server.server_port}/{route}/"
        if route == "central":
            mirror.find("m:mirrorOf", namespace).text = "external:*,!repo.jenkins-ci.org,!jenkins.repo,!jenkins,!jenkins-public,!maven.jenkins-ci.org,!incrementals"
    # Incrementals has a distinct origin and must retain its own repository identity.
    mirrors = tree.find("m:mirrors", namespace)
    mirror = ET.SubElement(mirrors, "{http://maven.apache.org/SETTINGS/1.0.0}mirror")
    for key, value in {"id": "incrementals", "mirrorOf": "incrementals",
                       "url": f"http://127.0.0.1:{server.server_port}/incrementals/"}.items():
        ET.SubElement(mirror, "{http://maven.apache.org/SETTINGS/1.0.0}" + key).text = value
    tree.write(settings, encoding="utf-8", xml_declaration=True)
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
