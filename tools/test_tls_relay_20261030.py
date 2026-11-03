"""Check byte transparency and half-close handling independently of public proxies."""
import socket
import threading
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from satellite_wf_v3_tls_relay_20261030 import DiagnosticThreadedRelay


class RelayTest(unittest.TestCase):
    def test_transparency_and_half_close_without_payload_logging(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        received = []
        payload = b'private-client-payload' * 4096
        reply = b'private-server-payload' * 4096
        def upstream():
            conn, _ = listener.accept()
            with conn:
                chunks = []
                while True:
                    data = conn.recv(8192)
                    if not data: break
                    chunks.append(data)
                received.append(b''.join(chunks))
                conn.sendall(reply)
            listener.close()
        thread = threading.Thread(target=upstream)
        thread.start()
        server = DiagnosticThreadedRelay(('127.0.0.1',0),listener.getsockname(),'/tmp/unused-relay-ready')
        events = []
        server.log = events.append
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            with socket.create_connection(server.server_address,timeout=5) as client:
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                chunks=[]
                while True:
                    data=client.recv(8192)
                    if not data: break
                    chunks.append(data)
            self.assertEqual(b''.join(chunks),reply)
            thread.join(5)
            self.assertEqual(received,[payload])
            self.assertNotIn('private-',str(events))
            directions={e['direction'] for e in events if e['event']=='eof'}
            self.assertEqual(directions,{'client_to_proxy','proxy_to_client'})
            self.assertEqual(sum(e['bytes'] for e in events if e['event']=='forwarded' and e['direction']=='client_to_proxy'),len(payload))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(5)

if __name__ == '__main__': unittest.main()
