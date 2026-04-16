import socket
import threading
import time

from aegis_scan import scanner, utils


def _start_dummy_server(port_container: list):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    port_container.append(port)

    # accept one connection then close
    try:
        conn, _ = s.accept()
        try:
            conn.sendall(b"hello\n")
        except Exception:
            pass
        finally:
            conn.close()
    finally:
        s.close()


def test_parse_ports():
    assert utils.parse_ports("22,80,1000-1002") == [22, 80, 1000, 1001, 1002]


def test_scan_local_open_port():
    ports = []
    t = threading.Thread(target=_start_dummy_server, args=(ports,), daemon=True)
    t.start()
    # wait for server to bind
    timeout = time.time() + 2
    while not ports and time.time() < timeout:
        time.sleep(0.01)
    assert ports, "server did not start"
    port = ports[0]
    res = scanner.scan_ports("127.0.0.1", [port], timeout=0.5, workers=1)
    assert port in res


def test_ping_localhost():
    assert isinstance(scanner.ping_host("127.0.0.1"), bool)
