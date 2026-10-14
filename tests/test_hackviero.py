"""Tests de Hackviero. Todo corre en local: sin internet ni objetivos externos."""
from __future__ import annotations

import hashlib
import json
import shutil
import socket
import ssl
import subprocess
import threading

import pytest

import hackviero as hv


# ──────────────────────────────────────────────────────────────────────────────
#  Utilidades de red para los tests
# ──────────────────────────────────────────────────────────────────────────────
def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def banner_server():
    """Servidor TCP local que responde con un banner; devuelve su puerto."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    stop = threading.Event()

    def loop() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            conn.sendall(b"SSH-2.0-TestServer\r\n")
            conn.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join(timeout=2)
    server.close()


# ──────────────────────────────────────────────────────────────────────────────
#  Puertos
# ──────────────────────────────────────────────────────────────────────────────
class TestPorts:
    def test_parse_ports_mixed(self):
        assert hv.parse_ports("22, 80,1000-1002") == [22, 80, 1000, 1001, 1002]

    def test_parse_ports_dedupes_and_orders(self):
        assert hv.parse_ports("80,22,80,20-22") == [20, 21, 22, 80]

    def test_parse_ports_reversed_range(self):
        assert hv.parse_ports("10-8") == [8, 9, 10]

    @pytest.mark.parametrize("bad", ["", "abc", "0", "70000", "1-70000", "80,x"])
    def test_parse_ports_invalid(self, bad):
        with pytest.raises(ValueError):
            hv.parse_ports(bad)

    def test_resolve_port_spec_keywords(self):
        assert hv.resolve_port_spec("top") == list(hv.TOP_PORTS)
        assert len(hv.resolve_port_spec("all")) == 65535
        assert hv.resolve_port_spec("443") == [443]

    def test_scan_finds_open_port_and_banner(self, banner_server):
        closed = free_port()
        results = hv.scan_ports("127.0.0.1", [banner_server, closed], timeout=1.0)
        assert [r.port for r in results] == [banner_server]
        assert results[0].banner.startswith("SSH-2.0-TestServer")

    def test_scan_without_banner(self, banner_server):
        results = hv.scan_ports("127.0.0.1", [banner_server], timeout=1.0, grab_banner=False)
        assert results[0].banner == ""

    def test_scan_progress_callback_counts_every_port(self):
        ports = [free_port() for _ in range(5)]
        ticks = []
        hv.scan_ports("127.0.0.1", ports, timeout=0.3, on_progress=lambda: ticks.append(1))
        assert len(ticks) == 5

    def test_resolve_host(self):
        assert hv.resolve_host("127.0.0.1") == "127.0.0.1"
        with pytest.raises(ValueError):
            hv.resolve_host("no-existe.invalid")


# ──────────────────────────────────────────────────────────────────────────────
#  Hashes
# ──────────────────────────────────────────────────────────────────────────────
class TestHashes:
    def test_known_vectors(self):
        digests = hv.hash_bytes(b"abc")
        assert digests["md5"] == "900150983cd24fb0d6963f7d28e17f72"
        assert digests["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
        assert digests["sha256"] == hashlib.sha256(b"abc").hexdigest()

    def test_hash_file_matches_bytes(self, tmp_path):
        path = tmp_path / "datos.bin"
        content = b"hackviero" * 200_000  # > 1 MiB: obliga a leer por bloques
        path.write_bytes(content)
        assert hv.hash_file(str(path)) == hv.hash_bytes(content)

    def test_verify_file_hash(self, tmp_path):
        path = tmp_path / "a.txt"
        path.write_text("hola")
        good = hashlib.sha256(b"hola").hexdigest()
        assert hv.verify_file_hash(str(path), good) == "sha256"
        assert hv.verify_file_hash(str(path), good.upper()) == "sha256"
        assert hv.verify_file_hash(str(path), "0" * 64) is None

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5"),
            ("a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1"),
            (hashlib.sha256(b"x").hexdigest(), "SHA-256"),
            (hashlib.sha512(b"x").hexdigest(), "SHA-512"),
            ("$2b$12$" + "a" * 53, "bcrypt"),
            ("$6$salt$hashhashhash", "SHA-512-crypt"),
        ],
    )
    def test_identify_hash(self, value, expected):
        assert expected in hv.identify_hash(value)

    def test_identify_hash_unknown(self):
        assert hv.identify_hash("") == []
        assert hv.identify_hash("esto no es un hash") == []
        assert hv.identify_hash("abc123") == []


# ──────────────────────────────────────────────────────────────────────────────
#  Contraseñas
# ──────────────────────────────────────────────────────────────────────────────
class TestPasswords:
    def test_common_password_is_very_weak(self):
        result = hv.analyze_password("qwerty123")
        assert result["label"] == "Muy débil"
        assert result["entropy"] <= 8.0
        assert any("comunes" in issue for issue in result["issues"])

    def test_detects_repeats_and_sequences(self):
        issues = " ".join(hv.analyze_password("aaa1234Zx").get("issues", []))
        assert "repetidos" in issues and "secuencias" in issues

    def test_strong_password_scores_high(self):
        result = hv.analyze_password("k#9Vq!2mZp@7Lx$4Rt&8")
        assert result["label"] in ("Fuerte", "Excelente")
        assert result["issues"] == []

    def test_longer_is_stronger(self):
        assert hv.analyze_password("Xk9#mQ2$vL7@pR4!")["entropy"] > hv.analyze_password("Xk9#mQ2$")["entropy"]

    def test_humanize_seconds(self):
        assert hv.humanize_seconds(0.2) == "instantáneo"
        assert hv.humanize_seconds(30) == "30 segundos"
        assert "universo" in hv.humanize_seconds(1e30)

    def test_generate_has_every_selected_class(self):
        for _ in range(50):
            pw = hv.generate_password(12)
            assert len(pw) == 12
            assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
            assert any(c.isdigit() for c in pw) and any(c in hv.SYMBOLS for c in pw)

    def test_generate_avoids_ambiguous(self):
        for _ in range(50):
            assert not set(hv.generate_password(40, avoid_ambiguous=True)) & set(hv.AMBIGUOUS_CHARS)

    def test_generate_digits_only(self):
        pw = hv.generate_password(16, lower=False, upper=False, symbols=False)
        assert pw.isdigit() and len(pw) == 16

    def test_generate_errors(self):
        with pytest.raises(ValueError):
            hv.generate_password(10, lower=False, upper=False, digits=False, symbols=False)
        with pytest.raises(ValueError):
            hv.generate_password(2)

    def test_generate_is_not_repeating(self):
        assert len({hv.generate_password(20) for _ in range(200)}) == 200

    def test_pwned_count_parses_k_anonymity_response(self, monkeypatch):
        # SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        seen = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return (
                    "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"
                    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n"
                    "00000000000000000000000000000000000:0\r\n"
                ).encode()

        def fake_urlopen(request, timeout=None):
            seen["url"] = request.full_url
            return FakeResponse()

        monkeypatch.setattr(hv.urllib.request, "urlopen", fake_urlopen)
        assert hv.pwned_count("password") == 9545824
        assert seen["url"].endswith("/range/5BAA6")  # solo el prefijo de 5 caracteres
        assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8" not in seen["url"].upper()  # el sufijo nunca sale
        assert hv.pwned_count("una-contraseña-que-no-esta-0000") == 0

    def test_report_pwned_exit_codes(self, monkeypatch):
        monkeypatch.setattr(hv, "pwned_count", lambda pw: 5)
        assert hv.report_pwned("x") == 1
        monkeypatch.setattr(hv, "pwned_count", lambda pw: 0)
        assert hv.report_pwned("x") == 0

        def boom(pw):
            raise hv.urllib.error.URLError("sin red")

        monkeypatch.setattr(hv, "pwned_count", boom)
        assert hv.report_pwned("x") == 2


# ──────────────────────────────────────────────────────────────────────────────
#  Codificadores y JWT
# ──────────────────────────────────────────────────────────────────────────────
class TestEncoders:
    @pytest.mark.parametrize("key", sorted(hv.CODEC_KEYS))
    @pytest.mark.parametrize("text", ["Hackviero", "ñandú ✓ 2026!", "a b\tc"])
    def test_roundtrip(self, key, text):
        _name, encode, decode = hv.CODECS[hv.CODEC_KEYS[key]]
        assert decode(encode(text)) == text

    def test_known_values(self):
        assert hv.CODECS[0][1]("hola") == "aG9sYQ=="
        assert hv.CODECS[2][1]("A") == "41"
        assert hv.CODECS[5][1]("A") == "01000001"

    def test_base64_without_padding(self):
        assert hv.CODECS[0][2]("aG9sYQ") == "hola"

    @pytest.mark.parametrize("key, bad", [("b64", "@@@"), ("hex", "zz"), ("bin", "0101"), ("bin", "abcdefgh")])
    def test_decode_errors_are_valueerror(self, key, bad):
        decode = hv.CODECS[hv.CODEC_KEYS[key]][2]
        with pytest.raises(ValueError):
            decode(bad)

    def test_decode_jwt(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiSnVhbiJ9."
            "firma"
        )
        head, payload = hv.decode_jwt(token)
        assert head == {"alg": "HS256", "typ": "JWT"}
        assert payload == {"sub": "123456", "name": "Juan"}

    @pytest.mark.parametrize("bad", ["", "a.b", "a.b.c.d", "!!!.???.###", "e30.W10.x"])
    def test_decode_jwt_invalid(self, bad):
        with pytest.raises(ValueError):
            hv.decode_jwt(bad)


# ──────────────────────────────────────────────────────────────────────────────
#  Subredes
# ──────────────────────────────────────────────────────────────────────────────
class TestSubnet:
    def rows(self, cidr):
        return dict(hv.subnet_info(cidr)["rows"])

    def test_slash24(self):
        rows = self.rows("192.168.1.77/24")
        assert rows["Red"] == "192.168.1.0"
        assert rows["Máscara"] == "255.255.255.0"
        assert rows["Broadcast"] == "192.168.1.255"
        assert rows["Primer host"] == "192.168.1.1"
        assert rows["Último host"] == "192.168.1.254"
        assert rows["Hosts utilizables"] == "254"
        assert rows["Tipo"] == "privada"

    def test_slash31_and_32(self):
        assert self.rows("10.0.0.0/31")["Hosts utilizables"] == "2"
        assert self.rows("10.0.0.5/32")["Hosts utilizables"] == "1"

    def test_ipv6(self):
        rows = self.rows("2001:db8::/32")
        assert rows["Versión"] == "IPv6"
        assert "Direcciones totales" in rows

    def test_public_and_invalid(self):
        assert "pública" in self.rows("8.8.8.0/24")["Tipo"]
        with pytest.raises(ValueError):
            hv.subnet_info("esto/no")


# ──────────────────────────────────────────────────────────────────────────────
#  Entradas de usuario
# ──────────────────────────────────────────────────────────────────────────────
class TestInputHelpers:
    def test_clean_target(self):
        assert hv.clean_target("  https://ejemplo.com/ruta?x=1 ") == "ejemplo.com"
        assert hv.clean_target("ftp://host:21/dir") == "host:21"
        assert hv.clean_target("1.2.3.4") == "1.2.3.4"

    def test_normalize_url(self):
        assert hv.normalize_url("ejemplo.com") == "https://ejemplo.com"
        assert hv.normalize_url("http://ejemplo.com") == "http://ejemplo.com"
        for bad in ("", "   ", "ftp://x.com", "http://"):
            with pytest.raises(ValueError):
                hv.normalize_url(bad)

    def test_split_host_port(self):
        assert hv.split_host_port("ejemplo.com") == ("ejemplo.com", 443)
        assert hv.split_host_port("ejemplo.com:8443") == ("ejemplo.com", 8443)
        assert hv.split_host_port("https://ejemplo.com:9000/x") == ("ejemplo.com", 9000)
        assert hv.split_host_port("::1") == ("::1", 443)  # IPv6: varios ':' no son puerto
        with pytest.raises(ValueError):
            hv.split_host_port("ejemplo.com:abc")

    def test_is_loopback(self):
        assert hv.is_loopback_host("localhost") and hv.is_loopback_host("127.0.0.1") and hv.is_loopback_host("::1")
        assert not hv.is_loopback_host("8.8.8.8") and not hv.is_loopback_host("ejemplo.com")


# ──────────────────────────────────────────────────────────────────────────────
#  Cabeceras HTTP
# ──────────────────────────────────────────────────────────────────────────────
class TestHeaders:
    def report(self, headers, cookies=(), url="https://x.com"):
        return hv.HeaderReport(final_url=url, status=200, headers=headers, cookies=list(cookies))

    def test_perfect_score(self):
        headers = {key: "x" for key, _n, _d in hv.SECURITY_HEADERS}
        analysis = hv.analyze_headers(self.report(headers))
        assert analysis["grade"] == "A+" and analysis["score"] == 100 and not analysis["missing"]

    def test_empty_is_failing_and_flags_http(self):
        analysis = hv.analyze_headers(self.report({}, url="http://x.com"))
        assert analysis["grade"] == "F" and not analysis["uses_https"]
        assert len(analysis["missing"]) == len(hv.SECURITY_HEADERS)

    def test_csp_frame_ancestors_covers_xfo(self):
        analysis = hv.analyze_headers(
            self.report({"content-security-policy": "default-src 'self'; frame-ancestors 'none'"})
        )
        assert "x-frame-options" in analysis["present"]

    def test_leaks_and_cookies(self):
        analysis = hv.analyze_headers(
            self.report(
                {"server": "nginx/1.0", "x-powered-by": "PHP/5"},
                cookies=["a=1; Secure; HttpOnly; SameSite=Lax", "b=2; Path=/"],
            )
        )
        assert dict(analysis["leaks"]) == {"server": "nginx/1.0", "x-powered-by": "PHP/5"}
        assert len(analysis["cookie_issues"]) == 1 and analysis["cookie_issues"][0].startswith("b:")


# ──────────────────────────────────────────────────────────────────────────────
#  DNS, subdominios y WHOIS (con respuestas simuladas: sin red)
# ──────────────────────────────────────────────────────────────────────────────
class TestDnsAndWhois:
    def test_dns_lookup_localhost(self):
        data = hv.dns_lookup("localhost")
        assert "127.0.0.1" in data["ipv4"]

    def test_dns_lookup_ip_and_failure(self):
        assert hv.dns_lookup("127.0.0.1")["ipv4"] == ["127.0.0.1"]
        with pytest.raises(ValueError):
            hv.dns_lookup("no-existe.invalid")

    def test_enumerate_subdomains(self, monkeypatch):
        table = {"www.ej.com": ["1.1.1.1"], "api.ej.com": ["2.2.2.2", "2.2.2.3"]}
        monkeypatch.setattr(hv, "resolve_quiet", lambda name: table.get(name, []))
        found, wildcard = hv.enumerate_subdomains("ej.com", ["www", "api", "nada"])
        assert found == [("api.ej.com", ["2.2.2.2", "2.2.2.3"]), ("www.ej.com", ["1.1.1.1"])]
        assert wildcard == set()

    def test_enumerate_subdomains_filters_wildcard_dns(self, monkeypatch):
        def fake(name):
            return ["9.9.9.9"] if name != "real.ej.com" else ["3.3.3.3"]

        monkeypatch.setattr(hv, "resolve_quiet", fake)
        found, wildcard = hv.enumerate_subdomains("ej.com", ["www", "mail", "real"])
        assert wildcard == {"9.9.9.9"}
        assert found == [("real.ej.com", ["3.3.3.3"])]

    def test_enumerate_subdomains_reports_progress(self, monkeypatch):
        monkeypatch.setattr(hv, "resolve_quiet", lambda name: [])
        ticks = []
        hv.enumerate_subdomains("ej.com", ["a", "b", "c"], on_progress=lambda: ticks.append(1))
        assert len(ticks) == 3

    def test_load_wordlist(self, tmp_path):
        path = tmp_path / "w.txt"
        path.write_text("# comentario\nWWW\n\nApi\nwww\n", encoding="utf-8")
        assert hv.load_wordlist(str(path)) == ["www", "api"]

    def test_parse_whois_domain(self):
        text = (
            "% aviso\n"
            "   Domain Name: EXAMPLE.COM\n"
            "   Registrar: Example Registrar, Inc.\n"
            "   Creation Date: 1995-08-14T04:00:00Z\n"
            "   Registry Expiry Date: 2026-08-13T04:00:00Z\n"
            "   Name Server: A.IANA-SERVERS.NET\n"
            "   Name Server: B.IANA-SERVERS.NET\n"
            "   Name Server: A.IANA-SERVERS.NET\n"
            ">>> Last update <<<\n"
        )
        rows = dict(hv.parse_whois(text))
        assert rows["Dominio"] == "EXAMPLE.COM"
        assert rows["Registrador"] == "Example Registrar, Inc."
        assert rows["Servidores DNS"] == "A.IANA-SERVERS.NET, B.IANA-SERVERS.NET"  # sin duplicados

    def test_parse_whois_ip_and_garbage(self):
        rows = dict(hv.parse_whois("NetRange: 8.8.8.0 - 8.8.8.255\nOrgName: Google LLC\nCountry: US\n"))
        assert rows["Rango de red"] == "8.8.8.0 - 8.8.8.255" and rows["Organización"] == "Google LLC"
        assert hv.parse_whois("nada útil aquí") == []

    def test_whois_lookup_follows_referrals(self, monkeypatch):
        calls = []

        def fake(server, query, timeout=8.0):
            calls.append(server)
            if server == "whois.iana.org":
                return "refer:        whois.verisign-grs.com\n"
            if server == "whois.verisign-grs.com":
                return "Domain Name: EJ.COM\nRegistrar WHOIS Server: whois.registrador.test\n"
            return "Domain Name: EJ.COM\nRegistrar: Detallado S.A.\n"

        monkeypatch.setattr(hv, "whois_query", fake)
        server, text = hv.whois_lookup("ej.com")
        assert calls == ["whois.iana.org", "whois.verisign-grs.com", "whois.registrador.test"]
        assert server == "whois.registrador.test" and "Detallado" in text

    def test_whois_lookup_keeps_registry_if_registrar_fails(self, monkeypatch):
        def fake(server, query, timeout=8.0):
            if server == "whois.iana.org":
                return "whois: whois.verisign-grs.com\n"
            if server == "whois.verisign-grs.com":
                return "Domain Name: EJ.COM\nRegistrar WHOIS Server: caido.test\n"
            raise OSError("caído")

        monkeypatch.setattr(hv, "whois_query", fake)
        server, text = hv.whois_lookup("ej.com")
        assert server == "whois.verisign-grs.com" and "EJ.COM" in text


# ──────────────────────────────────────────────────────────────────────────────
#  TLS contra un servidor local con certificado autofirmado
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl no disponible")
    folder = tmp_path_factory.mktemp("tls")
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
            "-days", "30", "-subj", "/CN=localhost/O=Hackviero Test", "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    stop = threading.Event()

    def loop() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            try:
                with context.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                conn.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    yield {"port": server.getsockname()[1], "cert": str(cert)}
    stop.set()
    thread.join(timeout=2)
    server.close()


class TestTls:
    def test_untrusted_certificate_is_reported(self, tls_server):
        data = hv.tls_inspect("127.0.0.1", tls_server["port"])
        assert data["verified"] is False
        assert "self" in data["error"].lower() or "unable" in data["error"].lower()
        assert data["protocol"] in ("TLSv1.2", "TLSv1.3")

    def test_trusted_certificate_is_parsed(self, tls_server, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", tls_server["cert"])
        data = hv.tls_inspect("localhost", tls_server["port"])
        assert data["verified"] is True
        assert data["subject"]["commonName"] == "localhost"
        assert data["subject"]["organizationName"] == "Hackviero Test"
        assert data["san"] == ["localhost"]
        assert 28 <= data["days_left"] <= 30

    def test_connection_refused_raises_oserror(self):
        with pytest.raises(OSError):
            hv.tls_inspect("127.0.0.1", free_port(), timeout=1.0)


# ──────────────────────────────────────────────────────────────────────────────
#  CLI de extremo a extremo
# ──────────────────────────────────────────────────────────────────────────────
class TestCli:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            hv.main(["--version"])
        assert exc.value.code == 0
        assert hv.VERSION in capsys.readouterr().out

    def test_unknown_command_exits_with_error(self):
        with pytest.raises(SystemExit) as exc:
            hv.main(["inexistente"])
        assert exc.value.code != 0

    def test_scan_loopback_writes_json(self, banner_server, tmp_path, capsys):
        out = tmp_path / "scan.json"
        code = hv.main(["scan", "127.0.0.1", "-p", str(banner_server), "-t", "1", "-o", str(out)])
        assert code == 0
        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["ip"] == "127.0.0.1" and report["scanned_ports"] == 1
        assert report["open"][0]["port"] == banner_server
        assert report["open"][0]["banner"].startswith("SSH-2.0")

    def test_scan_requires_confirmation_when_not_interactive(self, monkeypatch, capsys):
        monkeypatch.setattr(hv.sys.stdin, "isatty", lambda: False, raising=False)
        monkeypatch.setattr(hv, "resolve_host", lambda host: "93.184.216.34")
        assert hv.main(["scan", "ejemplo.test", "-p", "80"]) == 1
        assert "--yes" in capsys.readouterr().out

    def test_scan_rejects_bad_ports(self):
        assert hv.main(["scan", "127.0.0.1", "-p", "abc"]) == 2

    def test_hash_commands(self, tmp_path):
        path = tmp_path / "f.txt"
        path.write_text("hola")
        digest = hashlib.sha256(b"hola").hexdigest()
        assert hv.main(["hash", "text", "hola"]) == 0
        assert hv.main(["hash", "file", str(path)]) == 0
        assert hv.main(["hash", "id", digest]) == 0
        assert hv.main(["hash", "id", "zzz"]) == 1
        assert hv.main(["hash", "verify", str(path), digest]) == 0
        assert hv.main(["hash", "verify", str(path), "0" * 64]) == 1
        assert hv.main(["hash", "file", str(tmp_path / "no-existe")]) == 2

    def test_enc_outputs_raw_text_when_piped(self, capsys):
        assert hv.main(["enc", "b64", "hola"]) == 0
        assert capsys.readouterr().out.strip().endswith("aG9sYQ==")
        assert hv.main(["enc", "b64", "aG9sYQ==", "-d"]) == 0
        assert capsys.readouterr().out.strip().endswith("hola")
        assert hv.main(["enc", "hex", "zz", "-d"]) == 1

    def test_pass_gen_outputs_one_per_line_when_piped(self, capsys):
        assert hv.main(["pass", "gen", "-l", "18", "-n", "4", "--no-symbols"]) == 0
        lines = [l for l in capsys.readouterr().out.splitlines() if len(l) == 18]
        assert len(lines) == 4 and all(l.isalnum() for l in lines)
        assert hv.main(["pass", "gen", "-l", "2"]) == 2

    def test_pass_check_reads_hidden_prompt(self, monkeypatch):
        monkeypatch.setattr(hv.getpass, "getpass", lambda prompt="": "Xk9#mQ2$vL7@pR4!zT")
        assert hv.main(["pass", "check"]) == 0
        monkeypatch.setattr(hv.getpass, "getpass", lambda prompt="": "")
        assert hv.main(["pass", "check"]) == 2

    def test_subnet_command(self):
        assert hv.main(["subnet", "10.1.2.3/16", "--split", "18"]) == 0
        assert hv.main(["subnet", "10.0.0.0/24", "--split", "20"]) == 2
        assert hv.main(["subnet", "basura"]) == 2

    def test_jwt_command(self):
        good = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x"
        assert hv.main(["jwt", good]) == 0
        assert hv.main(["jwt", "nope"]) == 1

    def test_tls_command_against_local_server(self, tls_server):
        assert hv.main(["tls", f"127.0.0.1:{tls_server['port']}"]) == 0
        assert hv.main(["tls", "127.0.0.1", "-p", str(free_port())]) == 1

    def test_misc_commands_run(self):
        assert hv.main(["dns", "localhost"]) == 0
        assert hv.main(["sys"]) == 0
        assert hv.main(["dns", "no-existe.invalid"]) == 1
        assert hv.main(["subs", "sindominio"]) == 2

    def test_whois_network_error_is_handled(self, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError("sin red")

        monkeypatch.setattr(hv, "whois_query", boom)
        assert hv.main(["whois", "ejemplo.com"]) == 1


# ──────────────────────────────────────────────────────────────────────────────
#  Menú interactivo
# ──────────────────────────────────────────────────────────────────────────────
class TestInteractive:
    def test_menu_lists_every_tool_with_unique_keys(self):
        keys = [key for key, *_ in hv.TOOLS]
        assert len(keys) == len(set(keys)) == 11
        assert all(callable(func) for *_, func in hv.TOOLS)

    def test_menu_runs_a_tool_and_exits(self, monkeypatch):
        answers = iter(["11", "", "0"])  # info del sistema → Enter para volver → salir
        monkeypatch.setattr(hv.PromptES, "ask", classmethod(lambda cls, *a, **k: next(answers)))
        monkeypatch.setattr(hv.console, "input", lambda *a, **k: next(answers))
        assert hv.main([]) == 0
