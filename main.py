# Servidor HTTPS
import http.server
import ssl
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# Função para gerar chave e certificado autoassinado
def generate_self_signed_cert(cert_file, key_file):
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Distrito Federal"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Brasília"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SegurancaComputacional"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        cert = cert.public_key(key.public_key()).serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365))
        cert = cert.sign(key, hashes.SHA256())

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("Certificado e chave gerados com sucesso!")

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

generate_self_signed_cert(CERT_FILE, KEY_FILE)

class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Conexao segura estabelecida!')

if __name__ == "__main__":
    server_address = ('localhost', 4443)
    httpd = http.server.HTTPServer(server_address, SecureHTTPRequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("Servidor HTTPS rodando em https://localhost:4443")
    httpd.serve_forever()

# Cliente HTTPS
import requests

url = "https://localhost:4443"

try:
    response = requests.get(url, verify=CERT_FILE)
    print("Resposta do servidor:", response.text)
except requests.exceptions.SSLError as e:
    print("Erro SSL:", e)
except requests.exceptions.RequestException as e:
    print("Erro de requisicao:", e)