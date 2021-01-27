#!/usr/bin/python3

import argparse
import configparser
import datetime
import socket
import ssl

from cryptography import x509


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--config", "-c", type=str, default="certexpire.ini")
    args = argparser.parse_args()

    config = configparser.ConfigParser(allow_no_value=True)
    config.read(args.config)

    for hostname in config.sections():
        if hostname == "DEFAULT":
            continue

        context = ssl.create_default_context()

        with socket.create_connection((hostname, config[hostname].getint("port", 443))) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                der_cert = sslsock.getpeercert(True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

                cert = x509.load_pem_x509_certificate(bytes(pem_cert, "utf-8"))
                now = datetime.datetime.now()
                time_left = cert.not_valid_after - now

                if time_left.days < config[hostname].getint("warn_days_before", 5):
                    print(hostname, "is going to expire in", time_left.days, "days!")


if __name__ == '__main__':
    main()
