import copy
import re
from datetime import datetime, timedelta
from pathlib import Path
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, \
    load_pem_private_key, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend


def get_input(prompt, typecast_to=None, sanity_limit=5, choices=None, default=None):
    for _ in range(sanity_limit):
        given_input = input(prompt + ': ')
        if given_input == '' and default:
            given_input = copy.deepcopy(default)
        if typecast_to:
            try:
                given_input = typecast_to(given_input)
            except ValueError:
                print("Input not valid. Expected type is {}.Try again".format(typecast_to))
                continue
            except Exception as e:
                print(str(e))
                continue
        if choices:
            if given_input not in choices:
                print("Input not valid. Allowed choices are : {}.Try again".format(choices))
                continue
            else:
                break
        break
    else:
        raise Exception("Invalid input given for more than {} time(s)".format(sanity_limit))
    return given_input


def is_country_name_correct(data):
    if len(data) != 2 or not re.search('^[A-Z]{2}$', data):
        raise Exception("Country name is in incorrect format. It should a 2 letter code in all caps. Ex: IN")
    else:
        return str(data)


def is_cn_correct(data):
    if not data:
        raise Exception("CN should be given")
    else:
        return str(data)


def is_ip_correct(data):
    if data:
        try:
            ip = ip_address(data)
        except ValueError:
            raise Exception("Given input {} is not an IPv4 or IPv6 address".format(data))
        return ip
    else:
        return data


def get_ca_cert_input():

    print('\nPlease enter the required params to generate key pair and ca cert. Few params support default values. '
          'If you want to go with default values, just press enter\n')

    key_type = get_input("\nKey type to be generated. Only RSA is supported for now (default: RSA)",
                         typecast_to=str, sanity_limit=5, choices=['RSA'], default='RSA')

    key_size = get_input("\nKey size to be used. Only RSA key sizes are supported for now (default: 2048)",
                         typecast_to=int, sanity_limit=5, choices=[1024, 2048, 4096, 8192], default=2048)

    x509_list = []

    country = get_input("\nCountry Name (default: IN)",
                        typecast_to=is_country_name_correct, sanity_limit=5, default='IN')

    if country:
        x509_list.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country))

    state = get_input("\nState or Province",
                      typecast_to=str, sanity_limit=5)
    if state:
        x509_list.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state))

    locality = get_input("\nLocality",
                         typecast_to=str, sanity_limit=5)
    if locality:
        x509_list.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, state))

    org = get_input("\nOrganisation",
                    typecast_to=str, sanity_limit=5)

    if org:
        x509_list.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org))

    ou = get_input("\nOrganisational unit",
                   typecast_to=str, sanity_limit=5)

    if ou:
        x509_list.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, ou))

    cn = get_input("\nCommon Name",
                   typecast_to=is_cn_correct, sanity_limit=5)

    if cn:
        x509_list.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, cn))

    email = get_input("\nEmail",
                      typecast_to=str, sanity_limit=5)

    if org:
        x509_list.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email))

    san_list = []

    for i in range(10):
        dns_name = get_input("\nSAN DNS Name (Press enter to continue to next param)",
                             typecast_to=str, sanity_limit=5)
        if not dns_name:
            break
        else:
            san_list.append(x509.DNSName(dns_name))

    for i in range(10):
        dns_ip = get_input("\nSAN IP Name (Press enter to continue to next param)",
                           typecast_to=is_ip_correct, sanity_limit=5)
        if not dns_ip:
            break
        else:
            san_list.append(x509.IPAddress(dns_ip))

    validity = get_input("\nValidity in days",
                         typecast_to=int, sanity_limit=5)

    parent = get_input("\nCN of ca cert which will be used to sign this CA. For self signed, "
                       "please provide this input as 'self' (default: self)",
                       typecast_to=str, sanity_limit=5, default='self')

    name = x509.Name(x509_list)
    san = x509.SubjectAlternativeName(san_list)

    return key_type, key_size, name, san, validity, parent


def create_ca_cert(parent_folder):
    ca_cert = None
    ca_key = None

    key_type, key_size, name, san, validity, parent_ca_cn = get_ca_cert_input()

    if parent_ca_cn != 'self':
        if not Path(parent_folder).joinpath(parent_ca_cn).is_dir():
            raise Exception('Parent ca folder with name {} is not found under folder: {}'
                            .format(parent_folder, parent_ca_cn))
        else:
            ca_path = Path(parent_folder).joinpath(parent_ca_cn).joinpath('certs').joinpath('ca.cert.pem')
            with open(ca_path, "rb") as f:
                pem_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(pem_data, default_backend())

            key_path = Path(parent_folder).joinpath(parent_ca_cn).joinpath('private').joinpath('ca.key.pem')

            with open(key_path, "rb") as f:
                key_data = f.read()
            ca_key = load_pem_private_key(key_data, password=None)

    if key_type == 'RSA':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    else:
        raise Exception('Only RSA key type is supported for now.')

    cert = x509.CertificateBuilder().subject_name(
                name
            ).issuer_name(
                ca_cert.subject if ca_cert else name
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=validity)
            ).add_extension(
                san, critical=False
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            ).add_extension(
                x509.KeyUsage(digital_signature=True,
                              content_commitment=False,
                              key_encipherment=False,
                              data_encipherment=False,
                              key_agreement=False,
                              key_cert_sign=True,
                              crl_sign=True,
                              encipher_only=False,
                              decipher_only=False), critical=True
           ).sign(ca_key if ca_key else private_key, hashes.SHA256())

    cn = name.rfc4514_string().split(',')[0].split('=')[1]
    cn = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    ca_parent_path = Path(parent_folder).joinpath(cn)
    ca_certs_path = ca_parent_path.joinpath('certs')
    new_certs_path = ca_parent_path.joinpath('newcerts')
    priv_path = ca_parent_path.joinpath('private')
    crl_path = ca_parent_path.joinpath('crl')

    ca_parent_path.mkdir(exist_ok=True)
    ca_certs_path.mkdir()
    new_certs_path.mkdir()
    priv_path.mkdir()
    crl_path.mkdir()

    cert_path = ca_certs_path.joinpath('ca.cert.pem')
    private_key_path = priv_path.joinpath('ca.key.pem')

    with open(str(cert_path), "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    with open(str(private_key_path), "wb") as f:
        f.write(private_key.private_bytes(
                   encoding=Encoding.PEM,
                   format=PrivateFormat.TraditionalOpenSSL,
                   encryption_algorithm=NoEncryption()))


if __name__ == '__main__':
    create_ca_cert('/home/lonewolf/PycharmProjects/cmp/certs/')
