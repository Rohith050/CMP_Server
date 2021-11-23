from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_modules import rfc2314
from pyasn1_modules import rfc2459
from pyasn1_modules import rfc2511

from pyasn1_modules import rfc4210, rfc3279, rfc3280, rfc2511
from pyasn1.type import char, univ, useful
from pyasn1_modules.rfc4210 import (PKIHeader, PKIMessage, PKIBody, PKIProtection, id_PasswordBasedMac, PBMParameter)
from pyasn1_modules.rfc2459 import (id_at_commonName, id_at_countryName, id_at_stateOrProvinceName, id_at_localityName,
                                    id_at_organizationName, id_at_organizationalUnitName,
                                    AttributeTypeAndValue, GeneralName, Name,
                                    RelativeDistinguishedName, RDNSequence)
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

import http.server
from socketserver import ThreadingMixIn

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat._oid import ObjectIdentifier

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

import hashlib
import hmac
import pathlib
import argparse

import binascii
import pprint
from termcolor import colored
from datetime import datetime, timedelta

import uuid

from cert_builder import get_input, create_ca_cert

PORT = 8000
cert_db = {}
state_tracker = {}


def convert_str_to_hex(string_input):
    str_val = string_input.encode('utf-8')
    return binascii.hexlify(str_val).decode('utf-8')


def convert_hex_to_str(hex_input):
    bytes_object = bytes.fromhex(hex_input)
    return bytes_object.decode("ASCII")


def convert_binary_to_string(binary_input):
    return binascii.b2a_base64(binary_input)


def calculate_hash(hex_input, algo='sha256'):
    return hashlib.sha256(bytes.fromhex(hex_input)).hexdigest()


def calculate_hmac(key, hex_input, algo='sha1'):
    return hmac.new(bytes.fromhex(key), bytes.fromhex(hex_input), hashlib.sha1).hexdigest()
    # return hmac.HMAC(bytes.fromhex(key), bytes.fromhex(hex_input), 'sha1').hexdigest()


def convert_hex_to_bin(hex_input):
    return binascii.a2b_hex(hex_input)


def get_algo_mapping(oid=None, name=None):
    if not oid and not name:
        raise Exception("Either OID or name is needed.")
    if oid and name:
        raise Exception("Either OID or name should be provided. Both are not allowed")
    mapper = {
               '2.16.840.1.101.3.4.2.1': 'SHA256',
               '1.3.6.1.5.5.8.1.2': 'HMAC-SHA1'
    }
    if oid:
        if oid not in mapper:
            raise Exception("{} is not known".format(oid))
        return {oid: mapper[oid]}
    elif name:
        for oid, algo_name in mapper.items():
            if algo_name == name:
                return {oid: name}
        raise Exception("{} is not known".format(name))


def decode_der(data):
    decoded_data = der_decoder.decode(data, asn1Spec=rfc4210.PKIMessage())
    x = list(decoded_data[0].items())
    a = decoded_data[0]['header']
    b = decoded_data[0]['body']
    c = list(a.items())
    d = list(b.items())
    print(decoded_data[0].prettyPrint())
    # print(decoded_data)


class MyHandler(http.server.BaseHTTPRequestHandler):

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "application/pkixcmp")
        self.end_headers()
        print(colored('Parsing the CMP Data', 'red'))
        data_string = self.rfile.read(int(self.headers['Content-Length']))
        self.wfile.write(get_packet(data_string))


class CmpHeaderPvno:
    def __init__(self, data, expected_pvno=None):
        if not data.isValue:
            raise Exception('pvno is not present in header')
        if str(data) != expected_pvno:
            raise Exception('Unsupported pvno. Expected {}. Received {}'.format(expected_pvno, str(data)))


class CmpSenderReciever:
    def __init__(self, data, mandatory=None):
        self.param = {'data': der_encoder.encode(data).hex(), 'obj': data}
        if not data.isValue and mandatory:
            raise Exception('sender/receiver is not present in header')
        self.param['directory_name'] = DirectoryName(data).param


class DirectoryName:
    def __init__(self, data):
        self.param = {}
        name = data.getComponentByName('directoryName')
        rdn_sequence = name.getComponentByName('')
        # for rdn_sequence in name.values():
        self.param['rdn_sequence'] = RDNSeq(rdn_sequence).param


class Subject:
    def __init__(self, data):  # here data is name object
        self.param = {}
        rdn_sequence = data.getComponentByName('')
        self.param['rdn_sequence'] = RDNSeq(rdn_sequence).param


class RDNSeq:
    def __init__(self, data):
        self.param = {'relat_dn': []}
        if not data.isValue:
            print('RDN sequence is not set')
        else:
            for relat_dn in data:
                self.param['relat_dn'].append(RelativeDN(relat_dn).param)
            temp_list = []
            x509_list = []
            for subject_attribute in self.param['relat_dn']:
                for key, value in subject_attribute.items():
                    if key == 'x509_attr':
                        x509_list.append(value)
                    else:
                        temp_list.append('{}={}'.format(key, value))
            # temp_subject = '/' + '/'.join(['{}={}'.format(key, value) for key, value in self.param.items()])
            self.param['one_line_subject'] = '/' + '/'.join(temp_list)
            self.param['X509_subject'] = x509.Name(x509_list)


class RelativeDN:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('RDN is not set')
        else:
            for relat_dn_attr in data:
                phew = der_decoder.decode(relat_dn_attr['value'])
                temp = ObjectIdentifier(str(univ.ObjectIdentifier(relat_dn_attr['type'])))
                self.param['x509_attr'] = x509.NameAttribute(temp, str(phew[0]))
                print(relat_dn_attr)
                if univ.ObjectIdentifier(relat_dn_attr['type']) == id_at_commonName:
                    # phew = der_decoder.decode(relat_dn_attr['value'])
                    self.param['CN'] = phew[0]
                elif univ.ObjectIdentifier(relat_dn_attr['type']) == id_at_countryName:
                    # phew = der_decoder.decode(relat_dn_attr['value'])
                    self.param['C'] = phew[0]
                elif univ.ObjectIdentifier(relat_dn_attr['type']) == id_at_stateOrProvinceName:
                    # phew = der_decoder.decode(relat_dn_attr['value'])
                    self.param['ST'] = phew[0]
                elif univ.ObjectIdentifier(relat_dn_attr['type']) == id_at_localityName:
                    # phew = der_decoder.decode(relat_dn_attr['value'])
                    self.param['L'] = phew[0]
                elif univ.ObjectIdentifier(relat_dn_attr['type']) == id_at_organizationName:
                    # phew = der_decoder.decode(relat_dn_attr['value'])
                    self.param['O'] = phew[0]
                elif univ.ObjectIdentifier(relat_dn_attr['type']) == id_at_organizationalUnitName:
                    # phew = der_decoder.decode(relat_dn_attr['value'])
                    self.param['OU'] = phew[0]
                else:
                    self.param[relat_dn_attr['type']] = phew[0]
                    print('Attribute "{}" in subject is parsed as raw OID. Script might need an update'
                          .format(relat_dn_attr['type']))


class MessageTime:
    def __init__(self, header_data):
        if not header_data.isValue:
            print('MessageTime is not set')
        else:
            ti = str(header_data)
            t = useful.UTCTime(ti)
            print('Message time: {}'.format(t))


class PBMParameters:
    def __init__(self, data):
        self.param = {}
        try:
            param = der_decoder.decode(data, asn1Spec=rfc4210.PBMParameter())
            param = dict(param[0])
            # salt = der_decoder.decode(param['salt'], asn1Spec=univ.OctetString)
            self.param['salt'] = bytes(param['salt']).hex()
            self.param['owf'] = dict(param['owf'])
            self.param['it'] = param['iterationCount']
            self.param['hmac'] = dict(param['mac'])
        except Exception as e:
            pass  # TODO: in cert req message, algorithm parameters isvalue is set to true but it is empty.
            # Have to check


class ProtectionAlgorithm:
    def __init__(self, data):
        self.param = {'obj': data}
        if not data.isValue:
            print('protectionAlg is not set')
        else:
            self.algo = data.getComponentByName('algorithm')
            self.algo = str(self.algo)
            self.param['algo'] = self.algo
            param = data.getComponentByName('parameters')
            if univ.ObjectIdentifier(self.algo) == id_PasswordBasedMac:
                print("Password Based Mac is being used")
            self.pbmp = PBMParameters(param)
            self.param['pbmp'] = self.pbmp.param


class CmpHeader:
    def __init__(self, pkidata):
        self.param = {}
        if not pkidata.isValue:
            raise Exception("PKI header is not present")

        for header_option, header_data in pkidata.items():
            if header_option == 'pvno':
                self.param[header_option] = CmpHeaderPvno(header_data, expected_pvno='cmp2000')

            elif header_option == 'sender' or header_option == 'recipient':
                self.param[header_option] = CmpSenderReciever(header_data,
                                                              mandatory=(header_option == 'sender'))

            elif header_option == 'messageTime':
                self.param[header_option] = MessageTime(header_data)

            elif header_option == 'protectionAlg':
                self.param[header_option] = ProtectionAlgorithm(header_data).param

            elif header_option in ('senderKID', 'recipKID', 'transactionID', 'senderNonce', 'recipNonce'):
                if not header_data.isValue:
                    continue
                self.param[header_option] = bytes(header_data).hex()

            elif header_option == 'freeText':
                if not header_data.isValue:
                    continue
                self.param[header_option] = str(header_data)

            elif header_option == 'generalInfo':
                pass
                # TODO: handle general info

            else:
                print("Header Option {} is not known".format(header_option))

        # print(pprint.pformat(self.header_data))


class CMPBody:
    def __init__(self, pkidata):
        self.param = {}

        if not pkidata.isValue:
            raise Exception("PKI Body is not present")

        for body_option, body_data in pkidata.items():
            print('{}::::\n\n{}'.format(body_option, body_data))
            if body_option == 'ir':
                self.param[body_option] = IR(body_data).param
            elif body_option == 'certConf':
                # print(body_data)
                # for i in body_data:
                #     print(i)
                self.param[body_option] = certstatus(body_data[0]).param  # Only once cert status
        print(self.param)


class certstatus:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('certstatus is not set')
        else:
            for body_option, body_data in dict(data).items():
                if body_option == 'certHash':
                    self.param['certhash'] = bytes(body_data).hex()
                elif body_option == 'certReqId':
                    self.param['certreqid'] = body_data
                elif body_option == 'statusInfo':
                    pass  # TODO: Add check for PKI status. Ignoring for now as dealing with positive case


class IR:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('IR is not set')
        else:
            self.param['cert_request'] = []
            for cert_request in data:  # here data is a list of cert request messages
                self.param['cert_request'].append(CertReqMsg(cert_request).param)


class CertReqMsg:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Cert request message is not set')
        else:
            for option, tdata in data.items():
                if option == 'certReq':
                    self.param['certreq'] = CertReq(tdata).param
                elif option == 'pop':
                    self.param['pop'] = Pop(tdata).param


class Pop:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Cert request is not set')
        else:
            for option, tdata in data.items():
                if option == 'signature':
                    self.param['signature'] = POPOSigningKey(tdata).param


class POPOSigningKey:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Cert request is not set')
        else:
            for option, tdata in data.items():
                if option == 'algorithmIdentifier':
                    self.param['algorithmIdentifier'] = ProtectionAlgorithm(tdata).param
                elif option == 'signature':
                    signature = hex(int(str(tdata), 2))
                    self.param['signature'] = signature[2:] if signature.startswith('0x') else signature
                    self.param['signature'] = self.param['signature'] if (len(self.param['signature']) % 2 == 0) \
                        else '0' + self.param['signature']
                    # self.param['signature'] = convert_hex_to_bin(self.param['signature'])
                    # self.param['signature'] = int(signature, 0)
                elif option == 'poposkInput':
                    pass  # TODO: handle signing key input


class CertReq:
    def __init__(self, data):
        self.param = {'data': der_encoder.encode(data).hex()}
        if not data.isValue:
            print('Cert request is not set')
        else:
            for option, tdata in data.items():
                if option == 'certReqId':
                    self.param['certreqid'] = tdata
                if option == 'certTemplate':
                    self.param['certtemplate'] = CertTemplate(tdata).param


class CertTemplate:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Cert template is not set')
        else:
            for option, tdata in data.items():
                if option == 'subject':
                    self.param['subject'] = Subject(tdata).param
                elif option == 'publicKey':
                    self.param['publickey'] = SubjectPublicKeyinfo(tdata).param


class SubjectPublicKeyinfo:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Subject public key info is not set')
        else:
            for option, tdata in data.items():
                if option == 'algorithm':
                    self.param['algorithm'] = ProtectionAlgorithm(tdata).param
                elif option == 'subjectPublicKey':
                    self.param['subjectPublicKey'] = SubjectPublicKey(tdata).param


class SubjectPublicKey:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Subject public key is not set')
        else:
            public_key = hex(int(str(data), 2))
            public_key = public_key[2:] if public_key.startswith('0x') else public_key
            public_key = convert_hex_to_bin(public_key)
            key = load_der_public_key(public_key)
            self.param['public_key'] = key


class ProtectionData:
    def __init__(self, data):
        self.param = {}
        if not data.isValue:
            print('Subject public key is not set')
        else:
            protectiondata = hex(int(str(data), 2))[2:]
            self.param['protectiondata'] = protectiondata if (len(protectiondata) % 2 == 0) \
                else '0' + protectiondata


def get_packet(data):
    global state_tracker
    print(colored('Decoding DER encoded data using RFC4210 PKIMessage Schema', 'green'))
    decoded_data = der_decoder.decode(data, asn1Spec=rfc4210.PKIMessage())
    print(colored(decoded_data[0].prettyPrint(), 'cyan'))
    protectedpart = rfc4210.ProtectedPart()

    cmp = None
    signing_cert = None
    state_key = None

    for pkitype, pkidata in decoded_data[0].items():
        if pkitype == 'header':
            header = CmpHeader(pkidata)
            protectedpart.setComponentByName('header', pkidata)

            transaction_id = header.param['transactionID']
            if transaction_id not in state_tracker:
                state_tracker[transaction_id] = {'ir_received': False,
                                                 'ip_sent': False,
                                                 'certconf_received': False,
                                                 'pkiconf_sent': False}

        elif pkitype == 'body':
            body = CMPBody(pkidata)
            protectedpart.setComponentByName('infoValue', pkidata)

            if 'ir' in body.param:

                try:
                    if state_tracker[transaction_id]['ir_received']:
                        raise Exception("IR already recieved for transaction ID: {}".format(transaction_id))
                    else:
                        state_tracker[transaction_id]['ir_received'] = True
                    # TODO: instead of erroring out, send an error message
                except KeyError:
                    raise Exception("We shouldnt be here")

                # verifying POP signature
                try:
                    pub_key = body.param['ir']['cert_request'][0]['certreq']['certtemplate']['publickey']['subjectPublicKey']['public_key']
                    signature = body.param['ir']['cert_request'][0]['pop']['signature']['signature']
                    message = body.param['ir']['cert_request'][0]['certreq']['data']

                    signature = bytes.fromhex(signature)
                    message = bytes.fromhex(message)
                    pub_key.verify(signature, message,
                                   padding.PKCS1v15(), hashes.SHA256())
                except Exception as e:
                    print('Verifying POP signature failed')

                # signing part
                # check if requested subject is in cert DB

                recipient = header.param['recipient'].param['directory_name']['rdn_sequence']['one_line_subject']

                if recipient in cert_db:
                    signing_cert = cert_db[recipient]
                else:
                    raise Exception('Couldnt find the recipient "{}" in cert DB.\nCert_DB:{}'.format(recipient,
                                                                                                     pprint.pformat(
                                                                                                         cert_db)))
                subject = body.param['ir']['cert_request'][0]['certreq']['certtemplate']['subject']['rdn_sequence'][
                    'X509_subject']
                pub_key = \
                    body.param['ir']['cert_request'][0]['certreq']['certtemplate']['publickey']['subjectPublicKey'][
                        'public_key']

                cert = sign_certificate_request(subject,
                                                pub_key,
                                                signing_cert['cert_object'],
                                                signing_cert['key_object'])
                # print('blah')
                # print(cert.fingerprint(hashes.SHA256()).hex())
                # print(cert.fingerprint(hashes.SHA1()).hex())
                # print(cert.signature.hex())

                # calculate hash of cert
                # signing_pub_key = signing_cert['cert_object'].public_key()
                # cert_signature = cert.signature
                #
                # hashy = signing_pub_key.recover_data_from_signature(cert_signature, padding.PKCS1v15(), hashes.SHA256())
                # print(hashy.hex())

                # x = hashlib.sha256()
                # x.update(cert.tbs_certificate_bytes)
                # print(x.digest().hex())
                # print(cert.fingerprint(cert.signature_hash_algorithm).hex())

                ip_rep = build_cmp_ip_response(cert, [signing_cert['cert_object']])
                # # print(ip_rep)

                # building body

                s_body = PKIBody()
                rep_msg = s_body['ip']
                rep_msg['caPubs'] = ip_rep['caPubs']
                rep_msg['response'] = ip_rep['response']
                # s_body['ip'] = ip_rep

                s_header = PKIHeader()
                s_header['pvno'] = 2
                s_header['sender'] = header.param['recipient'].param['obj']
                s_header['recipient'] = header.param['sender'].param['obj']

                now = datetime.now()
                temp = useful.GeneralizedTime(now.strftime('%Y%m%d%H%M%SZ'))
                s_header['messageTime'] = str(temp)
                s_header['protectionAlg'] = header.param['protectionAlg']['obj']
                s_header['senderKID'] = str(univ.OctetString(hexValue=header.param['senderKID']))
                s_header['transactionID'] = str(univ.OctetString(hexValue=header.param['transactionID']))
                nonce = str(univ.OctetString(hexValue=uuid.uuid4().hex))
                s_header['senderNonce'] = nonce if not nonce.startswith('0x') else nonce[2:]
                s_header['recipNonce'] = str(univ.OctetString(hexValue=header.param['senderNonce']))

                s_protectedpart = rfc4210.ProtectedPart()
                s_protectedpart.setComponentByName('header', s_header)
                s_protectedpart.setComponentByName('infoValue', s_body)

                # calculating protection data
                encoded_input = der_encoder.encode(s_protectedpart).hex()
                secret = 'testing123'
                hex_secret = convert_str_to_hex(secret)
                hash_input = hex_secret + header.param['protectionAlg']['pbmp'][
                    'salt']  # using same as header values
                for i in range(header.param['protectionAlg']['pbmp']['it']):
                    hash_input = calculate_hash(hash_input)
                protection_data = calculate_hmac(hash_input, encoded_input)
                protection_data = protection_data if (len(protection_data) % 2 == 0) else '0' + protection_data

                s_protection = PKIProtection(univ.BitString(hexValue=protection_data))

                cmp = PKIMessage()
                cmp['header'] = s_header
                cmp['body'] = s_body
                cmp['protection'] = str(s_protection)

                state_key = 'ip_sent'

            if 'certConf' in body.param:
                try:
                    if not state_tracker[transaction_id]['ir_received']:
                        raise Exception("IR is not recieved for transaction ID: {}".format(transaction_id))
                    elif not state_tracker[transaction_id]['ip_sent']:
                        raise Exception("IP is not sent yet for transaction ID: {}".format(transaction_id))
                    else:
                        state_tracker[transaction_id]['certconf_received'] = True
                    # TODO: instead of erroring out, send an error message
                except KeyError:
                    raise Exception("We shouldnt be here")

                s_body = PKIBody()
                rep_msg = s_body['pkiconf']
                temp = rfc4210.PKIConfirmContent(univ.Null(''))
                rep_msg._value = b''
                rep_msg.isValue = True  # TODO: Do this properly
                # s_body.setComponentByName('pkiconf', temp)

                s_header = PKIHeader()
                s_header['pvno'] = 2
                s_header['sender'] = header.param['recipient'].param['obj']
                s_header['recipient'] = header.param['sender'].param['obj']

                now = datetime.now()
                temp = useful.GeneralizedTime(now.strftime('%Y%m%d%H%M%SZ'))
                s_header['messageTime'] = str(temp)
                s_header['protectionAlg'] = header.param['protectionAlg']['obj']
                s_header['senderKID'] = str(univ.OctetString(hexValue=header.param['senderKID']))
                s_header['transactionID'] = str(univ.OctetString(hexValue=header.param['transactionID']))
                nonce = str(univ.OctetString(hexValue=uuid.uuid4().hex))
                s_header['senderNonce'] = nonce if not nonce.startswith('0x') else nonce[2:]
                s_header['recipNonce'] = str(univ.OctetString(hexValue=header.param['senderNonce']))

                s_protectedpart = rfc4210.ProtectedPart()
                s_protectedpart.setComponentByName('header', s_header)
                s_protectedpart.setComponentByName('infoValue', s_body)

                # calculating protection data
                encoded_input = der_encoder.encode(s_protectedpart).hex()
                secret = 'testing123'
                hex_secret = convert_str_to_hex(secret)
                hash_input = hex_secret + header.param['protectionAlg']['pbmp'][
                    'salt']  # using same as header values
                for i in range(header.param['protectionAlg']['pbmp']['it']):
                    hash_input = calculate_hash(hash_input)
                protection_data = calculate_hmac(hash_input, encoded_input)
                protection_data = protection_data if (len(protection_data) % 2 == 0) else '0' + protection_data

                s_protection = PKIProtection(univ.BitString(hexValue=protection_data))

                cmp = PKIMessage()
                cmp['header'] = s_header
                cmp['body'] = s_body
                cmp['protection'] = str(s_protection)

                state_key = 'pkiconf_sent'

        elif pkitype == 'protection' and pkidata.isValue:
            protectiondata = ProtectionData(pkidata).param['protectiondata']

            # verifying protection data
            encoded_input = der_encoder.encode(protectedpart).hex()
            secret = 'testing123'
            hex_secret = convert_str_to_hex(secret)
            hash_input = hex_secret + header.param['protectionAlg']['pbmp']['salt']
            for i in range(header.param['protectionAlg']['pbmp']['it']):
                hash_input = calculate_hash(hash_input)
            protection_data = calculate_hmac(hash_input, encoded_input)
            protection_data = protection_data if (len(protection_data) % 2 == 0) else '0' + protection_data
            if protectiondata != protection_data:
                raise Exception('PKI protection validation failed.'
                                '\nReceived: {}\nCalculated: {}'.format(protectiondata, protection_data))

        elif pkitype == 'extraCerts' and pkidata.isValue:
            continue  # TODO: handle extra certs

    # # signing part
    # # check if requested subject is in cert DB
    #
    # recipient = header.param['recipient'].param['directory_name']['rdn_sequence']['one_line_subject']
    #
    # if recipient in cert_db:
    #      signing_cert = cert_db[recipient]
    # else:
    #     raise Exception('Couldnt find the recipient "{}" in cert DB.\nCert_DB:{}'.format(recipient,
    #                                                                                      pprint.pformat(cert_db)))
    # subject = body.param['ir']['cert_request'][0]['certreq']['certtemplate']['subject']['rdn_sequence']['X509_subject']
    # pub_key = \
    #     body.param['ir']['cert_request'][0]['certreq']['certtemplate']['publickey']['subjectPublicKey']['public_key']
    #
    # cert = sign_certificate_request(subject,
    #                                 pub_key,
    #                                 signing_cert['cert_object'],
    #                                 signing_cert['key_object'])
    # # print('blah')
    # # print(cert.fingerprint(hashes.SHA256()).hex())
    # # print(cert.fingerprint(hashes.SHA1()).hex())
    # # print(cert.signature.hex())
    #
    # # calculate hash of cert
    # # signing_pub_key = signing_cert['cert_object'].public_key()
    # # cert_signature = cert.signature
    # #
    # # hashy = signing_pub_key.recover_data_from_signature(cert_signature, padding.PKCS1v15(), hashes.SHA256())
    # # print(hashy.hex())
    #
    # # x = hashlib.sha256()
    # # x.update(cert.tbs_certificate_bytes)
    # # print(x.digest().hex())
    # # print(cert.fingerprint(cert.signature_hash_algorithm).hex())
    #
    # ip_rep = build_cmp_ip_response(cert, [signing_cert['cert_object']])
    # # # print(ip_rep)
    #
    #
    #
    # # building body
    #
    # s_body = PKIBody()
    # rep_msg = s_body['ip']
    # rep_msg['caPubs'] = ip_rep['caPubs']
    # rep_msg['response'] = ip_rep['response']
    # # s_body['ip'] = ip_rep
    #
    # s_header = PKIHeader()
    # s_header['pvno'] = 2
    # s_header['sender'] = header.param['recipient'].param['obj']
    # s_header['recipient'] = header.param['sender'].param['obj']
    #
    # now = datetime.now()
    # temp = useful.GeneralizedTime(now.strftime('%Y%m%d%H%M%SZ'))
    # # k = s_header
    # # k['messageTime'] = temp
    # s_header['messageTime'] = str(temp)
    # s_header['protectionAlg'] = header.param['protectionAlg']['obj']
    # s_header['senderKID'] = str(univ.OctetString(hexValue=header.param['senderKID']))
    # s_header['transactionID'] = str(univ.OctetString(hexValue=header.param['transactionID']))
    # nonce = str(univ.OctetString(hexValue=uuid.uuid4().hex))
    # s_header['senderNonce'] = nonce if not nonce.startswith('0x') else nonce[2:]
    # s_header['recipNonce'] = str(univ.OctetString(hexValue=header.param['senderNonce']))
    #
    # s_protectedpart = rfc4210.ProtectedPart()
    # s_protectedpart.setComponentByName('header', s_header)
    # s_protectedpart.setComponentByName('infoValue', s_body)
    #
    # # calculating protection data
    # encoded_input = der_encoder.encode(s_protectedpart).hex()
    # secret = 'testing123'
    # hex_secret = convert_str_to_hex(secret)
    # hash_input = hex_secret + header.param['protectionAlg']['pbmp']['salt']  # using same as header values
    # for i in range(header.param['protectionAlg']['pbmp']['it']):
    #     hash_input = calculate_hash(hash_input)
    # protection_data = calculate_hmac(hash_input, encoded_input)
    # protection_data = protection_data if (len(protection_data) % 2 == 0) else '0' + protection_data
    #
    # s_protection = PKIProtection(univ.BitString(hexValue=protection_data))
    #
    # cmp = PKIMessage()
    # cmp['header'] = s_header
    # cmp['body'] = s_body
    # cmp['protection'] = str(s_protection)

    if cmp:
        encoded_data = der_encoder.encode(cmp)
        state_tracker[transaction_id][state_key] = True
        return encoded_data


def sign_certificate_request(subject, public_key, ca_cert, private_ca_key):
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)  # 30 days validity
    ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
                x509.KeyUsage(digital_signature=True,
                              content_commitment=False,
                              key_encipherment=True,
                              data_encipherment=False,
                              key_agreement=False,
                              key_cert_sign=True,
                              crl_sign=False,
                              encipher_only=False,
                              decipher_only=False), critical=True
    ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                       x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True    # TODO: EKU should be set as per ref ID.
    ).sign(private_ca_key, hashes.SHA256())  # Sign our certificate with our private key

    return cert


def build_cmp_ip_response(cert, ca_cert_list=None, req_id=0, status=0):
    ip_rep = rfc4210.CertRepMessage()

    if ca_cert_list:
        for asn1_cert in build_ca_pubs(ca_cert_list):
            ip_rep['caPubs'].append(asn1_cert)

    pki_status = rfc4210.PKIStatus(status)
    pki_status_info = rfc4210.PKIStatusInfo()
    pki_status_info.setComponentByName('status', pki_status)

    cert_respose = rfc4210.CertResponse()
    cert_respose.setComponentByName('certReqId', req_id)
    cert_respose.setComponentByName('status', pki_status_info)

    asn1_cert = build_asn1_CMPcertificate(cert)
    certorenccert = rfc4210.CertOrEncCert()
    cmpcert = certorenccert['certificate']

    # TODO: subtype is creating an issue. Below solution is from https://github.com/etingof/pyasn1/issues/183.
    #  Figure out if there is a better way

    cmpcert.setComponentByName('tbsCertificate', asn1_cert['tbsCertificate'])
    cmpcert.setComponentByName('signatureAlgorithm', asn1_cert['signatureAlgorithm'])
    cmpcert.setComponentByName('signatureValue', asn1_cert['signatureValue'])
    # cmpcert.setComponentByName('signatureValue', asn1_cert['signature'])
    # cmpcert.setComponentByName('certificate', asn1_cert)
    # certorenccert = CertOrEncCert()
    # certorenccert.setComponentByName('certificate', asn1_cert)

    certkeypair = rfc4210.CertifiedKeyPair()
    certkeypair.setComponentByName('certOrEncCert', certorenccert)

    cert_respose.setComponentByName('certifiedKeyPair', certkeypair)

    # ip_rep.setComponentByName('response', cert_respose)
    ip_rep['response'].append(cert_respose)

    return ip_rep


# class CMPCertificate(rfc3280.Certificate):
#     pass
#
#
# class CertOrEncCert(univ.Choice):
#     """
#      CertOrEncCert ::= CHOICE {
#          certificate     [0] CMPCertificate,
#          encryptedCert   [1] EncryptedValue
#      }
#     """
#     componentType = namedtype.NamedTypes(
#         namedtype.NamedType('certificate', CMPCertificate().subtype(explicitTag=tag.Tag(tag.tagClassContext,
#                                                                                         tag.tagFormatConstructed, 0))),
#         namedtype.NamedType('encryptedCert', rfc2511.EncryptedValue().
#                             subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
#     )


def build_ca_pubs(ca_cert_list=None):
    # if ca_cert_list:
    #     for ca_cert in ca_cert_list:
    #         cmpcert = rfc4210.CMPCertificate()
    #         cmpcert.setComponentByName()
    return [build_asn1_CMPcertificate(ca_cert) for ca_cert in ca_cert_list] if ca_cert_list else []


def build_asn1_CMPcertificate(cert):
    tbs_cert_encoded = cert.tbs_certificate_bytes
    tbs_cert_decoded = der_decoder.decode(tbs_cert_encoded, asn1Spec=rfc3280.TBSCertificate())[0]
    sign_algo_id = univ.ObjectIdentifier(cert.signature_algorithm_oid.dotted_string)
    signature_bit_string = univ.BitString(hexValue=cert.signature.hex())
    # asn1_cert = rfc3280.Certificate()
    asn1_cert = rfc4210.CMPCertificate()
    # asn1_cert = CMPCertificate()
    asn1_cert.setComponentByName('tbsCertificate', tbs_cert_decoded)

    algoid = rfc3280.AlgorithmIdentifier()
    algoid.setComponentByName('algorithm', sign_algo_id)
    # algoid.setComponentByName('parameters', '0x0500')
    asn1_cert.setComponentByName('signatureAlgorithm', algoid)
    asn1_cert.setComponentByName('signatureValue', signature_bit_string)
    return asn1_cert


def build_asn1_certificate(cert):
    tbs_cert_encoded = cert.tbs_certificate_bytes
    tbs_cert_decoded = der_decoder.decode(tbs_cert_encoded, asn1Spec=rfc3280.TBSCertificate())[0]
    sign_algo_id = univ.ObjectIdentifier(cert.signature_algorithm_oid.dotted_string)
    signature_bit_string = univ.BitString(hexValue=cert.signature.hex())
    asn1_cert = rfc3280.Certificate()
    asn1_cert.setComponentByName('tbsCertificate', tbs_cert_decoded)

    algoid = rfc3280.AlgorithmIdentifier()
    algoid.setComponentByName('algorithm', sign_algo_id)
    asn1_cert.setComponentByName('signature', signature_bit_string)
    return asn1_cert


def parse_cert_parent_folder(folder_path, update_db=False):
    main_folder = pathlib.Path(folder_path)
    if not main_folder.exists():
        raise Exception('Cert folder "{}" does not exists'.format(folder_path))
    for sub_folder in main_folder.iterdir():
        if sub_folder.is_dir():
            parse_cert_folder(str(sub_folder), update_db=update_db)


def parse_cert_folder(folder_path, update_db=False):
    cert_folder = pathlib.Path(folder_path)
    sub_folders = [str(x.name) for x in cert_folder.iterdir() if x.is_dir()]
    if 'certs' not in sub_folders or 'newcerts' not in sub_folders or 'private' not in sub_folders:
        raise Exception("Cert folder '{}' is not per standards. certs/newcerts/private "
                        "folder is missing".format(folder_path))
    cacert = cert_folder.joinpath('certs').joinpath('ca.cert.pem')
    priv_key = cert_folder.joinpath('private').joinpath('ca.key.pem')
    parse_cert(str(cacert), update_db=update_db, key_path=str(priv_key))


def parse_cert(cert_path, update_db=False, key_path=None, key_passphrase=None):
    with open(cert_path, "rb") as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    subject = cert.subject
    subject_string = subject.rfc4514_string()
    subject_string = subject_string.split(',')
    subject_string.reverse()
    subject_string = '/' + '/'.join(subject_string)
    key = None
    if key_path:
        with open(key_path, "rb") as f:
            key_data = f.read()
        key = load_pem_private_key(key_data, password=key_passphrase)
    if update_db:
        temp_db = {'cert_object': cert}
        if key_path:
            temp_db['key_object'] = key
        global cert_db
        cert_db[subject_string] = temp_db
    return cert, key, subject_string


class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""


def print_cert_db():
    print("\nBelow CA certs are available in the DB.\n")
    count = 1
    for temp_db in cert_db.values():
        print("{}:  {} signed by {}".format(count, temp_db['cert_object'].subject.rfc4514_string(),
                                            temp_db['cert_object'].issuer.rfc4514_string()))
        count += 1


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Remmina_Convertor')
    requiredNamed = parser.add_argument_group('required arguments')

    requiredNamed.add_argument('-f', '--certificate_folder_path',
                               help='Folder where cert folders are stored',
                               required=False,
                               default='/home/lonewolf/PycharmProjects/cmp/certs/')
    args = parser.parse_args()

    while True:
        parse_cert_parent_folder(args.certificate_folder_path, update_db=True)
        print_cert_db()
        user_input = get_input('\nPress\n1 to start CMP server with above CAs\n2 to add CAs using cert builder\ninput',
                               typecast_to=str, choices=['1', '2'], sanity_limit=5)
        if user_input == '1':
            break
        else:
            create_ca_cert(args.certificate_folder_path)

    server = ThreadedHTTPServer(('localhost', PORT), MyHandler)
    try:
        # print('Started http server')
        print(colored('Started Multi threaded HTTP server on port {}.\n'
                      'Waiting for connections'.format(PORT), 'green'))
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()


# with open("/home/lonewolf/Downloads/cert.der", "rb") as f:
#     cert = Certificate.load(f.read())
#
# n = cert.public_key.native["public_key"]["modulus"]
# e = cert.public_key.native["public_key"]["public_exponent"]
#
# print("{:#x}".format(n))    # prints the modulus (hexadecimal)
# print("{:#x}".format(e))    # same, for the public exponent

# # rdn_sequence = RDNSequence()
    # # rdn_sequence.append(rdn)
    # # rdn_sequence.append(rdn)
    # # general_name = GeneralName()
    # # general_name['directoryName'][''] = rdn_sequence
    # # print(general_name.prettyPrint())
    # pkiheader = rfc4210.PKIHeader()
    # pkiheader.setComponentByName('pvno', 'cmp2000')
    #
    # attr_type_and_value = AttributeTypeAndValue()
    # attr_type_and_value['type'] = id_at_commonName
    # attr_type_and_value['value'] = der_encoder.encode(char.UTF8String('lte_3065_sample_ra'))
    #
    # rdn = RelativeDistinguishedName()
    # rdn.append(attr_type_and_value)
    # rdn_sequence = RDNSequence()
    # general_name = GeneralName()
    # general_name['directoryName'][''] = rdn_sequence
    # pkiheader.setComponentByName('sender', general_name)
    # rdn_sequence = RDNSequence()
    # rdn_sequence.append(rdn)
    # rdn_sequence.append(rdn)
    # general_name = GeneralName()
    # general_name['directoryName'][''] = rdn_sequence
    # pkiheader.setComponentByName('recipient', general_name)
    # pkiheader.setComponentByName('senderKID', der_encoder.encode(univ.OctetString(hexValue='3134323532')))
    # pkiheader.setComponentByName('transactionID',
    #                              der_encoder.encode(univ.OctetString(hexValue='c062375c017e94864c272d6353b7e578')))
    # pkiheader.setComponentByName('senderNonce',
    #                              der_encoder.encode(univ.OctetString(hexValue='2a72988e822e40674dc639c28e36985f')))
    # encoded_data = der_encoder.encode(pkiheader)
    # return encoded_data
#
# substrate = pem.readPemFromFile(open('/home/lonewolf/Downloads/www-google-com.pem'))
# cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
# print(cert.prettyPrint())