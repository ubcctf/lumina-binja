from binaryninja import *
from binaryninja.log import Logger

from lumina_structs import *

import socket, ssl

from .sig.x86 import X86

arch_mapping = {'x86_64': X86, 'x86': X86}
log = Logger(0, 'Lumina')


class LuminaClient:
    def __init__(self) -> None:
        self.socket = None
        self.reconnect()

    def is_valid(self, bv: BinaryView, func: Function = None):
        return self.socket and (func.arch.name in arch_mapping if func else True)
    
    def send_and_recv_rpc(self, code: RPC_TYPE, **kwargs):
        try:
            payload = rpc_message_build(code, **kwargs)
            log.log_debug('Sending ' + str(code) + ' command (' + str(payload) + ')')
            self.socket.send(payload)

            packet, message = rpc_message_parse(self.socket)
            log.log_debug('Received ' + str(packet) + 'Message: ' + str(message) + '')
            return packet, message
        except ConnectionError:
            log.log_warn('Disconnected from the Lumina server. Reconnecting...')
            self.reconnect()


    def reconnect(self, *_):  #ignore additional args
        s = Settings()
        try:
            if self.socket:  #reset connection
                self.socket.close()

            host = s.get_string('lumina.host'), int(s.get_string('lumina.port'))

            self.socket = socket.socket()
            self.socket.connect(host)

            cert = s.get_string('lumina.cert')
            if cert:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cert)
                self.socket = context.wrap_socket(self.socket, server_hostname=host[0])

            #TODO reverse hexrays id and watermark?
            try:
                keypath = s.get_string('lumina.key')
                if keypath:
                    with open(key, 'rb') as kf:
                        key = kf.read()
                else:
                    key = b''
            except OSError:
                log.log_warn('Lumina key file path is invalid, ignoring...')
                key = b''


            if(self.send_and_recv_rpc(RPC_TYPE.RPC_HELO, protocol=2, hexrays_license=key, hexrays_id=0, watermark=0, field_0x36=0)[0].code != RPC_TYPE.RPC_OK):
                raise ConnectionError('Handshake failed')

            log.log_info('Connection to Lumina server ' +  host[0] + ':' + str(host[1]) + ' (TLS: ' + str(bool(cert)) + ') succeeded.')
        except Exception as e:
            if self.socket:  #if we got an error after opening the socket, close it
                self.socket.close()
            self.socket = None

            log.log_alert('Connection to Lumina server failed (' + (str(e) if type(e) != ValueError else 'invalid port') + '). Please check your configuration.')

    def pull_all_mds(self, bv: BinaryView):
        pass

    def push_all_mds(self, bv: BinaryView):
        pass

    def pull_function_md(self, bv: BinaryView, func: Function):
        gen = arch_mapping[func.arch.name](bv) #guaranteed mapped since otherwise is_valid would fail

        #TODO pop up saying "pulling function metadata..."
        sig = gen.calc_func_metadata(func)[0]

        self.send_and_recv_rpc(RPC_TYPE.PULL_MD, flags=(1 if func.arch.address_size == 8 else 0), ukn_list=[0], funcInfos=[{'signature':sig}])

        pass

    def push_function_md(self, bv: BinaryView, func: Function):
        pass