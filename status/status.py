import socket
import fcntl
import struct
import time
import logging
from select import select
import sys
import argparse
import _thread
from itertools import chain
from queue import Queue
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.responses import FileResponse
import uvicorn


def hexdump_lines(data):
    '''Utility function to make a hex dump of a bytes-like object.'''
    for index in range(0, len(data), 16):
        line_data = data[index:index+16]
        yield '%06X  %-47s  %-16s' % (index, ' '.join(('%02X' % i) for i in line_data), ''.join((chr(i) if 32 <= i < 127 else '.') for i in line_data))


class SynthesizerStatus:

    def __init__(self, interface):
        self.interface = interface
        self.socket = None
        self.macaddr = None
        self.node = 254
        self.network = b'\xFF\xF0'
        self.synthesizerlist = {}
        self.queue = Queue(maxsize=0)
        self.current_transaction_ids = []
        self.transaction_id = 32767
        self.app = FastAPI()
        self.lastmessage = bytearray(b'\x00\x00\x00')
        self.synthdata = {'status': {},
                          'couplings': {},
                          'trityl': {},
                          'model': {},
                          }
        self.timeout = time.monotonic() + 0.1
        self.lastdata = {}
        self.bases = {1: 'A',
                      2: 'G',
                      4: 'C',
                      8: 'T',
                      16: '5',
                      32: '6',
                      64: '7',
                      128: '8'}

    def initialize(self):
        self.socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.socket.bind((self.interface, 0))
        self.macaddr = (fcntl.ioctl(self.socket.fileno(), 0x8927,  struct.pack(
            '256s', bytes(self.interface, 'utf-8')[:15])))[18:24]

        self.find_synthesizers()

        # get an unused EtherTalk node id (not sure if this is needed, if the network doesn't matter. Just assume statup range maybe.)
        '''now = time.monotonic() + 0.2
        send_repeat = 0

        print('Getting Network Number', end='', flush=True)
        while True:
            if now < time.monotonic():
                print('.', end='', flush=True)
                for x in range(256):
                    def aarp_request():
                        return (
                            b'\x09\x00\x07\xff\xff\xff'
                            + self.macaddr
                            + b'\x00\x24'
                            + b'\xaa\xaa\x03\x00\x00\x00\x80\xf3\x00\x01\x80\x9b\x06\x04\x00\x03'
                            + self.macaddr
                            + b'\x00'
                            + self.network
                            + int(x).to_bytes(1, 'big')
                            + b'\x00\x00\x00\x00\x00\x00'
                            + b'\x00'
                            + self.network
                            + int(x).to_bytes(1, 'big')
                        )
                    rlist, wlist, xlist = select((), (self.socket,), (), 0.2)
                    if self.socket in wlist:
                        self.socket.send(aarp_request())
                    now = time.monotonic() + 0.1
                    if self.socket in rlist:
                        data, sender_addr = self.socket.recvfrom(65565)
                        if data[17:22] == bytearray(b'\x00\x00\x00\x80\xf3') and data[29] == 2:
                            send_repeat = 0
                            self.network = (int.from_bytes(
                                self.network, 'big') + 1).to_bytes(2, 'big')
                send_repeat += 1
                if send_repeat > 4:
                    print(' Found:', int.from_bytes(self.network, 'big'))
                    break'''

    def send(self):
        if self.queue.empty() != True and time.monotonic() > self.timeout:
            self.socket.send(self.queue.get())
            self.timeout = time.monotonic() + 0.1

    def receive(self):
        data, sender_addr = self.socket.recvfrom(65507)
        self.lastmessage = bytearray(data)
        self.parse_answer(data)

    def find_synthesizers(self):
        self.synthesizerlist = {}
        print('Searching for Synthesizers')
        for x in range(7):
            def nbp_lkup():
                return (
                    b'\x09\x00\x07\xff\xff\xff'
                    + self.macaddr
                    + b'\x00\x30'
                    + b'\xaa\xaa'
                    + b'\x03\x08\x00\x07\x80\x9b\x00\x28\x00\x00\x00\x00'
                    + self.network
                    + b'\xff\xfe'
                    + b'\x02\xfd\x02\x21'
                    + int(x).to_bytes(1, 'big')
                    + self.network
                    + b'\xfe\xfd\x00\x01\x3d'
                    + b'\x0f\x41\x42\x49\x20\x53\x79\x6e\x74\x68\x65\x73\x69\x7a\x65\x72\x01\x2a'
                )
            self.queue.put(nbp_lkup())

    def Modl(self, synthesizer_id):
        self.queue.put(
            int(self.synthesizerlist[synthesizer_id]['mac']).to_bytes(6, 'big')
            + self.macaddr
            + b'\x00\x29\xaa\xaa'
            + b'\x03\x08\x00\x07\x80\x9b\x00\x21\x00\x00'
            + int(self.synthesizerlist[synthesizer_id]
                  ['net']).to_bytes(2, 'big')
            + self.network
            + int(self.synthesizerlist[synthesizer_id]
                  ['node']).to_bytes(1, 'big')
            + int(self.node).to_bytes(1, 'big')
            + int(self.synthesizerlist[synthesizer_id]
                  ['port']).to_bytes(1, 'big')
            + b'\xfb\x5c\x40\x00'
            + int(self.transaction_id).to_bytes(2, 'big')
            + b'\x4d\x6f\x64\x6c\x00\x00\x00\x00\x00\x00\x00\x00\x50\x41\x53\x53'
        )
        self.current_transaction_ids.append(self.transaction_id)
        self.transaction_id += 1
        if self.transaction_id >= 65535:
            self.transaction_id = 0

    def Stat(self, synthesizer_id):
        self.queue.put(
            int(self.synthesizerlist[synthesizer_id]['mac']).to_bytes(6, 'big')
            + self.macaddr
            + b'\x00\x29\xaa\xaa'
            + b'\x03\x08\x00\x07\x80\x9b\x00\x21\x00\x00'
            + int(self.synthesizerlist[synthesizer_id]
                  ['net']).to_bytes(2, 'big')
            + self.network
            + int(self.synthesizerlist[synthesizer_id]
                  ['node']).to_bytes(1, 'big')
            + int(self.node).to_bytes(1, 'big')
            + int(self.synthesizerlist[synthesizer_id]
                  ['port']).to_bytes(1, 'big')
            + b'\xfb\x5c\x40\x00'
            + int(self.transaction_id).to_bytes(2, 'big')
            + b'\x53\x74\x61\x74\x00\x00\x00\x00\x00\x00\x00\x00\x50\x41\x53\x53'
        )
        self.current_transaction_ids.append(self.transaction_id)
        self.transaction_id += 1
        if self.transaction_id >= 65535:
            self.transaction_id = 0

    def NMon(self, synthesizer_id, column_number):
        self.queue.put(
            int(self.synthesizerlist[synthesizer_id]['mac']).to_bytes(6, 'big')
            + self.macaddr
            + b'\x00\x29\xaa\xaa'
            + b'\x03\x08\x00\x07\x80\x9b\x00\x21\x00\x00'
            + int(self.synthesizerlist[synthesizer_id]
                  ['net']).to_bytes(2, 'big')
            + self.network
            + int(self.synthesizerlist[synthesizer_id]
                  ['node']).to_bytes(1, 'big')
            + int(self.node).to_bytes(1, 'big')
            + int(self.synthesizerlist[synthesizer_id]
                  ['port']).to_bytes(1, 'big')
            + b'\xf8\x5c\x40\x00'
            + int(self.transaction_id).to_bytes(2, 'big')
            + b'\x4e\x4d\x6f\x6e\x00'
            + int(column_number).to_bytes(1, 'big')
            + b'\x00\x00\x00\x00\x00\x00\x50\x41\x53\x53'
        )
        self.current_transaction_ids.append(self.transaction_id)
        self.transaction_id += 1
        if self.transaction_id >= 65535:
            self.transaction_id = 0

    def MonD(self, synthesizer_id, column_number, last_coupling):
        self.queue.put(
            int(self.synthesizerlist[synthesizer_id]['mac']).to_bytes(6, 'big')
            + self.macaddr
            + b'\x00\x29\xaa\xaa'
            + b'\x03\x08\x00\x07\x80\x9b\x00\x21\x00\x00'
            + int(self.synthesizerlist[synthesizer_id]
                  ['net']).to_bytes(2, 'big')
            + self.network
            + int(self.synthesizerlist[synthesizer_id]
                  ['node']).to_bytes(1, 'big')
            + int(self.node).to_bytes(1, 'big')
            + int(self.synthesizerlist[synthesizer_id]
                  ['port']).to_bytes(1, 'big')
            + b'\xfb\x5c\x40\x00'
            + int(self.transaction_id).to_bytes(2, 'big')
            + b'\x4d\x6f\x6e\x44\x00'
            + int(column_number).to_bytes(1, 'big')
            + b'\x00\x00\x00\x01\x00'
            + int(last_coupling).to_bytes(1, 'big')
            + b'\x50\x41\x53\x53'
        )
        self.current_transaction_ids.append(self.transaction_id)
        self.transaction_id += 1
        if self.transaction_id >= 65535:
            self.transaction_id = 0

    def parse_answer(self, data):
        print('\n'.join(chain(('From Synthesizer:',), (line for line in hexdump_lines(
            data)))))

        if data[:6] != self.macaddr or data[:6] == data[6:12] or data[14:16] != b'\xaa\xaa' or data[16:22] == b'\x03\x00\x00\x00\x80\xF3':
            return

        for x in self.current_transaction_ids:
            if x < self.transaction_id - 10:
                self.current_transaction_ids.remove(x)

        if data[32] == 0xfd and data[34] == 0x02 and data[35] == 0x31:
            self.synthesizerlist = {}
            smac = int.from_bytes(data[6:12], 'big')
            snet = int.from_bytes(data[37:39], 'big')
            snode = data[39]
            sport = data[40]
            objectoffset = 43 + data[42]
            sname = data[43:objectoffset].decode('ascii')
            typeoffset = objectoffset + 1 + \
                data[objectoffset]
            stype = data[objectoffset + 1:typeoffset].decode('ascii')
            zoneoffset = typeoffset + 1 + \
                data[typeoffset]
            szone = data[typeoffset + 1: zoneoffset].decode('ascii')
            self.synthesizerlist.update(
                {sname: {'name': sname, 'mac': smac, 'node': snode, 'net': snet, 'port': sport, 'type': stype, 'zone': szone}})
            print('Found ', sname)
            print(self.synthesizerlist)
            return

        d_ddptype = data[34]            # should be 0x5c if from Synthesizer
        d_rx_tx = data[35]              # 0x40 for command, 0x80 for answer
        # same for sent command and answer to that command (3-byte Number)
        d_transactionid = int.from_bytes(data[37:39], 'big')
        print(data[39:43].decode('ascii'))
        print(self.current_transaction_ids)
        print(d_transactionid)
        print(d_rx_tx)
        print(d_ddptype)

        # ASCII encoded 4 character function name
        d_functionname = data[39:43].decode('ascii')

        if d_ddptype == 0x5c and d_rx_tx == 0x80 and d_transactionid in self.current_transaction_ids:
            self.current_transaction_ids.remove(d_transactionid)

            if d_functionname == 'Modl':
                self.synthdata['model'] = {'name': data[63:80].decode('ascii'),
                                           'modelno': int.from_bytes(data[55:57], 'big'),
                                           'basecount': data[58],
                                           'columncount': data[60],
                                           'romversion': data[62],
                                           'tritylmonitor': data[96]}
                print(self.synthdata['model'])
                return

            if d_functionname == 'Stat':
                startbyte = 68
                self.synthdata['status'] = {}
                for x in range(self.synthdata['model']['columncount']):
                    self.synthdata['status']['column' + str(x + 1)] = {'total': data[startbyte + 2],
                                                                       'left': data[startbyte + 4],
                                                                       'step': data[startbyte + 6],
                                                                       'functionnumber': data[startbyte + 8],
                                                                       'functiontext': data[startbyte + 9: startbyte + 24].decode('ascii').replace('\u0000', ''),
                                                                       'timestep': int.from_bytes(data[startbyte + 25: startbyte + 27], 'big'),
                                                                       'timestepleft': int.from_bytes(data[startbyte + 27: startbyte + 29], 'big')
                                                                       }
                    startbyte += 38
                return

            if d_functionname == 'NMon':
                self.synthdata['couplings'].update({data[44]: data[56]})
                return
            
            if d_functionname == 'MonD':
                couplings = data[50]
                if couplings > 0x00:
                    offset = 56
                    self.synthdata['trityl'].update({data[44]: {}})
                    for x in range(couplings):
                        self.synthdata['trityl'][data[44]][data[offset]] = {'base': self.bases[data[offset + 2]],
                                                                                  'raw': int.from_bytes(data[offset + 3:offset + 5], 'big')}
                        offset += 6
                else:
                    self.synthdata['trityl'].update({data[44]: {}})
                return

    def status(self):
        while True:
            rlist, wlist, xlist = select(
                (self.socket,), (self.socket,), (), 10)
            if self.socket in rlist:
                self.receive()
            if self.socket in wlist:
                self.send()

    def run(self):

        _thread.start_new_thread(self.status, ())

        @self.app.get("/")
        async def root():
            return FileResponse('./monitor.html')
        
        @self.app.get("/chicago.ttf")
        async def root():
            return FileResponse('./chicago.ttf')

        @self.app.get("/sfind")
        async def sfind():
            self.find_synthesizers()
            timeout = time.monotonic() + 5
            while True:
                if self.synthesizerlist != {} or time.monotonic() > timeout:
                    break
            if time.monotonic() > timeout:
                return {'none': {'name': 'No Synthesizer found!'}}
            else:
                return self.synthesizerlist
            
        @self.app.get("/sget")
        async def sget():
            return self.synthesizerlist

        @self.app.get("/modl/{synthesizer_name}")
        async def smodl(synthesizer_name):
            comp = self.synthdata['model']
            self.Modl(self.synthesizerlist[synthesizer_name]['name'])
            timeout = time.monotonic() + 5
            while True:
                if self.synthdata['model'] != comp or time.monotonic() > timeout:
                    break
            return self.synthdata['model']

        @self.app.get("/stat/{synthesizer_name}")
        async def sstat(synthesizer_name):
            if self.synthdata['model'] == {}:
                self.Modl(self.synthesizerlist[synthesizer_name]['name'])
                timeout = time.monotonic() + 5
                while True:
                  if self.synthdata['model'] != None or time.monotonic() > timeout:
                    break
            else:
                self.Stat(self.synthesizerlist[synthesizer_name]['name'])
                for x in range(self.synthdata['model']['columncount']):
                    self.NMon(synthesizer_name, (x + 1))
                    if self.lastdata != self.synthdata['couplings']:
                        if self.synthdata['couplings'][x+1] != None:
                            for x in range(self.synthdata['model']['columncount']):
                                self.MonD(synthesizer_name, (x + 1), self.synthdata['couplings'][x+1])
                            self.lastdata = self.synthdata['couplings']
                return self.synthdata

        uvicorn.run(self.app, port=80, host='0.0.0.0')


def main(argv):

    parser = argparse.ArgumentParser(
        description='ABI Oligo Synthesizer Status Monitor Daemon')
    parser.add_argument('--interface', '-i', metavar='INTERFACE', required=True,
                        help='ethernet Interface to connect to ABI Oligo Synthesizer')
    args = parser.parse_args(argv[1:])

    daemon = SynthesizerStatus(args.interface)
    daemon.initialize()
    daemon.run()


if __name__ == '__main__':
    sys.exit(main(sys.argv))
