from itertools import chain
import fcntl
import logging
import os
import select
import socket
import struct
import time
from queue import Queue

from ..util import hexdump_lines, TashTalkReceiver, TashTalkTransmitter, NodeIdSet

class EtherTalkDaemon:

  def __init__(self, serial_obj, interface):
    self.interface = interface
    self.serial_obj = serial_obj
    self.receiver = None
    self.sender = None
    self.socket = None
    self.sender_id = None
    self.node_id_set = None
    self.macaddr = None
    self.bridge_lt_nodelist = []
    self.aarp_table = {255: { 'hw': b'\x09\x00\x07\xff\xff\xff', 'net': b'\x00\x00' }}
    self.bridge_net = b'\xff\x00'
    self.etqueue = Queue(maxsize = 0)
    self.ltqueue = Queue(maxsize = 0)

  def initialize(self):
    '''Set up the serial and socket connections the daemon will use.'''

    self.receiver = TashTalkReceiver(self.serial_obj)
    self.sender = TashTalkTransmitter(self.serial_obj)
    self.sender.initialize()

    # setup socket to listen to. a macvtap device works well for now
    self.socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))#socket.htons(0x0003))
    self.socket.bind((self.interface, 0))

    self.sender_id = struct.pack('>L', os.getpid())
    self.node_id_set = NodeIdSet(self.sender)
    self.macaddr = (fcntl.ioctl(self.socket.fileno(), 0x8927,  struct.pack(
        '256s', bytes(self.interface, 'utf-8')[:15])))[18:24]
    logging.info('Our MAC is: ')
    logging.info(self.macaddr)

    # get an unused LocalTalk node id
    now = time.monotonic() + 0.2
    send_repeat = 0
 
    # get an unused EtherTalk network
    now = time.monotonic() + 0.1
    send_repeat = 0

    print('Getting Network Number', end='', flush=True)
    '''while True:
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
              + self.bridge_net
              + int(x).to_bytes(1, 'big')
              + b'\x00\x00\x00\x00\x00\x00'
              + b'\x00'
              + self.bridge_net
              + int(x).to_bytes(1, 'big')
              )
            self.socket.send(aarp_request())
            now = time.monotonic() + 0.1
        rlist, wlist, xlist = select.select((self.receiver, self.socket), (), (), 0.2)
        if self.socket in rlist: 
          data, sender_addr = self.socket.recvfrom(65565)
          if data[17:22] == bytearray(b'\x00\x00\x00\x80\xf3') and data[29] == 2:
            send_repeat = 0
            self.bridge_net = (int.from_bytes(self.bridge_net, 'big') + 1).to_bytes(2, 'big')
        send_repeat += 1
        if send_repeat > 4:
          print(' Found:', int.from_bytes(self.bridge_net, 'big'))
          break'''
  	
  def service_tashtalk(self):
    '''Called when there is data from TashTalk that could finish one or more frames.'''
    for frame in self.receiver.get_frames():

      frame_dest = frame[0]
      frame_src = frame[1]
      frame_type = frame[2]

      if frame_type in (0x84, 0x85):
        logging.debug('not retransmitting RTS/CTS frame')
        continue

      if frame_type == 0x81 and frame_dest in self.node_id_set:
        logging.debug(
            'not retransmitting ENQ frame that TashTalk has already responded to')
        continue
      
      logging.info('\n'.join(chain(('received LocalTalk datagram from %s:' % str(frame_src),),
                                   (line for line in hexdump_lines(frame))))) 

      if not (frame_type == 0x81 or frame_type == 0x82 or frame_type == 0x84 or frame_type == 0x85):
        
        if not frame_src in self.bridge_lt_nodelist:
          self.bridge_lt_nodelist.append(frame_src)

          for x in self.aarp_table:
            def aarp_request():
              return (
              self.aarp_table.get(x)['hw']
              + self.macaddr
              + b'\x00\x24'
              + b'\xaa\xaa\x03\x00\x00\x00\x80\xf3\x00\x01\x80\x9b\x06\x04\x00\x01'
              + self.macaddr
              + b'\x00'
              + self.bridge_net
              + int(frame_src).to_bytes(1, 'big')
              + self.aarp_table.get(x)['hw']
              + b'\x00'
              + self.aarp_table.get(x)['net']
              + int(x).to_bytes(1, 'big')
              )
            self.etqueue.put(aarp_request())
          
        if frame_type == 0x01:
          ddp_type = frame[7]

        if frame_type == 0x02:
          ddp_type = frame[15]

        hw_dest = self.aarp_table.get(frame_dest, self.aarp_table.get(255))['hw']
        frame_header = b''
        frame_offset = 3

        if frame_type == 0x01:
          frame_header = (
             int(3 + len(frame[3:])).to_bytes(2, 'big')
            + b'\x00\x00'
            + b'\x00\x00'
            + self.bridge_net
            + int(frame_dest).to_bytes(1, 'big')
            + int(frame_src).to_bytes(1,'big')
          )
          if ddp_type == 0x02 and (frame[8] >> 4 == 1 or frame[8] >> 4 == 2):
            frame = (frame[:10]
            + self.bridge_net
            + frame[12:])

          if ddp_type == 0x02 and frame[8] >> 4 == 3:
            frame = (frame[:10]
            + self.bridge_net
            + frame[12:])  
          frame_offset = 5
        
        if frame_type == 0x02:
          frame_header = (
            frame[3:9]
            + self.bridge_net
          )
          if ddp_type == 0x02 and (frame[8] >> 4 == 1 or frame[8] >> 4 == 2):
            frame = (frame[:18]
            + self.bridge_net
            + frame[20:])

          if ddp_type == 0x02 and frame[16] >> 4 == 3:
            frame = (frame[:18]
            + self.bridge_net
            + frame[20:])

          frame_offset = 11

        def LtToEt(frame_dest, frame_src, hw_dest, frame):
            return (
              hw_dest
              + self.macaddr
              + int(6 + len(frame[3:])).to_bytes(2, 'big')
              + b'\xaa\xaa\x03\x08\x00\x07\x80\x9b'
              + frame_header
              + frame[frame_offset:-2]
            )
        logging.info('\n'.join(chain(('frame sent to EtherTalk:',), (line for line in hexdump_lines(LtToEt(frame_dest, frame_src, hw_dest, frame).ljust(60, b'\x00'))))))
        self.etqueue.put(LtToEt(frame_dest, frame_src, hw_dest, frame).ljust(60, b'\x00'))


  def service_ethertalk(self):
    '''Called when there is a EtherTalk datagram to be parsed and potentially forwarded.'''
    
    data, sender_addr = self.socket.recvfrom(65565)

    if len(data) < 20:
      logging.debug('ignoring invalid too-small EtherTalk datagram')
      return

    if data[:6] == data[6:12] or data[6:12] == self.macaddr:  # TODO check sender_addr too
      logging.debug('ignoring echoed EtherTalk datagram')
      return
    
    frame_type = data[17:22]

    if frame_type == (b'\x00\x00\x00\x80\xf3' or b'\x08\x00\x07\x80\x9b'):
        logging.info('\n'.join(chain(('received EtherTalk packet from %s:' % str(sender_addr),),
                                 (line for line in hexdump_lines(data)))))
  
    if frame_type == b'\x00\x00\x00\x80\xf3':
      hw_src = data[6:12]
      frame_dest = data[49]
      frame_src = data[39]
      frame_src_net =  data[37:39]

      aarp_function = data[29]

      if aarp_function == 0x03 or aarp_function == 0x01:
        if aarp_function == 0x01:
          self.aarp_table.update(
              {frame_src: {'hw': hw_src, 'net': frame_src_net}})
          self.node_id_set.touch(frame_src)

        if frame_dest in self.bridge_lt_nodelist:
        
          def aarp_response(frame_dest, frame_src, macaddr, bridge_net, frame_src_net, hw_src):
            return (
            hw_src
       	    + macaddr
            + b'\x00\x24'
            + b'\xaa\xaa\x03\x00\x00\x00\x80\xf3\x00\x01\x80\x9b\x06\x04\x00\x02'
            + macaddr
            + b'\x00'
            + bridge_net
            + int(frame_dest).to_bytes(1, 'big')
            + hw_src
            + b'\x00'
            + frame_src_net
            + int(frame_src).to_bytes(1, 'big')
            )
          logging.info('\n'.join(chain(('AARP Reply sent to EtherTalk:',), (line for line in hexdump_lines(aarp_response(
              frame_dest, frame_src, self.macaddr, self.bridge_net, frame_src_net, hw_src).ljust(60, b'\x00'))))))
          self.etqueue.put(aarp_response(
              frame_dest, frame_src, self.macaddr, self.bridge_net, frame_src_net, hw_src).ljust(60, b'\x00'))
    
    if frame_type == b'\x08\x00\x07\x80\x9b':
        logging.info('\n'.join(chain(('received EtherTalk DATA packet from %s:' % str(sender_addr),),
                                     (line for line in hexdump_lines(data)))))
        frame_src_net = data[28:30]
        frame_dest = data[30]
        frame_src = data[31]
        hw_src = data[6:12]
        frame_length = int(data[22:24].hex(), 16)
        self.aarp_table.update(
            {frame_src: {'hw': hw_src, 'net': frame_src_net}})     
        self.node_id_set.touch(frame_src)

        def EtToLt (frame_dest, frame_src, data):
          return (
            int(frame_dest).to_bytes(1, 'big')
            + int(frame_src).to_bytes(1, 'big')
            + b'\x02'
            + data[22:28]
            + data[28:30]
            + data[30:frame_length - 8 + 30]
          )
        logging.info('\n'.join(chain(('sent LocalTalk DATA frame to %s:' % str(frame_dest),),
                                     (line for line in hexdump_lines(EtToLt(frame_dest, frame_src, data))))))
        self.ltqueue.put(bytearray(EtToLt(frame_dest, frame_src, data)))

  def run(self):
    '''Run the daemon.'''

    last_check_expiration = time.monotonic()

    while True:
      rlist, wlist, xlist = select.select(
          (self.receiver, self.socket), (self.socket, self.sender), (), 10)
      if(self.receiver in rlist):
          self.service_tashtalk()
      if self.socket in rlist:
          self.service_ethertalk()
      if self.socket in wlist:
        if self.etqueue.empty() != True:
            self.socket.send(self.etqueue.get())
      if self.sender in wlist:
        if self.ltqueue.empty() != True:
            self.sender.send_frame(self.ltqueue.get())

      now = time.monotonic()
      if now - last_check_expiration >= 2:
        self.node_id_set.check_expiration()
        last_check_expiration = now
