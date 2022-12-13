import enum
import logging
import llp
import queue
import struct
import threading

class SWPType(enum.IntEnum):
    DATA = ord('D')
    ACK = ord('A')

class SWPPacket:
    _PACK_FORMAT = '!BI'
    _HEADER_SIZE = struct.calcsize(_PACK_FORMAT)
    MAX_DATA_SIZE = 1400 # Leaves plenty of space for IP + UDP + SWP header 

    def __init__(self, type, seq_num, data=b''):
        self._type = type
        self._seq_num = seq_num
        self._data = data

    @property
    def type(self):
        return self._type

    @property
    def seq_num(self):
        return self._seq_num
    
    @property
    def data(self):
        return self._data

    def to_bytes(self):
        header = struct.pack(SWPPacket._PACK_FORMAT, self._type.value, 
                self._seq_num)
        return header + self._data
       
    @classmethod
    def from_bytes(cls, raw):
        header = struct.unpack(SWPPacket._PACK_FORMAT,
                raw[:SWPPacket._HEADER_SIZE])
        type = SWPType(header[0])
        seq_num = header[1]
        data = raw[SWPPacket._HEADER_SIZE:]
        return SWPPacket(type, seq_num, data)

    def __str__(self):
        return "%s %d %s" % (self._type.name, self._seq_num, repr(self._data))

class SWPSender:
    _SEND_WINDOW_SIZE = 5
    _TIMEOUT = 1
    # seq_num = 0


    def __init__(self, remote_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(remote_address=remote_address,
                loss_probability=loss_probability)

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # TODO: Add additional state variables
        # current window = _lfs - _lar, which should be smaller than _SEND_WINDOW_SIZE
        self._lfs = 0
        self._lar = 0
        self.sem = threading.Semaphore(SWPSender._SEND_WINDOW_SIZE)
        # buffer: seq -> data, total of 5
        self.buff = {}
        self.seq = 0
        self.t = None
        self.lk = threading.Lock()


    def send(self, data):
        for i in range(0, len(data), SWPPacket.MAX_DATA_SIZE):
            self._send(data[i:i+SWPPacket.MAX_DATA_SIZE])

    def _send(self, data):
        # TODO
        self.sem.acquire()
        seq = self._lfs # seq number for this data chunk to use
        self._lfs += 1
        # add data to buffer?
        self.buff[seq] = data
        swp_packet = SWPPacket(SWPType.DATA, seq, data)
        pkt_raw = swp_packet.to_bytes()
        self._llp_endpoint.send(pkt_raw)

        self.t = threading.Timer(SWPSender._TIMEOUT, self._retransmit, [seq])
        self.t.start()
        return
        
    def _retransmit(self, seq_num):
        # TODO
        if self.buff.get(seq_num) is None:
            return
        data = self.buff[seq_num]
        swp_packet = SWPPacket(SWPType.DATA, seq_num, data)
        pkt_raw = swp_packet.to_bytes()
        self._llp_endpoint.send(pkt_raw)
        self.t = threading.Timer(SWPSender._TIMEOUT, self._retransmit, [seq_num])
        #self.seq = seq_num
        self.t.start()
        return 

    def _recv(self):
        while True:
            # Receive SWP packet
            raw = self._llp_endpoint.recv()
            if raw is None:
                continue
            packet = SWPPacket.from_bytes(raw)
            if packet.type == SWPType.ACK:
                seq = packet.seq_num
                self.t.cancel()
                self.lk.acquire()
                self.buff.pop(seq)
                self.lk.release()
                self.sem.release()

            logging.debug("Received: %s" % packet)

            # TODO

        return

class SWPReceiver:
    _RECV_WINDOW_SIZE = 5

    def __init__(self, local_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(local_address=local_address, 
                loss_probability=loss_probability)

        # Received data waiting for application to consume
        self._ready_data = queue.Queue()

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()
        
        # TODO: Add additional state variables
        self.lk = threading.Lock()
        self.buff = {}
        self.buff_q = queue.PriorityQueue() # store seq_num in order, to find holes easier
        self.highest_seq = 0

    def recv(self):
        return self._ready_data.get()

    def _recv(self):
        while True:
            # Receive data packet
            raw = self._llp_endpoint.recv()
            packet = SWPPacket.from_bytes(raw)
            seq = packet.seq_num
            logging.debug("Received: %s" % packet)
            
            # TODO
            # remember to add lock
            if seq < self.highest_seq:
                # retransmit ack
                swp_packet = SWPPacket(SWPType.ACK, self.highest_seq)
                pkt_raw = swp_packet.to_bytes()
                self._llp_endpoint.send(pkt_raw)
                logging.debug("Receiver retransmit ack: %s" % swp_packet)
                return
            data = packet.data
            self.lk.acquire()
            self.buff[seq] = data
            self.buff_q.put(seq)
            last_seq = self.buff_q.get()
            d = self.buff.pop(last_seq)
            self._ready_data.put(d)
            # self.lk.release()
            if self.buff_q.empty(): #if there is only one packet received
                self.highest_seq = last_seq
                swp_packet = SWPPacket(SWPType.ACK, last_seq)
                pkt_raw = swp_packet.to_bytes()
                self._llp_endpoint.send(pkt_raw)

            while not self.buff_q.empty():
                s = self.buff_q.get()
                if s == last_seq+1:
                    self._ready_data.put(self.buff.pop(s))
                    last_seq = s
                else: # hole between s and last_seq
                    # return s to buff_q
                    self.buff_q.put(s)
                    # send ack
                    self.highest_seq = last_seq
                    swp_packet = SWPPacket(SWPType.ACK, last_seq)
                    pkt_raw = swp_packet.to_bytes()
                    self._llp_endpoint.send(pkt_raw)
                    break
            self.lk.release()

        return
