import time
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import *
from scapy.all import *

FORMAT = "\x1b[1;32;40m[PLUS_SENDER:%(lineno)3s - %(funcName)15s()] %(message)s\x1b[0m"

logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)

class PLUS(Packet):

    name = 'PLUS'
    fields_desc = [XBitField("magic", 0xd8007ff, 28),
                   BitField("LoLa", 0, 1),
                   BitField("RoI", 0, 1),
                   BitField("stop", 0, 1),
                   BitField("extended", 0, 1),
                   BitField("CAT", 0, 64),
                   BitField("PSN", 0, 32),
                   BitField("PSE", 0, 32),
                   ConditionalField(BitField("PCF_Type", 0, 8), lambda pkt:pkt.extended == 1),
                   ConditionalField(BitField("PCF_Len", 0, 6), lambda pkt:pkt.extended == 1),
                   ConditionalField(BitField("PCF_II", 0, 2), lambda pkt:pkt.extended == 1),
                   ConditionalField(BitField("PCF_Value", 0, 8), lambda pkt:pkt.extended == 1)]

bind_layers(UDP, PLUS)
split_layers(UDP, DNS)

class PLUSSender(Automaton):

    def parse_args(self, sender, receiver, s_port, r_port, **kargs):
        Automaton.parse_args(self, **kargs)
        self.sender = sender
        self.receiver = receiver
        self.s_port = s_port
        self.r_port = r_port
        self.CAT = random.randint(0, 2**64-1)
        self.PSN = random.randint(0, 2**32-1)
        self.PSE = 0
        self.counter = 0
        self.test_counter = 0

    def send_pkt(self, PSE_to_send=0, is_stop=0, is_L=0, is_R=0, opt=0,
                opt_type=0, opt_len=0, II=0, opt_value=0):
        pkt = IP(src=self.sender, dst=self.receiver, ttl=30) / UDP(
                 sport=self.s_port, dport=self.r_port) / PLUS(CAT=self.CAT,
                 PSN=self.PSN, PSE=PSE_to_send, stop=is_stop, LoLa=is_L, RoI=is_R,
                 extended=opt, PCF_Type=opt_type, PCF_Len=opt_len, PCF_II=II,
                 PCF_Value=opt_value%2**8)

        send(pkt, verbose=0)
        log.debug('Send pkt [CAT: {0}, PSN: {1}, PSE: {2}, LoLa: {5}, RoI {6}, S: {3}, Ext: {4}]'.format(
            self.CAT, self.PSN, PSE_to_send, is_stop, opt, is_L, is_R))
        if opt:
            log.debug('   Extended: [PCF Type: {0} PCF Len: {1} PCF II: {2} PCF Value: {3}]'.format(
                opt_type, opt_len, II, opt_value%2**8))
        self.PSN = (self.PSN + 1) % 2**32
        self.test_counter += 1

    def master_filter(self, pkt):
        return (IP in pkt and pkt[IP].src == self.receiver and pkt[IP].dst == self.sender and 
               PLUS in pkt and ICMP not in pkt)

    @ATMT.state(initial=1)
    def S_start(self):
        
        if self.test_counter == 10:
            self.send_pkt(PSE_to_send=self.PSE, is_stop=1, opt=1, opt_type=1, opt_len=1,
                          II=0, opt_value=self.test_counter)
            raise self.S_end()
        else:
            self.send_pkt(PSE_to_send=self.PSE, opt=1, opt_type=1, opt_len=1, II=0,
                          opt_value=self.test_counter)
        time.sleep(0.3)

    @ATMT.timeout(S_start, 1)
    def timeout_start(self):
        raise self.S_start()

    @ATMT.state(final=1)
    def S_end(self):
        pass

    @ATMT.receive_condition(S_start)
    def pkt_in_init(self, pkt):
        self.PSE = pkt.getlayer(PLUS).PSN
        log.debug('Got answer from receiver, PSE: {0}'.format(self.PSE))
        raise self.S_start()

if __name__ == "__main__":

    sender_IP = "172.16.1.2"
    receiver_IP = "172.16.2.2"
    s_port = 3000
    r_port = 4000

    test = PLUSSender(sender_IP, receiver_IP, s_port, r_port)
    log.debug('sender start')

    test.run()
