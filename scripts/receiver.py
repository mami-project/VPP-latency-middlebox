import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import *
from scapy.all import *

FORMAT = "\x1b[1;32;40m[PLUS_RECEIVER:%(lineno)3s - %(funcName)15s()] %(message)s\x1b[0m"

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

class PLUSReceiver(Automaton):

    def parse_args(self, sender, receiver, s_port, r_port, **kargs):
        Automaton.parse_args(self, **kargs)
        self.sender = sender
        self.receiver = receiver
        self.s_port = s_port
        self.r_port = r_port
        self.CAT = 0
        self.PSN = random.randint(0, 2**32-1)
        self.PSE = 0
        self.counter = 0

    def send_pkt(self, PSE_to_send=0, is_stop=0, is_L=0, is_R=0, opt=0, opt_type=0, opt_len=0, II=0, opt_value='0'):
        pkt = IP(src=self.receiver, dst=self.sender, ttl=30) / UDP(sport=self.s_port, dport=self.r_port) / PLUS(
                 CAT=self.CAT, PSN=self.PSN, PSE=PSE_to_send, stop=is_stop, LoLa=is_L, RoI=is_R, extended=opt,
                 PCF_Type=opt_type, PCF_Len=opt_len, PCF_II=II, PCF_Value=(opt_len - len(opt_value)) * '0' + opt_value)

        send(pkt, verbose=0)
        
        log.debug('Send pkt [CAT: {0}, PSN: {1}, PSE: {2}, LoLa: {5}, RoI {6}, S: {3}, Ext: {4}]'.format(
                  self.CAT, self.PSN, PSE_to_send, is_stop, opt, is_L, is_R))
        if opt:
            log.debug('   Extended: [PCF Type: {0} PCF Len: {1} PCF II: {2} PCF Value {3}]'.format(
                      opt_type, opt_len, II, opt_value))
        self.PSN = (self.PSN + 1) % 2**32

    def master_filter(self, pkt):
        return (IP in pkt and pkt[IP].src == self.sender and pkt[IP].dst == self.receiver and 
               PLUS in pkt and ICMP not in pkt)

    @ATMT.state(initial=1)
    def S_start(self):
        pass
      
    @ATMT.receive_condition(S_start)
    def start_in_main(self, pkt):
        plus_in = pkt.getlayer(PLUS)
        log.debug('Received packet PSN: {0}'.format(plus_in.PSN))
        if plus_in.extended:
            log.debug('   Extended: [PCF Type: {0} PCF Len: {1} PCF II: {2} PCF Value {3}]'.format(
                      plus_in.PCF_Type, plus_in.PCF_Len, plus_in.PCF_II, plus_in.PCF_Value))

        self.PSE = pkt.getlayer(PLUS).PSN
        self.CAT = pkt.getlayer(PLUS).CAT

        if pkt.getlayer(PLUS).stop == 1:
            log.debug('Send stop signal')
            self.send_pkt(PSE_to_send=self.PSE, is_stop=1)
        else:
            self.send_pkt(PSE_to_send=self.PSE)

        raise self.S_start()

    @ATMT.state(final=1)
    def S_end(self):
        pass

if __name__ == "__main__":

    sender_IP = "172.16.1.2"
    receiver_IP = "172.16.2.2"
    s_port = 4000
    r_port = 3000

    test = PLUSReceiver(sender_IP, receiver_IP, s_port, r_port)
    log.debug('receiver start')

    test.run()
