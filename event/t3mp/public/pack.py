
import struct
NUMBER = 0
KEY    = 1
BIN    = 2
SIGNAL = 3
def pack_data(items):
    buffer = bytearray()
    
    for item in items:
        t = item['type']
        
        if t == BIN:
            data = item['data']
            buffer.extend(struct.pack('<Bi', BIN, len(data)))
            buffer.extend(data)
            
        elif t == NUMBER:
            val = item['value']
            buffer.extend(struct.pack('<Bq', NUMBER, val))
            
        elif t == KEY:
            k1, k2 = item['key1'], item['key2']
            buffer.extend(struct.pack('<Bqq', KEY, k1, k2))
            
        elif t == SIGNAL:
            action = item['action']
            sigtype = item['sigtype']
            buffer.extend(struct.pack('<Bii', SIGNAL, sigtype, action))
            
    return bytes(buffer)
def create_packet(opcode, packed_data):
    return  struct.pack("<i", opcode) + packed_data
