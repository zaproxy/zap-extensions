"""
This script is just a proof of concept for payload generation, 
supplementing ZAP's native generation mechanism(s).
It generates payload1 for field1 and calculates the payload 
(payload2 = sha1(base64(payload1))) for field2, something like Battering Ram
without the hassle of generating the payload2 wordlist first
"""

from base64 import b64encode;
from hashlib import sha1;
from java.lang import Long;     # bug resolution import

INITIAL_VALUE = 0; 
count = INITIAL_VALUE;
passfile_path = 'K:\\payloads.txt';
pl_buff = list();
lines = 0;
for line in open(passfile_path):  
    pl_buff.append(line.rstrip());
    lines += 1;
middle = str('&check=');
NUMBER_OF_PAYLOADS = lines;

def getNumberOfPayloads():
    return Long(NUMBER_OF_PAYLOADS);    # Typecast to solve bug

def hasNext():
    return (count < NUMBER_OF_PAYLOADS);

def next():
    global count;
    num = count;
    count+=1;
    return pl_buff[num]+middle+sha1(b64encode(pl_buff[num])).hexdigest();

def reset():
    count = INITIAL_VALUE;

def close():
    pass;

