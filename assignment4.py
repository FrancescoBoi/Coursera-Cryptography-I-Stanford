'''
Created on Mar 20, 2017

@author: root
'''
#import sys
#if (sys.version_info > (3, 0)):
     # Python 3 code in this block
#    import urllib3 as urllib
#else:
import urllib2 as urllib

import binascii

url = ("http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7"
       "000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577"
       "c0bdf302936266926ff37dbf7035d5eeb4")
       
iv_ct = ("f20bdba6ff29eed7b046d1df9fb7"
       "000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577"
       "c0bdf302936266926ff37dbf7035d5eeb4")
IV = iv_ct[0:int(len(iv_ct)/4)];
ct = iv_ct[int(len(iv_ct)/4):len(iv_ct)]


def xor_strings(s,t):
    """xor two strings together"""
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib.quote(q)    # Create query URL
        req = urllib.Request(target)         # Send HTTP request to server
        try:
            f = urllib.urlopen(req)          # Wait for response
        except urllib.HTTPError, e:          
            print ("We got: %d" % e.code)       # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding

if __name__ == "__main__":
    po = PaddingOracle()
    counter = 1
    candidate = IV
    decrypted = ''
    decrypted2 = ''
    decrypted3 = ''
    print(candidate)
    temp = []

    IV_str = ''.join(chr(int(IV[i:i+2], 16)) for i in range(0, len(IV), 2))
    for c in IV_str[::-1]:#reverse the string
        for i in range(0,256): 
            if counter==1 and i<2:
                continue
            print("--------------")
            #print("counter: " + str(counter) + ' ' + ("{:02x}".format(counter)))
            print("i: " + str(i) + ' ' + "{:02x}".format(i))
            print("chracter: " + c + ' '+ binascii.hexlify(c))
            b = xor_strings(c, binascii.unhexlify("{:02x}".format(i)))
            temp.insert(0, b)
            #print("candidate value:" + binascii.hexlify(b))
            #candidate = IV[0:len(IV)-counter*2]
            print(temp)
            candidate = IV[0:len(IV)-counter*2]
            for jj in range(0, counter):
                print (jj, counter, temp)
                candidate = candidate + binascii.hexlify(xor_strings(temp[jj],
                                            binascii.unhexlify("{:02x}".format(counter))))
                
            candidate = candidate + iv_ct[32:64]
            print(candidate)
            
            if po.query(candidate):
                #decrypted = binascii.unhexlify("{:02x}".format(i)) + decrypted
                decrypted2 = chr(i) + decrypted2
                decrypted3 = decrypted3 + chr(i)
                
                #print(binascii.hexlify(decrypted))
                print(binascii.hexlify(decrypted2))
                print(binascii.hexlify(decrypted3))
                print(decrypted2)
                print("--------------")
                break
            temp.pop(0) 
                   
        counter = counter+1

    #po.query(sys.argv[1])       # Issue HTTP query with the given argument
