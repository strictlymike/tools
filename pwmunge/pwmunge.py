# http://baileysoriginalirishtech.blogspot.com/2015/10/pumpkin-spiced-password-
# generator.html

import sys

# suffices = ['!', '1', '123', '2015', '2015!', '0915', '915', '1015', 'oct15', 'fall15', 'fall2015']
suffices = []

def toggle_case(c):
    if c.islower():
        return c.upper()
    else:
        return c.lower()

def transmute(beginstr, array, index, suffices, min, max):
    # If past end of string...
    if index == len(array):

        # Print current variant
        if len(beginstr) >= min and len(beginstr) <= max:
            print beginstr

        # Also print current variant along with each suffix (if any)
        for suffix in suffices:
            outstr = beginstr + suffix
            if len(outstr) >= min and len(outstr) <= max:
                print outstr

        # And unwind recursion
        return

    # Else, iterate through variants for this character, and recurse
    for c in array[index]:
        transmute(beginstr + c, array, index+1, suffices, min, max)
    
def build_array(str):
    ret = list()
    for i in range(0, len(str)):
        c = str[i]
        if c in 'aA':               # [aA] -> @
            ret.append([c, '@'])
        elif c in 'eE':             # [eE] -> 3
            ret.append([c, '3'])
        elif c in 'iI':             # [iI] -> 1
            ret.append([c, '1'])
        elif c in 'oO':             # [oO] -> 0
            ret.append([c, '0'])
        elif c in 'sS':             # [sS] -> 5,$
            ret.append([c, '5', '$'])
        elif c in 'tT':             # [tT] -> 7
            ret.append([c, '7'])
        else:
            ret.append([c])

        if i == 0:
            ret[0].append(toggle_case(ret[0][0]))

    return ret

if len(sys.argv) != 2 and len(sys.argv) != 4:
    print "Usage: pwmunge.py basepwd [min max]"
    sys.exit(1)

base = sys.argv[1]

min = 7
max = 14
if len(sys.argv) > 2:
    min = int(sys.argv[2])
    max = int(sys.argv[3])

# print build_array(base)
transmute('', build_array(base), 0, suffices, min, max)
