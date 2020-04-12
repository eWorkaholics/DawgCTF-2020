from pwn import *
import base64
import codecs

host = 'ctf.umbccd.io'
port = 5200
r = remote(host, port)

# Loop through initial instructions
for i in range(16):
    r.recvline()

# Railfence function ( by Pratik Somwanshi )
def decryptRailFence(cipher, key):
 
    # create the matrix to cipher  
    # plain text key = rows ,  
    # length(text) = columns
    # filling the rail matrix to  
    # distinguish filled spaces
    # from blank ones
    rail = [['\n' for i in range(len(cipher))]  
                  for j in range(key)]
      
    # to find the direction
    dir_down = None
    row, col = 0, 0
      
    # mark the places with '*'
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
          
        # place the marker
        rail[row][col] = '*'
        col += 1
          
        # find the next row  
        # using direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
              
    # now we can construct the  
    # fill the rail matrix
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if ((rail[i][j] == '*') and
               (index < len(cipher))):
                rail[i][j] = cipher[index]
                index += 1
          
    # now read the matrix in  
    # zig-zag manner to construct
    # the resultant text
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
          
        # check the direction of flow
        if row == 0:
            dir_down = True
        if row == key-1:
            dir_down = False
              
        # place the marker
        if (rail[row][col] != '*'):
            result.append(rail[row][col])
            col += 1
              
        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    return("".join(result))

# Atbash Cipher function
lookup_table = {'A' : 'Z', 'B' : 'Y', 'C' : 'X', 'D' : 'W', 'E' : 'V',
'F' : 'U', 'G' : 'T', 'H' : 'S', 'I' : 'R', 'J' : 'Q',
'K' : 'P', 'L' : 'O', 'M' : 'N', 'N' : 'M', 'O' : 'L',
'P' : 'K', 'Q' : 'J', 'R' : 'I', 'S' : 'H', 'T' : 'G',
'U' : 'F', 'V' : 'E', 'W' : 'D', 'X' : 'C', 'Y' : 'B', 'Z' : 'A'}
def atbash(message):
    cipher = ''
    for letter in message:
        if letter == '{':
            cipher += '{'
        elif letter == '}':
            cipher += '}'
        else:         
            cipher += lookup_table[letter]
 
    return cipher
 
# Affine function
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y
def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m
def affine_decrypt(cipher):
    '''
    P = (a^-1 * (C - b)) % 26
    '''
    key = [9, 6]
    return ''.join([ chr((( modinv(key[0], 26)*(ord(c) - ord('A') - key[1]))  
                    % 26) + ord('A')) for c in cipher ])

# rot function
def rot_encode(n):
    from string import ascii_lowercase as lc, ascii_uppercase as uc
    lookup = str.maketrans(lc + uc, lc[n:] + lc[:n] + uc[n:] + uc[:n])
    return lambda s: s.translate(lookup)

# start decipher text
while True:
    cipher = str(r.recvline())[2:-3]
    print(cipher)
    if cipher.startswith('I'):    
        # Base32 decode        
        decipher = base64.b32decode(cipher)        
        r.sendline(decipher)
    elif cipher.startswith('RG9n'):
        # Base64 decode        
        decipher = base64.b64decode(cipher)
        r.sendline(decipher)
    elif cipher.startswith('446F'):
        # Hex decode
        decipher = bytes.fromhex(cipher).decode("ASCII")
        r.sendline(decipher)
    elif cipher.startswith('Qbtr'):
        # ROT13 decipher        
        decipher = rot_encode(-13)(cipher)    
        r.sendline(decipher)
    elif cipher.startswith('Tewu'):
        # ROT16 decipher        
        decipher = rot_encode(-16)(cipher)    
        r.sendline(decipher)
    elif cipher.startswith('D'):
        # Railfence decipher
        decipher = decryptRailFence(cipher, 3)
        r.sendline(decipher)
    elif cipher.startswith('WLTV'):
        # atbash decipher
        decipher = atbash(cipher)
        r.sendline(decipher)
    elif cipher.startswith('HCIQ'):
        # Affine decipher
        decipher = affine_decrypt(cipher)
        decipher = decipher.replace('DOGECTFA','DOGECTF{')
        decipher = decipher[:-1]        
        decipher += '}'
        r.sendline(decipher)
    else:
        print(r.recv())
        r.close()
        break