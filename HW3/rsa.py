#My implementation of RSA

#Rabin-Miller algorithm returns true if number is probably prime, false otherwise. Iterating k times increases accuracy
def miller_rabin_test(number, k): 
  if number%2==0 :
    return False
  # number-1 can be written as 2^r + d
  r, d = 0, number-1
  while d % 2 == 0:
    r += 1
    d //= 2
  #print("r,d: {}, {}\n".format(r,d))
  for i in range(k):
    rand = random.randrange(2, number-2)
    x = pow(rand, d, number)
    if x != 1 and x != number-1:
      for j in range(1,r):
        x = pow(x,2,number)
        if x == number-1:
          continue
        elif x == 1:
          break
      if rand :
        return False
  return True

#Used to obtain private key d
def extended_euclidean_algorithm(e,phi):
	if e == 0:
		return phi,0,1
	gcd,s1,t1 = extended_euclidean_algorithm(phi%e,e)
	s = t1-(phi//e) * s1
	t = s1
	return gcd,s,t

#To speed up exponentials (from the slides), much much better than moltiplicative_inverse and pow
def square_multiply(base,exp,n):
	b=base
	f = 1
	while exp>0:
		lsb = exp & 0x1
		exp = exp // 2
		if lsb:
			f = (f*b) %n
		b = (b*b) %n
	return f

#Function that compute d -> moltiplicative inverse of e (mod phi)
#Too slow, instead I use square_multiply
def moltiplicative_inverse(e,phi):
  for x in range(1,phi):
    if (e*x) % phi == 1:
      return x
  return None

#Returns n,e,phi and d
def compute_values(n_bits): 
  #Generation of prime numbers p and q
  res = False
  p, q = 0, 0
  while res == False :
    p = random.randrange(2**(n_bits-1)+1, 2**n_bits-1)
    res = miller_rabin_test(p,40) #40 iterations is good
    #print("Is p:{} prime? {}".format(p,res))
  res = False
  while res == False :
    q = random.randrange(2**(n_bits-1)+1, 2**n_bits-1)
    res = miller_rabin_test(q,40) #40 iterations is good
    #print("Is q:{} prime? {}".format(q,res))
  #Computing modulus n and phi(n)
  n = p*q
  print("p={},\nq={},\nn=p*q={}".format(p,q,n)) #MEMO: message's length can't be bigger than n
  phi = (p-1)*(q-1)
  print("phi=(p-1)*(q-1)={}".format(phi))
  #e is choosen such that gcd(phi(n), e)=1
  e = 3 #at least three
  while e<phi//2:
    if math.gcd(e,phi) == 1:
      break
    e += 1
  print("Public key e={}".format(e))
  #Compute d = e^(-1) mod n
  #d = moltiplicative_inverse(e,phi)
  #d = pow(e,phi-1,phi)
  s,d,t = extended_euclidean_algorithm(e,phi)
  print("Private key d={}".format(d))
  return n,e,phi,d

#Encryption and decryption functions
def encryption(message,e,n):
  cipher = square_multiply(int.from_bytes(message, byteorder='big'),e,n)
  return cipher

def decryption(message,d,n,n_bits):
	msg = square_multiply(message,d,n)
	return msg.to_bytes(n_bits, byteorder='big')

#AES
def aes(message):
  #Key generation
  key = get_random_bytes(32) #AES-256
  #print("Key: {}".format(key))
  data = message.encode('UTF-8') #To converto into bytes type
  #Encrypt
  e_cipher = AES.new(key, AES.MODE_EAX)
  e_data = e_cipher.encrypt(data)
  print("Encrypted message: {}\n".format(e_data))
  #Decrypt
  d_cipher = AES.new(key, AES.MODE_EAX, e_cipher.nonce)
  d_data = d_cipher.decrypt(e_data)
  print("Original message was: {}".format(d_data.decode('UTF-8')))
  return

#RSA
def rsa(message):
  #Key generation
  random_generator = Random.new().read
  key = RSA.generate(2048, random_generator) #generate pub and priv key
  cipher = PKCS1_OAEP.new(key)
  data = message.encode('UTF-8') #To converto into bytes type
  #Encrypt
  encrypted = cipher.encrypt(data)
  print("Encrypted message: {}\n".format(encrypted))
  #Decrypt
  decrypted = cipher.decrypt(encrypted)
  #decrypted is a bytes type, I must convert it
  print ('Decrypted message: {}'.format(decrypted.decode('UTF-8')))
  return

#Run !pip3 install pycryptodome

import random
import math
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam eget tortor egestas, fermentum arcu eu, bibendum massa."
method = input('Insert which method for encryption/decryption to use (type myRSA or AES or RSA): ')
print("Message: {}".format(message))
#print(message.encode('UTF-8'))
if method == "myRSA":
	n_bits=1024 
	n,e,phi,d = compute_values(n_bits)
		#Check len of message -> cannot be > than n
	if len(message)<=n and d != None:
		cipher = encryption(message.encode('UTF-8'),e,n)
		print('Cyphertext: {}'.format(cipher))
		plaintext = decryption(cipher,d,n,n_bits)
		res = plaintext.decode('UTF-8')
		print('\nPlaintext: {}'.format(res))
	elif d == None:
		print("I could not compute the private key, try again!")
	else :
		print("Message has to be smaller")
elif method == "RSA":
  rsa(message)
elif method == "AES":
  aes(message)
else:
  print("Error: Valid values -> myRSA or RSA or AES")
