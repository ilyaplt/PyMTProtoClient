from random import randint
from math import gcd

# взято с stackoverflow
# Telegram требует разложение числа на два простых сомножителя, для этого можно воспользоваться алгоритмом Брента

def brent(N):
   if N%2==0: return 2
   y,c,m = randint(1, N-1),randint(1, N-1),randint(1, N-1)
   g,r,q = 1,1,1
   while g==1:
       x = y
       for i in range(r):
          y = ((y*y)%N+c)%N
       k = 0
       while (k<r and g==1):
          ys = y
          for i in range(min(m,r-k)):
             y = ((y*y)%N+c)%N
             q = q*(abs(x-y))%N
          g = gcd(q,N)
          k = k + m
       r = r*2
   if g==N:
       while True:
          ys = ((ys*ys)%N+c)%N
          g = gcd(abs(x-ys),N)
          if g>1:  break
   return g

def factorize(n1):
    if n1<=0: return []
    if n1==1: return [1]
    n=n1
    b=[]
    p=0
    mx=1000000
    while n % 2 ==0 : b.append(2);n//=2
    while n % 3 ==0 : b.append(3);n//=3
    i=5
    inc=2
    while i <=mx:
       while n % i ==0 : b.append(i); n//=i
       i+=inc
       inc=6-inc
    while n>mx:
      p1=n
      while p1!=p:
          p=p1
          p1=brent(p)
      b.append(p1);n//=p1
    if n!=1:b.append(n)
    b.sort()
    return b

def decompose(pq):
    p = brent(pq)
    q = pq // p
    if p > q:
        p, q = q, p
    return p, q