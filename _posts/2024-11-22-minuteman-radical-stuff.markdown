---
layout: post
title: "Radical stuff: Crypto Challenge - Minuteman CTF, October 2024"
date: 2024-11-22
categories: [CTF, Crypto]
tags: [Chinese Remainder Theorem, RSA, Broadcast attack, mid]
---

## Problem Statement

**Points:** 400

**Description:** As it turns out, encrypting identical messages with RSA is not usually a good idea... Use Chinese Remainder Theorem to reconstruct the message before modulus operations, then take its 257th root to recover the flag!

**Attachments:**
[2024-11-28-welcome-to-jekyll.markdown]({% post_url 2024-11-28-welcome-to-jekyll %})
- [public_keys.txt](./files/public_keys.txt)
- `nc crypto-challenges.minuteman.umasscybersec.org 10002`

**Hints:**
1. To use Chinese Remainder Theorem, you need the moduli (plural of modulus) and corresponding remainders.
2. Modify the given cube root function to take the 257th root instead, and don't forget to adjust the range!
3. There is a guarantee about how large the flag can be. Make sure you modify the bounds before binary searching.

## Solve

### TLDR

The `nc` asks to solve two systems of equations. Very helpfully, a function that solves the Chinese Remainder Theorem (`solve_crt`) has been provided. Then, we are asked to take the cube root of a large number, which also can be solved using a provided function (`binary_search_root`). This prints out a list of long numbers which are the ciphertexts for the various moduli in `public_keys.txt`. Then we use the `solve_crt` function to get `me` and `binary_search_root` function to take the `eth` root of `me`, getting our message.

### Part 1: Netcat

After connecting to the provided port with netcat, we are presented with a question.

The modulo (%) operator is used to represent the remainder after division. So, 17 % 3 = 2 and 49 % 9 = 5. An equation like this is called a congruence. We are looking for a number that satisfies the system. The Chinese Remainder Theorem guarantees the existence of a solution, as long as the moduli are relatively prime. The function `crt` in `main.py` will output such a solution. Here, the solution will be `crt(829, 863, 699, 669) = 338112`, and we can move on.

Next, we have a similar problem, but with bigger numbers and more equations.

The `solve_crt` function will be very helpful here. It takes in two lists of numbers, the moduli and the remainders. It then returns a key that satisfies all equations. Here, `solve_crt([mod1, mod2, mod3], [rem1, rem2, rem3]) = 161610605131125067631863428063916345645978616589351290330113` will pass this step.

Next, we are asked to take the cube root of a large number. This can be done with another provided function, the `binary_search_root` function (which is hardcoded to do the third root). We plug in the number, and out continue. This reveals a long list of numbers, which are in `other_nums.txt`.

We can notice two things about the numbers in `public_keys.txt` and `other_nums.txt`. Firstly, they both contain 300 numbers, and secondly, each number in `public_keys.txt` is greater than the corresponding number in `other_nums.txt`. This clues us in to the fact that `public_keys.txt` contains moduli and `other_nums.txt` contains the corresponding remainders.

RSA encrypts a number `m` using the equation `m^e % n = c`. The public key is `(e, n)` and the encrypted ciphertext is `c`. In our case, we have `e = 257`, and many `c, n` pairs that all correspond to the same message. In other words, we have a system of congruences, where
```
m^e % n1 = c1 
m^e % n2 = c2 
…
m^e % n300 = c300
```

We have seen this before! This is the exact form of the problem that `solve_crt` can solve. We now can calculate `m^e` using `solve_crt([n1 … n300], [c1 … c300])`.

The last step is to take the `eth` root of `m`. The degree of the root in `binary_search_root` is hard coded to 3, so we need to change that to 257. After this, we have `m`. Finally, we need to convert `m` into plaintext.

For this, I used [CyberChef](https://gchq.github.io/CyberChef/), an easy-to-use tool for when python gets too annoying. We must first convert our decimal number to hex (using the `To Base` operation–radix 16), then from hex to plaintext (`From Hex` operation). Plugging in the very long number `1830878586199007902198321745808716309199998543652268799969514110679370818759976479462490492628382747953931090202302350440488980854152245048356497589244961826221216426003564412216773009546916816955886211297911635610606392797120337` into our recipe, we get our flag! `MINUTEMAN{modern_rsa_inserts_extra_noise_for_each_encryption_to_avoid_this}`.


```python

from Crypto.Util.number import getPrime, getRandomRange
from Crypto.Random import get_random_bytes


def crt_challenge(modulus_size, modulus_count):
    primes = set()
    # generate a bunch of primes
    while len(primes) < modulus_count:
        primes.add(getPrime(modulus_size))


    # take their product
    product = 1
    for p in primes:
        product *= p


    # generate a number less than their product
    key = getRandomRange(0, product)
    for p in primes:
        print(f"key % {p} = {key % p}")


    guess = int(input("What could the value of key be?"))


    # check if the guess matches the congruences
    for p in primes:
        if guess % p != key % p:
            print("That's not the key!")
            exit(0)




def cube_challenge():
    # generate the cube of a large number
    target = pow(getPrime(512), 3)
    print(f"key ** 3 = {target}")




    guess = int(input("What can the value of key be?"))


    # check if cubing the guess matches target
    if pow(guess, 3) != target:
        print("That's not the key!")
        exit(0)




def load_mailing_list():
    with open('public_keys.txt', 'r') as f:
        return [int(key) for key in f.readlines()]




def load_flag():
    with open('flag.txt', 'rb') as f:
        return f.readline()




if __name__ == '__main__':
    print("Chinese Remainder Theorem allows us to merge congruences!")
    print("Let's start off with small numbers, and with only 2 factors:")
    crt_challenge(10, 2)
    print("Nice! Now let's ramp up the challenge a little bit!")
    crt_challenge(50, 4)
    print("Awesome! But can you take the cube root of a large number?")
    cube_challenge()


    print("Great! Finally, let's break a poor implementation of RSA!")
    FLAG = load_flag() + get_random_bytes(20)
    assert len(FLAG) < 128
    mailing_list = load_mailing_list()
    e = 0x101
    for n in mailing_list:
        print(pow(int.from_bytes(FLAG, 'big'), e, n))




# solves crt for 2 modulus
def crt(m1, m2, r1, r2):
    return (pow(m2, -1, m1) * m2 * r1 + pow(m1, -1, m2) * m1 * r2) % (m1 * m2)


# solves crt for any number of modulus
def multi_crt(ms: list[int], rs: list[int]):
    # while there's still things to merge
    while len(ms) > 1:
        m1 = ms.pop(0)
        m2 = ms.pop(0)
        r1 = rs.pop(0)
        r2 = rs.pop(0)
        # merge the modulus via taking their LCM (assuming they're coprime, this is the same as their product)
        ms.append(m1 * m2)
        # merge the remainders using CRT on 2 modulus
        rs.append(crt(m1, m2, r1, r2))
    return rs[0]




# take the integer cube root of super large numbers
def binary_search_root(target):
    low = 0
    high = 1 << 512
    # cube-root-ing is hard, but cubing is easy.
    # since x < y if and only if x ** 3 < y ** 3, we can think of the cube function as a sorted array, and binary search!
    # so if we did have an array, arr[n] should store n ** 3.
    # we don't need to store the whole array though, since we can just calculate the needed values on demand.
    while high >= low:
        mid = (high + low) // 2
        val = pow(mid, 3)
        if val < target:
            low = mid + 1
        elif val > target:
            high = mid - 1
        else:
            return mid
    return low
```