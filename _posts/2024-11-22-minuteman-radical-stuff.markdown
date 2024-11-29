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
- [main.py](main.py)
- [public_keys.txt](public_keys.txt)
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
