---
date:  "2025-08-19T23:26:01+01:00"
draft: false
categories: 
 - Cryptography
title: "Implementing AES-128 in Rust: From Finite Fields to Encryption"
---

# Implementing AES-128 in Rust: From Finite Fields to Encryption

## Introduction

The Advanced Encryption Standard (AES), based on the Rijndael cipher, is a symmetric-key block cipher standardised by the US National Institute of Standards and Technology (NIST) in 2001. AES always operates on 128-bit blocks and supports three key sizes: 128, 192 and 256 bits. These variants use 10, 12 and 14 rounds respectively.

AES is widely used in security protocols and applications. It is important to distinguish the block cipher itself from a *mode of operation*: AES defines how to transform one 128-bit block, while modes such as CBC, CTR and GCM specify how to use a block cipher to protect longer messages.

### Project Goal

In this tutorial, I implement AES-128 block encryption and decryption in Rust. The implementation covers the AES round transformations, key expansion and the inverse transformations used for decryption. It is intended as an educational exercise, not as a general-purpose encryption library.

> **Security warning:** Do not use this implementation to protect real data. It has not been independently audited and does not provide an authenticated encryption interface or a complete message-encryption mode. For production Rust applications, use a maintained, reviewed implementation such as the [`aes-gcm` crate](https://crates.io/crates/aes-gcm).

## Encryption overview

AES-128 uses an initial key addition followed by 10 rounds. The first nine rounds apply four transformations:

1. **SubBytes** — substitute each byte using the AES S-box.
2. **ShiftRows** — cyclically shift the rows of the state.
3. **MixColumns** — apply a linear transformation to each column.
4. **AddRoundKey** — XOR the state with the round key.

The tenth and final round omits MixColumns and applies SubBytes, ShiftRows and AddRoundKey, in that order. Before the rounds begin, the initial key is added to the state.

The implementation is organised around the following functions:

- `sub_bytes()`
- `shift_rows()`
- `mix_cols()`
- `add_round_key()`
- `generate_round_keys()`

I will introduce each transformation, explain the relevant mathematics and then show its Rust implementation.

### SubBytes

The AES substitution box (S-box) is a bijection from the 256 possible byte values to themselves. It provides the non-linear part of the cipher, helping AES resist linear and differential cryptanalysis. The S-box is constructed using multiplicative inverses in the finite field $GF(2^8)$ (with zero handled separately), followed by an affine transformation over $GF(2)$. The table below contains the resulting substitution values.

```rust
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
```

The function below iterates over the 16-byte state and replaces each byte with the corresponding S-box value. The state is modified in place through a mutable reference.

```rust
fn sub_bytes(state: &mut [u8;16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}
```

### Shift Rows

The **ShiftRows** operation can be represented as a map $M$ acting on the AES state, a $4\times4$ matrix whose entries are bytes:

$M : GF(2^8)^{4\times4} \to GF(2^8)^{4\times4}.$

The first row is unchanged. The second, third and fourth rows are cyclically shifted left by one, two and three byte positions respectively. With the state stored column by column in the one-dimensional array, the transformation is shown below.

$$
\begin{aligned}
M\left(\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_1 & b_5 & b_9 & b_{13} \\
b_2 & b_6 & b_{10} & b_{14} \\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}\right)
&=
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_5 & b_9 & b_{13} & b_1 \\
b_{10} & b_{14} & b_2 & b_6 \\
b_{15} & b_3 & b_7 & b_{11}
\end{bmatrix}
\end{aligned}
$$

ShiftRows moves bytes between columns. Together with MixColumns, it contributes to **diffusion**: after the transformations are applied across successive rounds, each input byte influences many output bytes. The Rust function below performs the row shifts in place.

```rust
fn shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}
```

The function receives a mutable reference to the state. It first copies the original state into `temp`, then reads from that copy while writing the shifted values back into `state`. Using a temporary copy prevents earlier assignments from overwriting values that are still needed.

## MixColumns

The **MixColumns** operation applies the same linear transformation to each four-byte column of the state. Its matrix coefficients and arithmetic are defined in the finite field $GF(2^8)$. Before writing the transformation, it is useful to review how this finite field works.

### The finite field $GF(2^8)$

- $GF(2^8)$ is a finite field containing $2^8=256$ elements.
- Each element can be represented by an 8-bit byte, or equivalently by a binary polynomial of degree at most 7.
- Addition is bitwise XOR. For example, adding two field elements $a$ and $b$ is written $a\oplus b$.
- Multiplication is polynomial multiplication over $GF(2)$ followed by reduction modulo the irreducible polynomial
  $m(x)=x^8+x^4+x^3+x+1$.
- A byte with bits $b_7b_6\ldots b_0$ represents the polynomial
  $b_7x^7+b_6x^6+\cdots+b_1x+b_0$.

The modulus is what keeps every result representable by a byte. In the AES field, the relation $x^8\equiv x^4+x^3+x+1$ is used during reduction.

### Example: multiplying in $GF(2^8)$

Consider the product $255\cdot3$ in the AES field.

1. **Write the bytes as polynomials.** The byte 255 is
   $x^7+x^6+x^5+x^4+x^3+x^2+x+1$, and the byte 3 is $x+1$.

2. **Multiply over $GF(2)$.** Let
   $a(x)=1+x+x^2+\cdots+x^7$. Then
   $$
   a(x)(x+1)=x^8+1,
   $$
   because each intermediate power appears twice and cancels in characteristic two.

3. **Reduce modulo the AES polynomial.** Since
   $m(x)=x^8+x^4+x^3+x+1=0$ in the field,
   $$
   x^8\equiv x^4+x^3+x+1.
   $$
   Therefore,
   $$
   x^8+1\equiv x^4+x^3+x.
   $$

4. **Convert back to a byte.** The polynomial $x^4+x^3+x$ has binary representation
   `00011010`, hexadecimal representation `0x1A`, and decimal value 26.

Thus, in the AES field, $255\cdot3=26$. This is not ordinary integer multiplication; it is multiplication followed by reduction in $GF(2^8)$.

### Rust implementation

The following routine uses the usual shift-and-XOR method for multiplication in $GF(2^8)$. It examines the bits of `b` from least significant to most significant. When a bit is set, the current value of `a` is XORed into the result. At each iteration, `a` is multiplied by $x$ (with reduction if its degree would exceed 7), and `b` is shifted right.

```rust
fn gal_mul(mut a: u8, mut b: u8) -> u8 {
   //initially sets result to 0
    let mut result = 0u8;
    //loops while b is greater than 0
    while b > 0 {
        // checks if least significant bit is on and executes below codeif it is
        if b & 1 != 0 {
            // XOR's the result with a i.e addition in GF(2^8)
            result ^= a;
        }
        // We than check if the most significant bit is on
        let carry = a & 0x80;
        // Then we perform a binary shift to the left i.e multiplication by 2 i.e x in polynomial form
        a <<= 1;
        // If the most significant bit was on we the XOR a with the reduction polynomial x^8+x^4+x^3+x^1+1 which is 0x1b in hexadecimal
        // thus keeping a and by extension the result in GF(2^8) by not allowing degree to exceed 7 i.e <= 7
        if carry != 0 {
            a ^= 0x1b;
        }
        // Finally we shift b one place to the right i.e division by 2 or x
        b >>= 1;
    }
    result
}
```

### How the multiplication routine works

The routine is a bitwise version of polynomial multiplication. At each iteration, the least significant bit of `b` determines whether the current `a` contributes to the result. The routine then shifts `b` right, which moves to its next coefficient, and multiplies `a` by $x$ by shifting it left.

If the high bit of `a` was set before the shift, the result would contain an $x^8$ term. XORing with `0x1b` performs the required reduction, because `0x1b` represents $x^4+x^3+x+1$, the lower-degree part of the AES modulus after substituting for $x^8$.

The process ends when all bits of `b` have been processed. The accumulated XOR is the product in $GF(2^8)$.

#### Worked trace

1. $ a(x) = x^3+x^2 $, $ b(x) = x^2 + x $, $ r = 0 $
2. $ a(x) = x^4 + x^3 $, $ b(x) = x + 1 $, $ r = x^3+x^2 $
3. $ a(x) = x^5+ x^4 $, $ b(x) = 1 $, $ r = x^3 + x^2 + x^4 + x^3 $
4. $ a(x) = x^6+x^5 $, $ b(x) = 0 $, $ r = x^3 + x^2 + x^4 + x^3 + x^5 + x^4 $
5. $ b(x) = 0 $ so $ r $ is returned $ r = x^3 + x^2 + x^4 + x^3 +x^5 + x^4 = x^5 + (x^4 \oplus x^4) + (x^3 \oplus x^3) + x^2 = x^5 + 0 + 0 + x^2 = x^5 + x^2 $

## The MixColumns transformation

Now that the field arithmetic is defined, we can describe MixColumns. For a column with entries $s_0,s_1,s_2,s_3$, the AES transformation is multiplication by the following matrix, with all arithmetic performed in $GF(2^8)$:

$ P: \mathbb{B}^{4 \times 1} \to \mathbb{B}^{4 \times 1} $

$$
\begin{aligned}
P\left(\begin{bmatrix} s_0 \\ s_1 \\ s_2 \\ s_3 \end{bmatrix}\right)
&=
\begin{bmatrix}
02 & 03 & 01 & 01 \\
01 & 02 & 03 & 01 \\
01 & 01 & 02 & 03 \\
03 & 01 & 01 & 02
\end{bmatrix}
\begin{bmatrix}
s_0 \\
s_1 \\
s_2 \\
s_3
\end{bmatrix}
&=
\begin{bmatrix}
(02 \cdot s_0) \oplus (03 \cdot s_1) \oplus (01 \cdot s_2) \oplus (01 \cdot s_3) \\
(01 \cdot s_0) \oplus (02 \cdot s_1) \oplus (03 \cdot s_2) \oplus (01 \cdot s_3) \\
(01 \cdot s_0) \oplus (01 \cdot s_1) \oplus (02 \cdot s_2) \oplus (03 \cdot s_3) \\
(03 \cdot s_0) \oplus (01 \cdot s_1) \oplus (01 \cdot s_2) \oplus (02 \cdot s_3)
\end{bmatrix}\end{aligned}
$$

The Rust implementation below applies this matrix independently to each of the four columns.

```rust
fn mix_cols(state: &mut [u8; 16]) {
    let temp = *state;
    for col in 0..4 {
        let offset = col * 4;
        let s = [
            temp[offset],
            temp[offset + 1],
            temp[offset + 2],
            temp[offset + 3],
        ];

        state[offset] = gal_mul(s[0], 0x02) ^ gal_mul(s[1], 0x03) ^ s[2] ^ s[3];
        state[offset + 1] = s[0] ^ gal_mul(s[1], 0x02) ^ gal_mul(s[2], 0x03) ^ s[3];
        state[offset + 2] = s[0] ^ s[1] ^ gal_mul(s[2], 0x02) ^ gal_mul(s[3], 0x03);
        state[offset + 3] = gal_mul(s[0], 0x03) ^ s[1] ^ s[2] ^ gal_mul(s[3], 0x02);
    }
}
```

## AddRoundKey

**AddRoundKey** XORs each of the 16 state bytes with the corresponding byte of the 128-bit round key. XOR is appropriate here because addition in $GF(2^8)$ is bitwise XOR.

```rust
fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(key.iter()) {
        *s ^= k;
    }
}
```

## The AES-128 key schedule

AES-128 expands the original 128-bit key into 11 round keys: the initial key plus one key for each of the 10 rounds. Each round key is 128 bits.

### Key expansion overview

The original key is represented as four 32-bit words, $W_0,W_1,W_2,W_3$. The expanded key contains 44 words in total, grouped into 11 round keys of four words each.

### Key expansion steps

The key schedule uses three operations:

- **SubWord:** apply the AES S-box independently to each byte of a 32-bit word.
- **RotWord:** cyclically rotate a word left by one byte:
  $\operatorname{RotWord}([b_0,b_1,b_2,b_3])=[b_1,b_2,b_3,b_0]$.
- **Round constant:** XOR a round-dependent constant into the first byte of the transformed word. Its first byte is a successive power of $x$ in $GF(2^8)$, beginning with `0x01`; the ten values are listed in `RCON` below.

### Round-key generation

**Initial words:** The first four words $W_0, W_1, W_2, W_3$ come directly from the original key $K$.
**Next words:** For $i = 4, 5, \dots, 43$:

If $i$ is a multiple of 4, calculate:

$W_i = W_{i-4} \oplus \operatorname{SubWord}(\operatorname{RotWord}(W_{i-1})) \oplus RCON[i/4]$

Otherwise:

$W_i = W_{i-4} \oplus W_{i-1}$

```rust
// First-byte values of the ten AES-128 round constants.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn generate_round_keys(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys = [[0u8; 16]; 11];
    //sets the first round key to the original key
    round_keys[0].copy_from_slice(key);
    //creates a temporary word that we can perform operations on
    let mut temp = [0u8; 4];
    for i in 1..11 {
        //sets the temp value to  the last word of the previous round key
        temp.copy_from_slice(&round_keys[i - 1][12..16]);
        //rotares the temp left by 1 value
        temp.rotate_left(1);
        //substitue each byte in the word using SBOX lookup table
        for byte in &mut temp {
            *byte = SBOX[*byte as usize];
        }
        //XOR's the temp word with the Round constant for the round
        temp[0] ^= RCON[i - 1];
        //loops over the 4 words in the round key applying the following operations
        for j in 0..4 {
            //the round keys first word is a multiple of 4 so we xor with the temp
            // which is SubWord(ShiftWord(W_i)) xor RCON[i] thus mirroring the equation above
            round_keys[i][j] = round_keys[i - 1][j] ^ temp[j];
            //for the next 3 words with simply XOR with the previous word of the current round key
            //and the word in the same position on the previous round keys (W_i-1 and W_i_4) correspondingly
            // we repeat this 4 times for each byte of the 4 words
            round_keys[i][j + 4] = round_keys[i - 1][j + 4] ^ round_keys[i][j];
            round_keys[i][j + 8] = round_keys[i - 1][j + 8] ^ round_keys[i][j + 4];
            round_keys[i][j + 12] = round_keys[i - 1][j + 12] ^ round_keys[i][j + 8];
        }
    }

    round_keys
}
```

## Encrypting a block

We can now combine the transformations to implement AES-128 encryption of a single 128-bit block. The function takes the plaintext block and key as mutable byte arrays; after the call, the block contains the ciphertext.

```rust
pub fn block_encrypt(state: &mut [u8; 16], key: &[u8; 16]) {
    let round_keys = generate_round_keys(key);
    add_round_key(state, &round_keys[0]);
    for round in round_keys.iter().take(10).skip(1) {
        sub_bytes(state);
        shift_rows(state);
        mix_cols(state);
        add_round_key(state, round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[10]);
}
```

## Decryption

To recover the original plaintext, we need to reverse the encryption transformations. AddRoundKey is its own inverse because XORing with the same round key twice restores the original byte. The other transformations have corresponding inverse operations:

- `inv_sub_bytes()`
- `inv_shift_rows()`
- `inv_mix_cols()`

The decryption routine applies the round keys in reverse order and uses the inverse transformations in the order required to undo each encryption round.

- add_round_key
- inv_sub_bytes
- inv_shift_rows
- inv_mix_cols

The inverse transformations undo the corresponding encryption steps. AddRoundKey needs no separate inverse function: XOR is self-inverse, as shown below.

### Why AddRoundKey is its own inverse

For bits $b,k\in\{0,1\}$, XOR satisfies
$$
(b\oplus k)\oplus k
=b\oplus(k\oplus k)
=b\oplus0
=b.
$$
The same identity applies byte by byte to the state and round key. Therefore, applying AddRoundKey twice with the same key restores the original state.

We can now implement the inverse transformations.

### InvSubBytes

The inverse S-box reverses the substitution performed by the forward S-box. It can be constructed by reversing the lookup table: if `SBOX[i] = j`, then `INVSBOX[j] = i`. The table below contains those inverse values.

```rust
const INVSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];
```

As with the forward transformation, decryption applies the inverse lookup independently to each byte of the state:

```rust
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INVSBOX[*byte as usize]
    }
}
```

### InvShiftRows

InvShiftRows reverses ShiftRows by cyclically shifting the second, third and fourth rows right by one, two and three byte positions respectively. The first row remains unchanged.

$$
\begin{aligned}M\left(
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_1 & b_5 & b_9 & b_{13} \\
b_2 & b_6 & b_{10} & b_{14} \\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}
\right)
&=
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_{13} & b_1 & b_5 & b_9 \\
b_{10} & b_{14} & b_2 & b_6 \\
b_7 & b_{11} & b_{15} & b_3
\end{bmatrix}\end{aligned}
$$

```rust
fn inv_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[4] = temp[4];
    state[8] = temp[8];
    state[12] = temp[12];
    state[1] = temp[13];
    state[2] = temp[10];
    state[3] = temp[7];
    state[5] = temp[1];
    state[6] = temp[14];
    state[7] = temp[11];
    state[9] = temp[5];
    state[10] = temp[2];
    state[11] = temp[15];
    state[13] = temp[9];
    state[14] = temp[6];
    state[15] = temp[3];
}
```

### InvMixColumns

InvMixColumns applies the inverse of the MixColumns matrix to each state column. Its coefficients are also elements of $GF(2^8)$, and all multiplication and addition are performed in that field. The inverse matrix is encoded directly in the implementation below.

```rust
fn inv_mix_cols(state: &mut [u8; 16]) {
    let temp = *state;
    for col in 0..4 {
        let offset = col * 4;
        let s = [
            temp[offset],
            temp[offset + 1],
            temp[offset + 2],
            temp[offset + 3],
        ];

        state[offset] =
            gal_mul(s[0], 0x0e) ^ gal_mul(s[1], 0x0b) ^ gal_mul(s[2], 0x0d) ^ gal_mul(s[3], 0x09);
        state[offset + 1] =
            gal_mul(s[0], 0x09) ^ gal_mul(s[1], 0x0e) ^ gal_mul(s[2], 0x0b) ^ gal_mul(s[3], 0x0d);
        state[offset + 2] =
            gal_mul(s[0], 0x0d) ^ gal_mul(s[1], 0x09) ^ gal_mul(s[2], 0x0e) ^ gal_mul(s[3], 0x0b);
        state[offset + 3] =
            gal_mul(s[0], 0x0b) ^ gal_mul(s[1], 0x0d) ^ gal_mul(s[2], 0x09) ^ gal_mul(s[3], 0x0e);
    }
}
```

### Decrypting a block

Decryption starts by adding the final round key (index 10) to the ciphertext. It then processes the remaining round keys in reverse order, applying InvShiftRows, InvSubBytes, AddRoundKey and InvMixColumns. The final inverse round omits InvMixColumns and finishes by adding the original key (index 0). This reverses the encryption process and recovers the plaintext.

```rust
pub fn block_decrypt(state: &mut [u8; 16], key: &[u8; 16]) {
    let round_keys = generate_round_keys(key);
    add_round_key(state, &round_keys[10]);
    for round in round_keys.iter().take(10).skip(1).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round);
        inv_mix_cols(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &round_keys[0]);
}
```

## Testing and conclusion

The implementation now contains the forward and inverse transformations needed to encrypt and decrypt one AES-128 block. The tests below check the transformations and compare the encryption and decryption routines against a known-answer test vector from the NIST AES specification, [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final). Passing this vector is a useful correctness check, although it is not a substitute for extensive testing, independent review or a production cryptographic library.

```rust
#[cfg(test)]
mod tests {
    use hex_lit::hex;

    use super::*;
    #[test]
    fn test_shift_rows() {
        let original = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        let mut state = original;
        shift_rows(&mut state);
        assert_eq!(state, expected);
        inv_shift_rows(&mut state);
        assert_eq!(state, original);
    }
    #[test]
    fn test_byte_sub() {
        let original = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        let mut state = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        sub_bytes(&mut state);
        inv_sub_bytes(&mut state);
        assert_eq!(state, original);
    }
    #[test]
    fn test_gal_mul() {
        // Small field-multiplication checks.
        assert_eq!(gal_mul(2, 2), 4);
        assert_eq!(gal_mul(6, 3), 10);
        assert_eq!(gal_mul(7, 12), 36);
        assert_eq!(gal_mul(12, 12), 80);
    }
    #[test]
    fn test_mix_columns() {
        // Example MixColumns input/output from the AES specification.
        let original = hex!("d4bf5d30e0b452aeb84111f11e2798e5");
        let expected = hex!("046681e5e0cb199a48f8d37a2806264c");
        let mut state = original;
        mix_cols(&mut state);
        assert_eq!(state, expected);
        inv_mix_cols(&mut state);
        assert_eq!(state, original);
    }
    #[test]
    fn test_encryption() {
        // Known-answer test vector from NIST FIPS 197.
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mut plaintext = hex!("00112233445566778899aabbccddeeff");
        let expected = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
        block_encrypt(&mut plaintext, &key);
        assert_eq!(plaintext, expected);
    }
    #[test]
    fn test_decryption() {
        // Known-answer test vector from NIST FIPS 197.
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mut ciphertext = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
        let expected = hex!("00112233445566778899aabbccddeeff");
        block_decrypt(&mut ciphertext, &key);
        assert_eq!(ciphertext, expected);
    }
}
```

---

## Scope and security limitations

This project implements the AES-128 block transformation and its inverse. It does **not** implement ECB, CBC, CTR or GCM mode, message padding, nonce management or authentication. In particular, a raw block cipher is not by itself a safe way to encrypt arbitrary messages. Do not use this educational implementation for real-world data; use a well-maintained authenticated-encryption library such as AES-GCM instead.
