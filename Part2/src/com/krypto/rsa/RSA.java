package com.krypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public class RSA {
  public BigInteger e, n, d;

  public RSA() {
    generateRSAKeys();
  }

  public void generateRSAKeys() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger
    // represents a prime number will
    // exceed (1-1/2^certainty)

    BigInteger p = new BigInteger(k - 1, certainty, sc);
    BigInteger q = new BigInteger(k - 1, certainty, sc);

    // n=pq
    n = p.multiply(q);

    // phi(n) = (p-1)(q-1)
    BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

    // 1 < e < phi(n) mit ggT(e, phi(n))=1
    e = null;
    do {
      // 2 <= e < phi(n)
      e = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, phi, sc);

    } while (!(e.gcd(phi)).equals(BigInteger.ONE));

    // d = e^-1 mod phi(n)
    d = e.modInverse(phi);
  }
}
