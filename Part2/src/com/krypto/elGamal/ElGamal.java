package com.krypto.elGamal;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

public final class ElGamal {
  String publicKey;
  String privateKey;
  String publicKeyFile;
  String privateKeyFile;

  // public key
  public BigInteger p;
  public BigInteger g;
  public BigInteger y;

  // private key
  public BigInteger x;

  public ElGamal(BigInteger p, BigInteger g, BigInteger y, BigInteger x) {
    this.p = p;
    this.g = g;
    this.y = y;
    this.x = x;
  }

  public ElGamal(BigInteger p, BigInteger g, BigInteger y) {
    this.p = p;
    this.g = g;
    this.y = y;
  }

  public void getPrimeAndGenerator() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger represents a prime number will
                         // exceed (1-1/2^certainty)

    p = null;
    BigInteger q = null;
    do {
      q = new BigInteger(k - 1, certainty, sc);
      p = q.multiply(BigIntegerUtil.TWO).add(BigIntegerUtil.ONE); // secure prime p = 2q+1
    } while (!p.isProbablePrime(certainty));

    BigInteger MINUS_ONE = BigInteger.ONE.negate().mod(p); // -1 mod p

    g = null;
    BigInteger factor = null;
    do {
      // 2 <= g < p-1
      g = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);
      factor = g.modPow(q, p);
    } while (!factor.equals(MINUS_ONE));
  }

  public BigInteger encipher(BigInteger message) {
    Random sc = new SecureRandom();

    int Lp = p.bitLength(); // bitlength of p (512 bit)
    int L = (Lp - 1) / 8; // blocksize

    // read cleartext
    BigInteger M = message;
    // random two <= k < p-1
    BigInteger k = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);

    BigInteger a = g.modPow(k, p); // g^k mod p
    BigInteger b = M.multiply(y.modPow(k, p)).mod(p); // (M * y^k mod p) mod p

    BigInteger C = a.add(b.multiply(p)); // a + b*p

    return C;

  }

  public BigInteger decipher(BigInteger cipher) {
    // read ciphertext
    BigInteger C = cipher;
    BigInteger a = C.mod(p);
    BigInteger b = C.divide(p);

    BigInteger exponent = p.subtract(BigInteger.ONE).subtract(x);
    BigInteger z = a.modPow(exponent, p); // a^(p-1-x) mod p

    BigInteger M = z.multiply(b).mod(p); // M = z * b mod p

    return M;
  }

  private void Logger(String event) {
    System.out.println("ElGamal$  " + event);
  }

  public BigInteger sign(BigInteger message) {
    Random sc = new SecureRandom();

    int Lp = p.bitLength(); // bitlength of p (512 bit)
    int L = (Lp - 1) / 8; // blocksize

    BigInteger M = message;

    // random k with gcd(k, p-1) = 1
    BigInteger k = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);
    while (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
      // random two <= k < p-1
      k = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.subtract(BigIntegerUtil.ONE), sc);
    }

    BigInteger r = g.modPow(k, p);
    BigInteger t = k.modInverse(p.subtract(BigInteger.ONE)); // t = k^-1 mod p-1
    BigInteger s = (M.subtract(x.multiply(r))).multiply(t); // (M-xr)k^-1
    s = s.mod(p.subtract(BigInteger.ONE)); // mod (p-1)

    BigInteger C = r.add(s.multiply(p)); // r + s*p

    return C;
  }

  public boolean verify(BigInteger message, BigInteger cipher) {
    int Lp = p.bitLength(); // bitlength of p (512 bit)
    int L = (Lp - 1) / 8; // blocksize

    // read ciphertext
    BigInteger C = cipher;
    BigInteger M = message;

    Boolean verified = true;

    BigInteger r = C.mod(p);
    BigInteger s = C.divide(p);

    if ((r.compareTo(BigInteger.ONE) >= 0) && (r.compareTo(p.subtract(BigInteger.ONE)) <= 0)) {
      BigInteger yr = y.modPow(r, p); // y^r mod p
      BigInteger rs = r.modPow(s, p); // r^s mod p

      BigInteger v1 = yr.multiply(rs).mod(p); // y^r * r^s mod p

      BigInteger v2 = g.modPow(M, p);

      if (!v1.equals(v2)) {
        verified = false;
      }
    } else {
      System.out.println("Abbruch, da r >= 1 oder r <= p-1 nicht erfüllt ist!");
      verified = false;
    }

    return verified;

  }

}
