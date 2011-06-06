import com.krypto.idea.IDEA;
import com.krypto.rsa.RSA;
import com.krypto.fingerprint.Fingerprint;

import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;

public final class StationToStation implements Protocol {

  static private int MinPlayer = 2; // Minimal number of players
  static private int MaxPlayer = 2; // Maximal number of players
  static private String NameOfTheGame = "Station To Station";
  private Communicator Com;

  BigInteger ZERO = BigIntegerUtil.ZERO;
  BigInteger ONE = BigIntegerUtil.ONE;
  BigInteger TWO = BigIntegerUtil.TWO;

  BigInteger p, g; // Primzahl p, prim. W. g

  BigInteger x, y, S;
  BigInteger x_remote, y_remote, S_remote;

  public void getPrimeAndGenerator() {
    Random sc = new SecureRandom();
    int k = 512; // prime number with k=512 bits
    int certainty = 100; // The probability that the new BigInteger
    // represents a prime number will
    // exceed (1-1/2^certainty)

    p = null;
    BigInteger q = null;
    do {
      q = new BigInteger(k - 1, certainty, sc);
      p = q.multiply(TWO).add(ONE); // secure
      // prime
      // p =
      // 2q+1
    } while (!p.isProbablePrime(certainty));

    BigInteger MINUS_ONE = ONE.negate().mod(p); // -1 mod p

    g = null;
    BigInteger factor = null;
    do {
      // 2 <= g < p-1
      g = BigIntegerUtil.randomBetween(TWO, p.subtract(ONE), sc);
      factor = g.modPow(q, p);
    } while (!factor.equals(MINUS_ONE));
  }

  public void setCommunicator(Communicator com) {
    Com = com;
  }

  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Alice.
   */
  public void sendFirst() {
    // fingerprint werte aus datei auslesen
    Fingerprint fingerprint = new Fingerprint(new File("HashParameter"));

    // alice wählt p und g und sendet diese an bob
    getPrimeAndGenerator();
    System.out.println("p: " + p);
    System.out.println("g: " + g);
    Com.sendTo(1, p.toString(16));
    Com.sendTo(1, g.toString(16));

    // alice sendet öffentlichen schlüssel an bob
    RSA rsa_A = new RSA();
    System.out.println("RSA Alice e: " + rsa_A.e);
    System.out.println("RSA Alice n: " + rsa_A.n);
    System.out.println("RSA Alice d: " + rsa_A.d);
    Com.sendTo(1, rsa_A.e.toString(16));
    Com.sendTo(1, rsa_A.n.toString(16));

    // alice empfängt öffentlichen schlüssel von bob
    BigInteger e_B = new BigInteger(Com.receive(), 16);
    BigInteger n_B = new BigInteger(Com.receive(), 16);
    System.out.println("Bob e: " + e_B);
    System.out.println("Bob n: " + n_B);

    // zufällige zahl x_A in {1,...,p-2} -> randomBetween 1 <= x_A < p-1
    BigInteger x_A = BigIntegerUtil.randomBetween(ONE, p.subtract(ONE));
    // alice wählt x_A = g^(x_A) mod p
    BigInteger y_A = g.modPow(x_A, p);
    // y_A an bob senden
    Com.sendTo(1, y_A.toString(16));

    // alice empfängt
    BigInteger y_B = new BigInteger(Com.receive(), 16);

    // alice empfängt certificate
    String ID = new String(Com.receive());
    byte[] data = Com.receive().getBytes();
    BigInteger signature = new BigInteger(Com.receive(), 16);
    // wieder certificate objekt draus machen
    Certificate cert = new Certificate(ID, data, signature);
    
    //TODO: check certificate


    String S_B_encrypted = new String(Com.receive());

    // alice berechnet k
    BigInteger k = y_B.modPow(x_A, p);

    // TODO: zertifikat überprüfen

  }

  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Bob.
   */
  public void receiveFirst() {
    // fingerprint werte aus datei auslesen
    Fingerprint fingerprint = new Fingerprint(new File("HashParameter"));

    // bob bekommt p und g von alice
    p = new BigInteger(Com.receive(), 16);
    g = new BigInteger(Com.receive(), 16);
    System.out.println("p: " + p);
    System.out.println("g: " + g);

    // bob bekommt öffentlichen rsa schlüssel von alice
    BigInteger e_A = new BigInteger(Com.receive(), 16);
    BigInteger n_A = new BigInteger(Com.receive(), 16);
    System.out.println("Alice e: " + e_A);
    System.out.println("Alice n: " + n_A);

    // bob sendet seinen öffentlichen schlüssel
    RSA rsa_B = new RSA();
    System.out.println("RSA Bob e: " + rsa_B.e);
    System.out.println("RSA Bob n: " + rsa_B.n);
    System.out.println("RSA Bob d: " + rsa_B.d);
    Com.sendTo(0, rsa_B.e.toString(16));
    Com.sendTo(0, rsa_B.n.toString(16));

    // bob empfängt y_A
    BigInteger y_A = new BigInteger(Com.receive(), 16);
    System.out.println("y_A: " + y_A);

    // zufällige zahl x_B in {1,...,p-2} -> randomBetween 1 <= x_B < p-1
    BigInteger x_B = BigIntegerUtil.randomBetween(ONE, p.subtract(ONE));
    // bob wählt x_B = g^(x_B) mod p
    BigInteger y_B = g.modPow(x_B, p);
    // y_B an alice senden
    Com.sendTo(0, y_B.toString(16));

    // bob bestimmt schlüssel
    BigInteger k = y_A.modPow(x_B, p);
    System.out.println("k: " + k.toString());

    // signatur
    BigInteger m = y_B.multiply(p).add(y_A); // h(y_B,y_A) = y_B * p + y_A laut heft
    BigInteger hash = fingerprint.hash(m.toString(16));
    BigInteger S_B = rsa_B.getSignatur(hash); // S_B = hash^d_B mod n_B
    System.out.println("Signatur S_B: " + S_B);

    // bob sendet y_B
    Com.sendTo(0, y_B.toString(16));

    // zertifikat
    TrustedAuthority ta = new TrustedAuthority();
    byte[] data = (e_A.xor(n_A)).toByteArray();
    Certificate Z_B = ta.newCertificate(data);

    // bob sendet certificate
    Com.sendTo(0, Z_B.getID().toString()); // ID
    Com.sendTo(0, Z_B.getData().toString()); // data (pub key)
    Com.sendTo(0, Z_B.getSignature().toString(16)); // signature

    // encrypted S_B with idea
    int l = k.bitLength();
    BigInteger key = k.shiftRight(l - 128);
    System.out.println(key);
    System.out.println(key.bitLength());
    IDEA idea = new IDEA(key);
    String S_B_encrypted = idea.encipher(S_B.toString(16));

    // bob sendet S_B_encrypted
    Com.sendTo(0, S_B_encrypted);

  }

  public String nameOfTheGame() {
    return NameOfTheGame;
  }

  public int minPlayer() {
    return MinPlayer;
  }

  public int maxPlayer() {
    return MaxPlayer;
  }
  
  public boolean checkSignature(BigInteger e_A, BigInteger n_A, BigInteger signature){
    boolean isCorrekt = false;

    TrustedAuthority ta = new TrustedAuthority();
    
    return isCorrekt;
  }
}