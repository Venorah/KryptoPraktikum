import com.krypto.idea.IDEA;
import com.krypto.rsa.RSA;
import com.krypto.elGamal.ElGamalCipher;
import com.krypto.fingerprint.Fingerprint;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;

public final class ObliviousTransfer implements Protocol {

  static private int MinPlayer = 2; // Minimal number of players
  static private int MaxPlayer = 2; // Maximal number of players
  static private String NameOfTheGame = "Station To Station";
  private Communicator Com;

  private BigInteger ZERO = BigIntegerUtil.ZERO;
  private BigInteger ONE = BigIntegerUtil.ONE;
  private BigInteger TWO = BigIntegerUtil.TWO;

  private boolean betray = false;

  public void setCommunicator(Communicator com) {
    Com = com;
  }

  /**
   * Aktionen der beginnenden Partei. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Alice.
   */
  public void sendFirst() {
    System.out.println("-- Alice --");
    if (betray) {
      System.out.println("ACHTUNG: Betrugsmodus aktiv!!!");
    }

    // Hard coded ElGamal
    BigInteger p_A = new BigInteger("9529724065946661791619214607058571455523501317487241243976232835925891360305980300387951706129488838265474360650203061294036271683018196103397777779653383");
    BigInteger g_A = new BigInteger("1903807535454217102284567533195568004730442229592280053615111688429468626330712656899587676318279710558858454415018302802562437699598642215407022395224935");
    BigInteger y_A = new BigInteger("2779459789810637390587020096873488006835520565965769469851626928825192486936358410902751431979129618418717414793278325979795486789867808134854812793606315");
    // private:
    BigInteger x_A = new BigInteger("8408731721182017680099031010877093001204025969158347812072520791359337488056415633917552133990647980002619034528133832546926963071036452214551633046614916");
    // Objekt initialisieren mit priv key
    ElGamalCipher elGamal_A = new ElGamalCipher(p_A, g_A, y_A, x_A);

    // Alice sendet ElGamal public key an Bob
    Com.sendTo(1, elGamal_A.p.toString(16)); // S1
    Com.sendTo(1, elGamal_A.g.toString(16)); // S2
    Com.sendTo(1, elGamal_A.y.toString(16)); // S3

    // Alice wählt zufällig zwei Nachrichten m_o, m_1 in Z_p, 1 <= m < p
    BigInteger m_0 = BigIntegerUtil.randomBetween(ONE, elGamal_A.p);
    BigInteger m_1 = BigIntegerUtil.randomBetween(ONE, elGamal_A.p);

    // Alice sendet m_0, m_1 an Bob
    Com.sendTo(1, m_0.toString(16)); // S4
    Com.sendTo(1, m_1.toString(16)); // S5

  }

  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Bob.
   */
  public void receiveFirst() {
    System.out.println("-- Bob --");
    if (betray) {
      System.out.println("ACHTUNG: Betrugsmodus aktiv!!!");
    }

    // Bob empfängt Alice ElGamal pub key
    BigInteger p_A = new BigInteger(Com.receive(), 16); // R1
    BigInteger g_A = new BigInteger(Com.receive(), 16); // R2
    BigInteger y_A = new BigInteger(Com.receive(), 16); // R3

    // ElGamal Objekt ohne priv key bauen
    ElGamalCipher elGamal_A = new ElGamalCipher(p_A, g_A, y_A);

    // Bob wählt zufällig ein r in {0,1} und k in Z_p
    BigInteger r = BigIntegerUtil.randomBetween(ZERO, TWO);
    BigInteger k = BigIntegerUtil.randomBetween(ONE, p_A);

    // BigInteger q =

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

}