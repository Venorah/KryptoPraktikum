import com.krypto.elGamal.ElGamal;

import java.math.BigInteger;
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

  private boolean betray = true;

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

    // Hard coded messages M_0 and M_1
    BigInteger[] M = new BigInteger[2];
    M[0] = new BigInteger("11111111111111111111111111111111111111111111111111111111111");
    M[1] = new BigInteger("22222222222222222222222222222222222222222222222222222222222");

    if (betray) {
      M[1] = new BigInteger("11111111111111111111111111111111111111111111111111111111111");
    }

    // Hard coded ElGamal
    BigInteger p_A = new BigInteger("9529724065946661791619214607058571455523501317487241243976232835925891360305980300387951706129488838265474360650203061294036271683018196103397777779653383");
    BigInteger g_A = new BigInteger("1903807535454217102284567533195568004730442229592280053615111688429468626330712656899587676318279710558858454415018302802562437699598642215407022395224935");
    BigInteger y_A = new BigInteger("2779459789810637390587020096873488006835520565965769469851626928825192486936358410902751431979129618418717414793278325979795486789867808134854812793606315");
    // private:
    BigInteger x_A = new BigInteger("8408731721182017680099031010877093001204025969158347812072520791359337488056415633917552133990647980002619034528133832546926963071036452214551633046614916");
    // Objekt initialisieren mit priv key
    ElGamal elGamal_A = new ElGamal(p_A, g_A, y_A, x_A);

    // Alice sendet ElGamal public key an Bob
    Com.sendTo(1, elGamal_A.p.toString(16)); // S1
    Com.sendTo(1, elGamal_A.g.toString(16)); // S2
    Com.sendTo(1, elGamal_A.y.toString(16)); // S3

    // Alice wählt zufällig zwei Nachrichten m_0, m_1 in Z_p, 1 <= m < p
    BigInteger[] m = new BigInteger[2];
    m[0] = BigIntegerUtil.randomBetween(ONE, elGamal_A.p);
    m[1] = BigIntegerUtil.randomBetween(ONE, elGamal_A.p);
    System.out.println("m_0: " + m[0]);
    System.out.println("m_1: " + m[1]);

    // Alice sendet m_0, m_1 an Bob
    Com.sendTo(1, m[0].toString(16)); // S4
    Com.sendTo(1, m[1].toString(16)); // S5

    // Alice empfängt q
    BigInteger q = new BigInteger(Com.receive(), 16); // R6

    // Alice berechnet k_0', k_1', hier k_A[0] und k_A[1] genannt
    BigInteger[] k_A = new BigInteger[2];
    for (int i = 0; i < 2; i++) {
      k_A[i] = elGamal_A.decipher((q.subtract(m[i])).mod(elGamal_A.p.multiply(elGamal_A.p))).mod(elGamal_A.p); // D_A((q-m_i) mod p^2) mod p
    }
    System.out.println("k_A[0]: " + k_A[0]);
    System.out.println("k_A[1]: " + k_A[1]);

    // zufällig s wählen
    int s = BigIntegerUtil.randomBetween(ZERO, TWO).intValue();
    System.out.println("s: " + s);

    BigInteger[] send = new BigInteger[2];
    send[0] = (M[0].add(k_A[s])).mod(elGamal_A.p);
    send[1] = (M[1].add(k_A[s ^ 1])).mod(elGamal_A.p);

    System.out.println("send_0: " + send[0]);
    System.out.println("send_1: " + send[1]);

    int r = -1;
    if (betray) { // try to find right r :D
      r = BigIntegerUtil.randomBetween(ZERO, TWO).intValue();
    }

    // Signatur berechnen
    BigInteger[] S = new BigInteger[2];
    for (int i = 0; i < 2; i++) {
      if (betray) {
        if (i == r) { // gefälschte signatur
          S[i] = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, elGamal_A.p.multiply(elGamal_A.p));
        } else {
          S[i] = elGamal_A.sign(k_A[i]);
        }
      } else { // no betraying
        S[i] = elGamal_A.sign(k_A[i]);
      }
    }
    System.out.println("S_0: " + S[0]);
    System.out.println("S_1: " + S[1]);

    // Alice sendet send_0, send_1, s, S[0], S[1]
    Com.sendTo(1, send[0].toString(16)); // S7
    Com.sendTo(1, send[1].toString(16)); // S8
    Com.sendTo(1, s + ""); // S9
    Com.sendTo(1, S[0].toString(16)); // S10
    Com.sendTo(1, S[1].toString(16)); // S11
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
    ElGamal elGamal_A = new ElGamal(p_A, g_A, y_A);

    // Bob empfängt m_0 und m_1
    BigInteger[] m = new BigInteger[2];
    m[0] = new BigInteger(Com.receive(), 16); // R4
    m[1] = new BigInteger(Com.receive(), 16); // R5

    // Bob wählt zufällig ein r in {0,1} und k in Z_p
    int r = BigIntegerUtil.randomBetween(ZERO, TWO).intValue();
    System.out.println("r: " + r);
    BigInteger k = BigIntegerUtil.randomBetween(ONE, elGamal_A.p);
    System.out.println("k: " + k);

    // Bob berechnet q
    BigInteger q = elGamal_A.encipher(k).add(m[r]); // E_A(k) + m_r
    q = q.mod(elGamal_A.p.multiply(elGamal_A.p)); // mod p^2
    System.out.println("q: " + q);
    // Bob sendet q
    Com.sendTo(0, q.toString(16)); // S6

    // Bob empfängt send_0, send_1, s, S[0], S[1]
    BigInteger[] send = new BigInteger[2];
    send[0] = new BigInteger(Com.receive(), 16); // R7
    send[1] = new BigInteger(Com.receive(), 16); // R8
    int s = Integer.valueOf(Com.receive()); // R9
    BigInteger[] S = new BigInteger[2];
    S[0] = new BigInteger(Com.receive(), 16); // R10
    S[1] = new BigInteger(Com.receive(), 16); // R11

    int t = s ^ r;

    BigInteger M = ((send[t].mod(elGamal_A.p)).subtract(k)).mod(elGamal_A.p); // M = M_{s xor r}

    BigInteger k_dach = (send[t ^ 1].mod(elGamal_A.p.subtract(M))).mod(elGamal_A.p); // k_dach = k^dach_{r xor 1}

    System.out.println("S[r^1]: " + S[r ^ 1]);
    System.out.println("k_dach: " + k_dach);

    if (elGamal_A.verify(S[r ^ 1], k_dach)) {
      System.out.println("Betrug!!!!!!!!");
    } else {
      System.out.println("OK!");
    }

    System.out.println("Message choosen: M_" + t + ": " + M);
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