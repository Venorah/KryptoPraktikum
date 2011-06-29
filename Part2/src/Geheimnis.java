import com.krypto.elGamal.ElGamal;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.krypto.protokoll.*;

public final class Geheimnis implements Protocol {

  static private int MinPlayer = 2; // Minimal number of players
  static private int MaxPlayer = 2; // Maximal number of players
  static private String NameOfTheGame = "Geheimnisaustausch";
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

    int n = 2; // n in {1,...,10}
    int k = 2; // k in {0,...,7}

    // n und k an Bob
    Com.sendTo(1, Integer.toHexString(n)); // S1
    Com.sendTo(1, Integer.toHexString(k)); // S2

    
    Secret[][] a = new Secret[n][2];
    
    // fülle mit words
    for (int i=0; i<n;i++) {
      a[i][0] = new Secret(new BigInteger("001000", 2), k);
    }
    
//    BigInteger test = new BigInteger("1239abz", 36);
//    System.out.println(test.toString(36));
    
    ArrayList<BigInteger> prefixe = a[0][0].getBinaries();
    
    
    
    
    
    // beide senden je 1 von 2 geheimnissen eines jeden geheimnispaars gemäß oblivious transfer

  }

  /**
   * Aktionen der uebrigen Parteien. Bei den 2-Parteien-Protokollen seien dies die Aktionen von Bob.
   */
  public void receiveFirst() {
    System.out.println("-- Bob --");
    if (betray) {
      System.out.println("ACHTUNG: Betrugsmodus aktiv!!!");
    }

    // k und n von Alice
    int n = Integer.parseInt(Com.receive(), 16);// R1
    int k = Integer.parseInt(Com.receive(), 16); // R2

  }

  public void obliviousSend(BigInteger M_0, BigInteger M_1) {
    System.out.println("Oblivios Transfer");

    // Hard coded messages M_0 and M_1
    BigInteger[] M = new BigInteger[2];
    M[0] = M_0;
    M[1] = M_1;

    if (betray) {
      M[1] = M[0];
    }

    // Hard coded ElGamal
    BigInteger p_A = new BigInteger("7789788965135663714690749102453072297748091458564354001035945418057913886819451721947477667556269500246451521462308030406227237346483679855991947569361139");
    BigInteger g_A = new BigInteger("6064211169633122201619014531987050083527855665630754543345421103270545526304595525644519493777291154802011605984321393354028831270292432551124003674426238");
    BigInteger y_A = new BigInteger("3437627792030969437324738830672923365331058766427964788898937390314623633227168012908665090706697391878208866573481456022491841700034626290242749535475902");
    // private:
    BigInteger x_A = new BigInteger("3396148360179732969395840357777168909721385739804535508222449486018759668590512304433229713789117927644143586092277750293910884717312503836910153525557232");
    // Objekt initialisieren mit priv key
    ElGamal elGamal_A = new ElGamal(p_A, g_A, y_A, x_A);

    BigInteger p = elGamal_A.p;

    // Alice sendet ElGamal public key an Bob
    Com.sendTo(1, elGamal_A.p.toString(16)); // S1
    Com.sendTo(1, elGamal_A.g.toString(16)); // S2
    Com.sendTo(1, elGamal_A.y.toString(16)); // S3

    // Alice wählt zufällig zwei Nachrichten m_0, m_1 in Z_p, 1 <= m < p
    BigInteger[] m = new BigInteger[2];
    m[0] = BigIntegerUtil.randomBetween(ONE, p);
    m[1] = BigIntegerUtil.randomBetween(ONE, p);
    // System.out.println("m_0: " + m[0]);
    // System.out.println("m_1: " + m[1]);

    // Alice sendet m_0, m_1 an Bob
    Com.sendTo(1, m[0].toString(16)); // S4
    Com.sendTo(1, m[1].toString(16)); // S5

    // Alice empfängt q
    BigInteger q = new BigInteger(Com.receive(), 16); // R6

    // Alice berechnet k_0', k_1', hier k_A[0] und k_A[1] genannt
    BigInteger[] k_strich = new BigInteger[2];
    for (int i = 0; i < 2; i++) {
      k_strich[i] = elGamal_A.decipher((q.subtract(m[i])).mod(p.multiply(p))); // D_A((q-m_i) mod p^2)
    }
    // System.out.println("k_strich[0]: " + k_strich[0]);
    // System.out.println("k_strich[1]: " + k_strich[1]);

    // zufällig s wählen
    int s = BigIntegerUtil.randomBetween(ZERO, TWO).intValue();
    // System.out.println("s: " + s);

    BigInteger[] send = new BigInteger[2];
    send[0] = M[0].add(k_strich[s]).mod(p);
    send[1] = M[1].add(k_strich[s ^ 1]).mod(p);

    // System.out.println("send_0: " + send[0]);
    // System.out.println("send_1: " + send[1]);

    int r = -1;
    if (betray) { // try to find right r :D
      r = BigIntegerUtil.randomBetween(ZERO, TWO).intValue();
      System.out.println("guessed r: " + r);
    }

    // Signatur berechnen
    BigInteger[] S = new BigInteger[2];
    for (int i = 0; i < 2; i++) {
      if (betray) {
        if (i == r) { // gefälschte signatur
          S[i] = BigIntegerUtil.randomBetween(BigIntegerUtil.TWO, p.multiply(p));
        } else {
          S[i] = elGamal_A.sign(k_strich[i]);
        }
      } else { // no betraying
        S[i] = elGamal_A.sign(k_strich[i]);
      }
    }
    // System.out.println("S_0: " + S[0]);
    // System.out.println("S_1: " + S[1]);

    // Alice sendet send_0, send_1, s, S[0], S[1]
    Com.sendTo(1, send[0].toString(16)); // S7
    Com.sendTo(1, send[1].toString(16)); // S8
    Com.sendTo(1, s + ""); // S9
    Com.sendTo(1, S[0].toString(16)); // S10
    Com.sendTo(1, S[1].toString(16)); // S11
  }

  public BigInteger obliviousReceive() {
    System.out.println("Oblivios Transfer");

    // Bob empfängt Alice ElGamal pub key
    BigInteger p_A = new BigInteger(Com.receive(), 16); // R1
    BigInteger g_A = new BigInteger(Com.receive(), 16); // R2
    BigInteger y_A = new BigInteger(Com.receive(), 16); // R3
    // ElGamal Objekt ohne priv key bauen
    ElGamal elGamal_A = new ElGamal(p_A, g_A, y_A);

    BigInteger p = elGamal_A.p;

    // Bob empfängt m_0 und m_1
    BigInteger[] m = new BigInteger[2];
    m[0] = new BigInteger(Com.receive(), 16); // R4
    m[1] = new BigInteger(Com.receive(), 16); // R5

    // Bob wählt zufällig ein r in {0,1} und k in Z_p
    int r = BigIntegerUtil.randomBetween(ZERO, TWO).intValue();
    // System.out.println("r: " + r);
    BigInteger k = BigIntegerUtil.randomBetween(ONE, p);
    // System.out.println("k: " + k);

    // Bob berechnet q
    BigInteger q = elGamal_A.encipher(k).add(m[r]); // E_A(k) + m_r
    q = q.mod(p.multiply(p)); // mod p^2
    // System.out.println("q: " + q);
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
    // System.out.println("S_0: " + S[0]);
    // System.out.println("S_1: " + S[1]);

    // System.out.println("s: " + s);
    // System.out.println("r: " + r);

    BigInteger M = send[s ^ r].subtract(k).mod(p); // M = M_{s xor r}

    BigInteger k_quer = send[s ^ r ^ 1].subtract(M).mod(p);

    BigInteger k_quer2 = send[s ^ r].subtract(M).mod(p);

    // System.out.println("S[r^1]: " + S[r ^ 1]);
    // System.out.println("k_dach: " + k_quer);

    if (elGamal_A.verify(k_quer, S[r ^ 1])) {
      System.out.println("Betrug!!!!!!!!");
      System.exit(0);

      return null;
    } else {
      if (elGamal_A.verify(k_quer2, S[r])) {
        System.out.println("Alles OK!");
        System.out.println("Message choosen: M_" + (s ^ r) + ": " + M);

        return M;
      } else {
        System.out.println("Betrug!!!!!!!!");
        System.exit(0);

        return null;
      }
    }
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