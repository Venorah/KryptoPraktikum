import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;

public class Secret {
  private LinkedList<BigInteger> prefixe;
  private BigInteger word;

  private int k;

  public LinkedList<BigInteger> getPrefixe() {
    return prefixe;
  }

  public void setPrefixe(LinkedList<BigInteger> prefixe) {
    this.prefixe = prefixe;
  }

  public BigInteger getWord() {
    return word;
  }

  public void setWord(BigInteger word) {
    this.word = word;
  }

  public Secret(BigInteger word, int k) {
    this.word = word;
    this.k = k;

    this.prefixe = new LinkedList<BigInteger>();

    makePrefixe();
  }

  private void makePrefixe() {
    int n = (int) Math.pow(2, k + 1); // number of prefixes

    BigInteger counter = new BigInteger("0");
    for (int i = 0; i < n; i++) {
      prefixe.add(counter);

      counter = counter.add(BigInteger.ONE);
    }
  }

  public boolean isPrefix(BigInteger prefix) {
    System.out.println("isPrefix: word: " + word.toString(2));
    System.out.println("isPrefix: prefix: " + prefix.toString(2));

    BigInteger testWord = word;
    boolean isPrefix = false;
    while (testWord.bitLength() != 0) {
      if (testWord.equals(prefix)) {
        isPrefix = true;
      }

      testWord = testWord.shiftRight(1);
    }
    
    System.out.println("isPrefix: return: "+ isPrefix);
    return isPrefix;
  }

  public void printPrefixe() {
    Iterator<BigInteger> it = prefixe.iterator();

    while (it.hasNext()) {
      BigInteger current = it.next();
      System.out.print(current.toString(2) + ", ");
    }
    System.out.println();
  }

  public void removeRandomPrefix() {

  }

  // removeRandomPrefix
}
