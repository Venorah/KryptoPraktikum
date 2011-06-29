import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Random;

public class Secret {
  private ArrayList<BigInteger> binaries;
  private BigInteger word;

  private int k;

  public ArrayList<BigInteger> getBinaries() {
    return binaries;
  }

  public void setPrefixe(ArrayList<BigInteger> binaries) {
    this.binaries = binaries;
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

    this.binaries = new ArrayList<BigInteger>();

    makeBinaries();
  }

  private void makeBinaries() {
    int n = (int) Math.pow(2, k + 1); // number of prefixes

    BigInteger counter = new BigInteger("0");
    for (int i = 0; i < n; i++) {
      binaries.add(counter);

      counter = counter.add(BigInteger.ONE);
    }
  }

  private boolean isPrefix(BigInteger binary) {
    System.out.println("isPrefix: word: " + word.toString(2));
    System.out.println("isPrefix: binary: " + binary.toString(2));

    BigInteger testWord = word;
    boolean isPrefix = false;
    while (testWord.bitLength() != 0) {
      if (testWord.equals(binary)) {
        isPrefix = true;
      }

      testWord = testWord.shiftRight(1);
    }

    System.out.println("isPrefix: return: " + isPrefix);
    return isPrefix;
  }

  public String binariesToString() {
    Iterator<BigInteger> it = binaries.iterator();

    String output = "";
    while (it.hasNext()) {
      BigInteger current = it.next();
      output += current.toString(2) + ", ";
    }

    return output;
  }

  public int removeRandomPrefix() {
    Random rnd = new Random();

    // remove only those binarys that are no prefix of the word!!!
    int rndIndex = rnd.nextInt(binaries.size());
    while (isPrefix(binaries.get(rndIndex))) {
      rndIndex = rnd.nextInt(binaries.size());
    }

    System.out.println("removeRandomPrefix: binary removed: " + binaries.get(rndIndex).toString(2));
    System.out.println("removeRandomPrefix: remaining binaries: " + binariesToString());

    binaries.remove(rndIndex);

    return rndIndex;
  }
}
