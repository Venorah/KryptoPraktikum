import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Random;

public class Secret {
  private ArrayList<BigInteger> binaries;
  private BigInteger word;

  private int k;
  private int m;

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

  public Secret(BigInteger word, int k, int m) {
    this.word = word;
    this.k = k;
    this.m = m;

    if (word.bitLength() > m) {
      System.out.println("Problem: Bitlength of word (" + word.bitLength() + ") is bigger than m (" + m + ")! Exiting...");
      System.exit(0);
    }

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

  private boolean isPrefix(BigInteger val) {
    boolean isPrefix = false;

    int shift = m - k + 1;
    BigInteger modifiedWord = word.shiftRight(shift);

    if (val.equals(modifiedWord)) {
      isPrefix = true;
    }

    return isPrefix;
  }

  public String binariesToString(ArrayList<BigInteger> myBinaries) {
    Iterator<BigInteger> it = myBinaries.iterator();

    String output = "";
    while (it.hasNext()) {
      BigInteger current = it.next();
      output += current.toString(2) + ", ";
    }

    return output;
  }

  public int removeRandomPrefix() {
    Random rnd = new Random();

    // remove only those binaries that are no prefix of the word!!!
    int rndIndex = rnd.nextInt(binaries.size());
    while (isPrefix(binaries.get(rndIndex))) {
      rndIndex = rnd.nextInt(binaries.size());
    }

    System.out.println("removeRandomPrefix: binary removed: " + binaries.get(rndIndex).toString(2));
    System.out.println("removeRandomPrefix: remaining binaries: " + binariesToString(binaries));

    binaries.remove(rndIndex);

    return rndIndex;
  }

  private ArrayList<BigInteger> generateNewBinaries(ArrayList<BigInteger> myBinaries) {
    ArrayList<BigInteger> oldBinaries = myBinaries;
    ArrayList<BigInteger> newBinaries = new ArrayList<BigInteger>();

    Iterator<BigInteger> it = oldBinaries.iterator();
    while (it.hasNext()) {
      BigInteger current = it.next();

      BigInteger new1 = current.shiftLeft(1); // append 0 from right
      BigInteger new2 = current.shiftLeft(1).add(BigInteger.ONE); // append 1 from right

      // System.out.println("old: " + current.toString(2));
      // System.out.println("new1: " + new1.toString(2));
      // System.out.println("new2: " + new2.toString(2));

      newBinaries.add(new1);
      newBinaries.add(new2);
    }

    // System.out.println("old binaries: " + binariesToString(oldBinaries));
    // System.out.println("new binaries: " + binariesToString(newBinaries));

    return newBinaries;
  }

  public void expandBinaries() {
    binaries = generateNewBinaries(binaries);
    k += 1;
  }
}
