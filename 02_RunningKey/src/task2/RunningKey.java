/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        RunningKey.java
 * Beschreibung: Dummy-Implementierung der Chiffre mit laufendem Schlüssel
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.StringTokenizer;
import java.util.TreeMap;

import javax.management.openmbean.KeyAlreadyExistsException;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;
import de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables;
import de.tubs.cs.iti.jcrypt.chiffre.NGram;

public class RunningKey extends Cipher {

  File keyFile;
  int position = 42;
  BufferedReader keyBuffer;

  public void makeKey() {

    BufferedReader standardInput = launcher.openStandardInput();
    boolean accepted = false;

    do {
      Logger("Geben Sie den Modulus ein: ");
      try {
        modulus = Integer.parseInt(standardInput.readLine());
        if (modulus < 1) {
          Logger("Ein Modulus < 1 wird nicht akzeptiert. Bitte " + "korrigieren Sie Ihre Eingabe.");
        } else {
          String defaultAlphabet = CharacterMapping.getDefaultAlphabet(modulus);
          if (!defaultAlphabet.equals("")) {
            Logger("Vordefiniertes Alphabet: '" + defaultAlphabet + "'\nDieses vordefinierte Alphabet kann durch Angabe einer " + "geeigneten Alphabet-Datei\nersetzt werden. Weitere " + "Informationen finden Sie im Javadoc der Klasse\n'Character" + "Mapping'.");
            accepted = true;
          } else {
            Logger("Warnung: Dem eingegebenen Modulus kann kein Default-" + "Alphabet zugeordnet werden.\nErstellen Sie zusätzlich zu " + "dieser Schlüssel- eine passende Alphabet-Datei.\nWeitere " + "Informationen finden Sie im Javadoc der Klasse 'Character" + "Mapping'.");
            accepted = true;
          }
        }
      } catch (NumberFormatException e) {
        Logger("Fehler beim Parsen des Modulus. Bitte korrigieren" + " Sie Ihre Eingabe.");
      } catch (IOException e) {
        Logger("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
    accepted = false;

    Logger("Folgende Dateien stehen zur Auswahl:");
    File directory = new File("../text/");
    String[] list = directory.list();
    for (int i = 0; i < list.length; i++) {
      Logger("[" + i + "] " + list[i]);
    }
    int choice = 0;
    try {
      Logger("Welche Datei soll zum Verschluesseln benutzt werden: ");
      choice = Integer.parseInt(standardInput.readLine());
    } catch (NumberFormatException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }

    keyFile = new File("../text/" + list[choice]);

    FileReader fr = null;
    try {
      fr = new FileReader(keyFile);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    keyBuffer = new BufferedReader(fr);

    Logger("Using File: " + keyFile.getName() + " with Modulus " + modulus);

  }

  public void writeKey(BufferedWriter key) {
    try {
      key.write(modulus + " " + keyFile.getName());
      key.newLine();

      Logger("Writing Information: ");
      Logger("+--Modulus: " + modulus);
      Logger("+--File: " + keyFile.getName());

      key.close();
    } catch (IOException e) {
      System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }

  }

  public void readKey(BufferedReader key) {
    try {
      StringTokenizer st = new StringTokenizer(key.readLine(), " ");

      modulus = Integer.parseInt(st.nextToken());
      keyFile = new File("../text/" + st.nextToken());

      FileReader fr = null;
      try {
        fr = new FileReader(keyFile);
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      }
      keyBuffer = new BufferedReader(fr);

      Logger("Reading Information: ");
      Logger("+--Modulus: " + modulus);
      Logger("+--File: " + keyFile.getName());

      key.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Lesen oder Schließen der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    } catch (NumberFormatException e) {
      System.err.println("Abbruch: Fehler beim Parsen eines Wertes aus der " + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  public void encipher(BufferedReader cleartext, BufferedWriter ciphertext) {
    boolean characterSkipped = false;
    int cipherChar = -1, cipherCharMapped = -1, clearChar = -1, clearCharMapped = -1, keyChar = -1, keyCharMapped = -1;
   
    try {
      // lese cleartext schritt für schritt
      while ((clearChar = cleartext.read()) != -1) {
        // use a char that is not -1
        while ((clearCharMapped = charMap.mapChar(clearChar)) == -1) {
          Logger("clearCharMapped "+clearCharMapped);
          characterSkipped = true;
          // read next char
          clearChar = cleartext.read();
          if (clearChar == -1) {
            break;
          }
        }
        Logger("clearCharMapped after "+clearCharMapped);

        // read next keychar
        keyChar = keyBuffer.read();
        while ((keyCharMapped = charMap.mapChar(keyChar)) == -1) {
          Logger("keyCharMapped "+keyCharMapped);
          characterSkipped = true;
          // read next char
          keyChar = keyBuffer.read();
          if (keyChar == -1) {
            break;
          }
        }
        Logger("keyCharMapped after "+keyCharMapped);

        if (clearCharMapped != -1 && keyCharMapped != 1) {
          cipherCharMapped = (clearCharMapped + keyCharMapped) % modulus;
          Logger("clear enc: " + clearCharMapped);
          Logger("key enc: " + keyCharMapped);
          Logger("-> cipher enc: " + cipherCharMapped);
          cipherChar = charMap.remapChar(cipherCharMapped);
          Logger("cipher enc ascii: " + cipherChar);
          try {
            ciphertext.write(cipherChar);
          } catch (IOException e) {
            e.printStackTrace();
          }
        }
      }
    } catch (IOException e1) {
      e1.printStackTrace();
    }

    if (characterSkipped) {
      Logger("Warnung: Mindestens ein Zeichen aus der " + "Klartextdatei oder der Keydatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
    }
    try {
      cleartext.close();
      ciphertext.close();
      keyBuffer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
    boolean characterSkipped = false;
    int cipherChar = -1, cipherCharMapped = -1, clearChar = -1, clearCharMapped = -1, keyChar = -1, keyCharMapped = -1;

    try {
      // lese ciphertext schritt für schritt
      while ((cipherChar = ciphertext.read()) != -1) {
        // use a char that is not -1
        while ((cipherCharMapped = charMap.mapChar(cipherChar)) == -1) {
          Logger("ciphermapped "+cipherCharMapped);
          characterSkipped = true;
          // read next char
          cipherChar = ciphertext.read();
          if (cipherChar == -1) {
            break;
          }
        }
        Logger("ciphermapped after "+cipherCharMapped);

        // read next keychar
        keyChar = keyBuffer.read();
        while ((keyCharMapped = charMap.mapChar(keyChar)) == -1) {
          Logger("keycharmapped "+keyCharMapped);
          characterSkipped = true;
          // read next char
          keyChar = keyBuffer.read();
          if (keyChar == -1) {
            break;
          }
        }
        Logger("keycharmapped after "+keyCharMapped);


        if (cipherCharMapped != -1 && keyCharMapped != 1) {
          // decipher
          clearCharMapped = (cipherCharMapped - keyCharMapped + modulus) % modulus;
          Logger("cipher dec: " + cipherCharMapped);
          Logger("key dec: " + keyCharMapped);
          Logger("-> clear dec: " + clearCharMapped);
          clearChar = charMap.remapChar(clearCharMapped);
          Logger("clear dec ascii: " + clearChar);
          try {
            cleartext.write(clearChar);
          } catch (IOException e) {
            e.printStackTrace();
          }
        }
      }
    } catch (IOException e1) {
      e1.printStackTrace();
    }

    if (characterSkipped) {
      Logger("Warnung: Mindestens ein Zeichen aus der " + "Chiffretextdatei oder der Keydatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
    }
    try {
      cleartext.close();
      ciphertext.close();
      keyBuffer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }
  
  public void decipherOLD(BufferedReader ciphertext, BufferedWriter cleartext) {

    int cipherChar = 0, clearChar = 0, keyChar = 0;

    try {
      while (((cipherChar = ciphertext.read()) != -1) && ((keyChar = keyBuffer.read()) != -1)) {

        cipherChar = charMap.mapChar(cipherChar);
        keyChar = charMap.mapChar(keyChar);

        if (cipherChar != -1) { // TODO Maybe also check keyChar?!

          clearChar = (cipherChar - keyChar + modulus) % modulus;
          clearChar = charMap.remapChar(clearChar);

          try {
            cleartext.write(clearChar);
          } catch (IOException e) {
            e.printStackTrace();
          }
        } else {
          Logger("Wow!? Eh.. hi?");
        }
      }
    } catch (IOException e1) {
      e1.printStackTrace();
    }

    try {
      cleartext.close();
      ciphertext.close();
      keyBuffer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

    String[] cipherArray = getTextAsStringArray(ciphertext, 4);
    
    String cipherPart = "";
    String keyPart = "";
    String clearPart = "";

    /***** Interaction START */
    BufferedReader std1 = launcher.openStandardInput();
    Logger("Welche Stelle des Ciphertextes soll betrachtet werden?");
    Logger("Waehle: 0-" + cipherArray.length);

    int textPosition = 0;
    try {
      textPosition = Integer.parseInt(std1.readLine());
      cipherPart = cipherArray[textPosition];
    } catch (Exception e) {
      Logger("Falsche Eingabe, 0. Stelle wird ausgewaehlt!");
    }

    BufferedReader stdin2 = launcher.openStandardInput();
    Logger("Wie soll die Gewichtung aussehen fuer Uni/Di/Tri Grams?");
    int uni = 1, di = 1, tri = 1;
    try {
      Logger("Gewichtung Unigram: 1-1000: ");
      uni = Integer.parseInt(stdin2.readLine());

      Logger("Gewichtung Digram: 1-1000: ");
      di = Integer.parseInt(stdin2.readLine());

      Logger("Gewichtung Trigram: 1-1000: ");
      tri = Integer.parseInt(stdin2.readLine());
    } catch (Exception e) {
      Logger("Falsche Eingabe, 1 wird fuer alle ausgewaehlt");
    }
    /***** Interaction END */
    
    LinkedList<int[]> combinationsList = getCombination(cipherPart);
    TreeMap<Double, int[]> calculationMap = new TreeMap<Double, int[]>();


    for (int i = 0; i < combinationsList.size(); i++) {
      int[] currentCombination = combinationsList.get(i);
      double calculation = bewertung(currentCombination, 1, 1, 1);

      calculationMap.put(calculation, combinationsList.get(i));
    }

    Logger("Folgende Mappings erziehlten das beste Ergebnis:");
    Iterator<Double> it = calculationMap.keySet().iterator();
    HashMap<Integer, String> userInputMap = new HashMap<Integer, String>();
    for (int i = 0; i < 10 & it.hasNext(); i++) {
      int[] currentArray = calculationMap.get(it.next());
      
      clearPart = "" + currentArray[0] + currentArray[1] + currentArray[2] + currentArray[3];
      keyPart = "" + currentArray[4] + currentArray[5] + currentArray[6] + currentArray[7];
      Logger("[" + i + "] CIPHER: " + cipherPart + " CLEAR: " + clearPart + " KEY: " + keyPart);
      userInputMap.put(i, clearPart);
    }
    
    BufferedReader std3 = launcher.openStandardInput();
    Logger("Welches Mapping soll ausgewaehlt werden?");
    int choice = 0;
    try {
      choice = Integer.parseInt(std3.readLine());
    } catch (Exception e) {
      Logger("Falsche Eingabe, 0. Stelle wird ausgewaehlt!");
    }
    
    Logger(cipherPart + " wird in " + clearPart + " gemapped!");

    // Suppress framework exception
    System.exit(0);
  }

  private String getTextAsString(BufferedReader br) {
    String s = "", story = "";
    int character = 0;
    try {
      while ((character = br.read()) != -1) {
        char c = (char) character;
        story = story + c;
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

    Logger("Read the whole story! Phew~");

    return story;
  }

  private String[] getTextAsStringArray(BufferedReader br, int tokenSize) {

    String text = getTextAsString(br);

    String[] story = new String[(text.length() / tokenSize) + 1];

    for (int i = 0; i < story.length; i++) {
      if (text.length() > tokenSize) {
        String subString = text.substring(0, tokenSize);
        text = text.substring(tokenSize);
        story[i] = subString;
      } else {
        story[i] = text;
      }
    }

    return story;
  }

  /**
   * 
   * @param cipherToken
   *          Token of the length 4 from the cipher text.
   * @return List with suggestions. Format of int[]: int[0-3] = cleartext suggestions int[4-6] =
   *         keytext suggestions
   */
  private LinkedList<int[]> getCombination(String cipherToken) {

    char[] cipherTokenArray = cipherToken.toCharArray();

    int token0 = charMap.mapChar(cipherTokenArray[0]);
    int token1 = charMap.mapChar(cipherTokenArray[1]);
    int token2 = charMap.mapChar(cipherTokenArray[2]);
    int token3 = charMap.mapChar(cipherTokenArray[3]);

    int[] tokenArray = { token0, token1, token2, token3 };

    HashMap<Integer, LinkedList<int[]>> map = cipherMapping();

    LinkedList<int[]> la = map.get(tokenArray[0]);
    LinkedList<int[]> lb = map.get(tokenArray[1]);
    LinkedList<int[]> lc = map.get(tokenArray[2]);
    LinkedList<int[]> ld = map.get(tokenArray[3]);

    LinkedList<int[]> list = new LinkedList<int[]>();

    for (int a = 0; a < la.size(); a++) {
      int[] clear = new int[4];
      int[] key = new int[4];

      clear[0] = la.get(a)[0];
      key[0] = lb.get(a)[1];

      for (int b = 0; b < lb.size(); b++) {
        clear[1] = lb.get(b)[0];
        key[1] = lb.get(b)[1];

        for (int c = 0; c < lc.size(); c++) {
          clear[2] = lc.get(c)[0];
          key[2] = lb.get(c)[1];

          for (int d = 0; d < ld.size(); d++) {
            clear[3] = ld.get(d)[0];
            key[3] = lb.get(d)[1];

            int[] mixed = { clear[0], clear[1], clear[2], clear[3], key[0], key[1], key[2], key[3] };
            list.add(mixed);
            // System.out.println(clear[0] + " " + clear[1] + " " + clear[2] + " " + clear[3]);
          }
        }
      }
    }

    return list;
  }

  private HashMap<Integer, LinkedList<int[]>> cipherMapping() {

    HashMap<Integer, LinkedList<int[]>> map = new HashMap<Integer, LinkedList<int[]>>();

    for (int i = 0; i < modulus; i++) {
      for (int j = 0; j < modulus; j++) {

        int result = (i + j) % modulus;

        int[] mapping = { i, j };

        if (map.containsKey(result)) {
          LinkedList<int[]> list = map.get(result);
          list.add(mapping);
        } else {
          LinkedList<int[]> list = new LinkedList<int[]>();
          list.add(mapping);
          map.put(result, list);
        }
      }
    }

    return map;

  }

  private double bewertung(int[] combination, double g1, double g2, double g3) {

    Logger("Ich bin da!!!");

    // char[] clearPartArray = clearPart.toCharArray();
    // char[] keyPartArray = keyPart.toCharArray();

    int[] clearArray = { combination[0], combination[1], combination[2], combination[3] };
    int[] keyArray = { combination[4], combination[5], combination[6], combination[7] };

    ArrayList<NGram> unigram = FrequencyTables.getNGramsAsList(1, charMap);
    ArrayList<NGram> digram = FrequencyTables.getNGramsAsList(2, charMap);
    ArrayList<NGram> trigram = FrequencyTables.getNGramsAsList(3, charMap);

    HashMap<String, Double> unigramHashMap = nGramToHashMap(unigram);
    HashMap<String, Double> digramHashMap = nGramToHashMap(digram);
    HashMap<String, Double> trigramHashMap = nGramToHashMap(trigram);

    double result = 0;
    double k1 = 0, k2 = 0, k3 = 0;
    double s1 = 0, s2 = 0, s3 = 0;

    for (int i = 0; i < 4; i++) {
      s1 += unigramHashMap.get(charMap.remapChar(clearArray[i]) + "");
      k1 += unigramHashMap.get(charMap.remapChar(keyArray[i]) + "");
    }
    for (int i = 0; i < 3; i++) {

      String stmp = charMap.remapChar(clearArray[i]) + "" + charMap.remapChar(clearArray[i + 1]);
      String ktmp = charMap.remapChar(keyArray[i]) + "" + charMap.remapChar(keyArray[i + 1]);

      s2 += digramHashMap.get(stmp);
      k2 += digramHashMap.get(ktmp);
    }
    for (int i = 0; i < 2; i++) {

      String stmp = charMap.remapChar(clearArray[i]) + charMap.remapChar(clearArray[i + 1]) + "" + charMap.remapChar(clearArray[i + 2]);
      String ktmp = charMap.remapChar(keyArray[i]) + charMap.remapChar(keyArray[i + 1]) + "" + charMap.remapChar(keyArray[i + 2]);

      s3 += trigramHashMap.get(stmp);
      k3 += trigramHashMap.get(ktmp);
    }

    result = (g1 * k1 + g2 * k2 + g3 * k3) * (g1 * s1 + g2 * s2 + g3 * s3);

    return result;
  }

  private HashMap<String, Double> nGramToHashMap(ArrayList<NGram> nGram) {
    HashMap<String, Double> nGramHashMap = new HashMap<String, Double>();

    Iterator<NGram> it = nGram.iterator();

    while (it.hasNext()) {
      NGram n = it.next();
      nGramHashMap.put(n.getCharacters(), n.getFrequency());
    }

    return nGramHashMap;
  }

  private static void Logger(String event) {
    System.out.println("    RunningCipher$ " + event);
  }

}
