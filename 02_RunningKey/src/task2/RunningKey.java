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
import java.util.StringTokenizer;

import javax.management.openmbean.KeyAlreadyExistsException;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

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
    int cipherChar = 0, clearChar = 0, keyChar = 0;

    try {
      while (((clearChar = cleartext.read()) != -1) && ((keyChar = keyBuffer.read()) != -1)) {
        clearChar = charMap.mapChar(clearChar);
        keyChar = charMap.mapChar(keyChar);
        if (clearChar != -1) { // TODO Maybe also check keyChar?!
          cipherChar = (clearChar + keyChar) % modulus;
          cipherChar = charMap.remapChar(cipherChar);
          try {
            ciphertext.write(cipherChar);
          } catch (IOException e) {
            e.printStackTrace();
          }
        } else {
          characterSkipped = true;
        }
      }
    } catch (IOException e1) {
      e1.printStackTrace();
    }

    if (characterSkipped) {
      Logger("Warnung: Mindestens ein Zeichen aus der " + "Klartextdatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
    }
    try {
      cleartext.close();
      ciphertext.close();
      keyBuffer.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void encipherOLD(BufferedReader cleartext, BufferedWriter ciphertext) {

    char[] cleartextArray = getTextAsString(cleartext).toCharArray();
    int[] keyword = generateKeyArray(cleartextArray.length);

    int size = 0;

    boolean characterSkipped = false;

    if (cleartextArray.length != keyword.length) {
      Logger("Key did not match with cleartext!");
      System.exit(1);
    } else {
      size = cleartextArray.length;
    }

    for (int i = 0; i < size; i++) {
      int character = charMap.mapChar(cleartextArray[i]);
      if (character != -1) {

        character = (character + keyword[i]) % modulus;
        character = charMap.remapChar(character);
        try {
          ciphertext.write(character);
        } catch (IOException e) {
          e.printStackTrace();
        }
      } else {
        characterSkipped = true;
      }
    }
    if (characterSkipped) {
      Logger("Warnung: Mindestens ein Zeichen aus der " + "Klartextdatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
    }
    try {
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {

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

  public void decipherOLD(BufferedReader ciphertext, BufferedWriter cleartext) {

    char[] ciphertextArray = getTextAsString(ciphertext).toCharArray();
    int[] keyword = generateKeyArray(ciphertextArray.length);

    int size = 0;

    if (ciphertextArray.length != keyword.length) {
      Logger("Key did not match with ciphertext!");
      System.exit(1);
    } else {
      size = ciphertextArray.length;
    }

    for (int i = 0; i < size; i++) {
      int character = charMap.mapChar(ciphertextArray[i]);
      if (character != -1) {
        character = (character - keyword[i] + modulus) % modulus;
        character = charMap.remapChar(character);

        try {
          cleartext.write(character);
        } catch (IOException e) {
          e.printStackTrace();
        }
      } else {
        // Ein überlesenes Zeichen sollte bei korrekter Chiffretext-Datei
        // eigentlich nicht auftreten können.
      }
    }
    try {
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  private int[] generateKeyArray(int size) {

    int[] key = new int[size];
    String story = "";

    FileReader fr = null;
    try {
      fr = new FileReader(keyFile);
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }

    BufferedReader br = new BufferedReader(fr);
    String s;

    story = getTextAsString(br);

    char[] storyArray = story.toCharArray();

    for (int i = position, j = 0; i < position + size; i++, j++) {
      int mappedCharacter = charMap.mapChar(storyArray[i]);
      key[j] = mappedCharacter;
    }

    // for (int i = 0; i < key.length; i++) {
    // char tmp = (char) key[i];
    // Logger(tmp + ": " + key[i]);
    // }

    return key;
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

  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

  }

  private static void Logger(String event) {
    System.out.println("    RunningCipher$ " + event);
  }

}
