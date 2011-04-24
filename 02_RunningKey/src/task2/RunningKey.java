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
import java.io.IOException;
import java.util.StringTokenizer;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

public class RunningKey extends Cipher {

  File text;

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

    text = new File("../text/" + list[choice]);

    Logger("Using File: " + text.getName() + " with Modulus " + modulus);

  }

  public void writeKey(BufferedWriter key) {
    try {
      key.write(modulus + " " + text.getName());
      key.newLine();

      Logger("Writing Information: ");
      Logger("+--Modulus: " + modulus);
      Logger("+--File: " + text.getName());

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
      text = new File("../text/" + st.nextToken());

      Logger("Reading Information: ");
      Logger("+--Modulus: " + modulus);
      Logger("+--File: " + text.getName());

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

  }

  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {

  }

  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

  }

  private static void Logger(String event) {
    System.out.println("    RunningCipher$ " + event);
  }

}
