package task3;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class Helper {
  
  public static String getTextAsString(FileInputStream cleartext) {
    StringBuffer clearTextBuffer = new StringBuffer();

    try {
      int ch = 0;
      while ((ch = cleartext.read()) != -1) {
        clearTextBuffer.append((char) ch);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

    return clearTextBuffer.toString();
  }
  
  public static String[] getTextAsStringArray(String text, int tokenSize) {

    String[] story = new String[(text.length() / tokenSize) + 1];

    for (int i = 0; i < story.length; i++) {
      if (text.length() > tokenSize) {
        String subString = text.substring(0, tokenSize);
        text = text.substring(tokenSize);
        story[i] = subString;
      } else {
        text = appendWhitespaces(text, tokenSize);
        story[i] = text;
      }
    }
    return story;
  }


  public static BigInteger[] stringToBigIntegerArray(String textPart) {
    BigInteger[] array = new BigInteger[textPart.length()];

    char[] charArray = textPart.toCharArray();

    for (int i = 0; i < charArray.length; i++) {
      int val = charArray[i];
      int bac = '-';

      BigInteger bi = new BigInteger(String.valueOf(val));
      BigInteger bi_backup = new BigInteger(String.valueOf(bac));

      if (bi.bitLength() > 8) {
        array[i] = bi_backup;
      } else {
        array[i] = bi;
      }
    }

    return array;
  }

  public static String bigIntegerArrayToString(BigInteger[] array) {
    String output = "";

    for (int i = 0; i < array.length; i++) {
      char character = (char) array[i].intValue();
      output += character;
    }

    return output;
  }

  public static BigInteger bigIntegerArraySum(BigInteger[] array) {
    BigInteger output = new BigInteger("0");

    int counter = array.length - 1;
    for (int i = 0; i < array.length; i++) {
      BigInteger currentValue = array[i].shiftLeft(8 * (counter--));
      output = output.add(currentValue);
    }

    return output;
  }
  
  public static String appendWhitespaces(String textPart, int tokenSize) {
    String token = textPart;

    while (token.length() != tokenSize) {
      token = token + " ";
    }

    return token;
  }

  public static String prependZeros(String textPart, int tokenSize) {
    String token = textPart;

    while (token.length() != tokenSize) {
      token = "0" + token;
    }

    return token;
  }

  public static BigInteger[] byteArrayToShortArray(BigInteger[] array) {
    BigInteger[] outputArray = new BigInteger[array.length / 2];

    int counter = 0;
    for (int i = 0; i < outputArray.length; i++) {
      BigInteger val1 = array[counter++];
      BigInteger val2 = array[counter++];

      outputArray[i] = byteToShort(val1, val2);
    }

    return outputArray;
  }

  public static BigInteger byteToShort(BigInteger val1, BigInteger val2) {
    val1 = val1.shiftLeft(8);
    return val1.add(val2);
  }

  public static String decimalToBinaryString(int val) {
    String output = "";

    while (val != 0) {
      if (val % 2 == 0) {
        output = "0" + output;
      } else {
        output = "1" + output;
      }
      val /= 2;
    }

    return output;
  }

  public static int binaryStringToDecimal(String binaryString) {
    int output = 0;
    char[] array = binaryString.toCharArray();

    for (int i = 0, j = array.length - 1; j >= 0; i++, j--) {
      if (array[j] == '1') {
        output += Math.pow(2, i);
      }
    }

    return output;
  }
  
  private static BigInteger generateMaxBigInteger(int bits) {

    int shift = 0;
    BigInteger output = new BigInteger("0");
    BigInteger round = new BigInteger("0");
    BigInteger val = new BigInteger("1");
    
    for (int i = 0; i < bits; i++) {
      
      int j = i % 8;
      
      if ( i != 0 && (i % 8) == 0) {
        round = round.shiftLeft(shift*8);
        output = output.add(round);

        round = new BigInteger("0");
        shift++;
      }

      val = new BigInteger("1");
      val = val.shiftLeft(j);
      round = round.add(val);
    }
    
    round = round.shiftLeft(shift*8);
    output = output.add(round);

    return output;
  }
}
