package com.krypto.idea;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;

public final class IDEA {

  String keyString;
  BigInteger keyInteger;
  static BigInteger[][] encKeys;
  static BigInteger[][] decKeys;
  BigInteger iv;

  public IDEA(BigInteger keyInteger, BigInteger iv) {
    this.keyInteger = keyInteger;
    this.iv = iv;
    BigInteger[] keyArray = Helper.extractValues(keyInteger, 8, 16);
    encKeys = getEncryptionKeys(keyArray);
    decKeys = getDecryptionKeys(encKeys);
  }

  public BigInteger encipher(BigInteger clear) {

    BigInteger[] messageArray = unmerge(clear);
    BigInteger output[] = cbcLoop(messageArray, iv, true);
    BigInteger out = merge(output);

    return out;
  }

  public BigInteger decipher(BigInteger cipher) {

    BigInteger[] cipherArray = unmerge(cipher);

    BigInteger output[] = cbcLoop(cipherArray, iv, false);
    
    BigInteger out = merge(output);
    return out;
  }

  public BigInteger cbcBlock(BigInteger message, BigInteger iv, boolean isEncryption) {
    BigInteger output = null;
    if (isEncryption) {
      // message xor iv
      BigInteger input = message.xor(iv);

      // encryption with idea
      output = idea(input, isEncryption);
    } else {
      // decryption with idea
      BigInteger idea = idea(message, isEncryption);

      // idea xor iv
      output = idea.xor(iv);
    }

    return output;
  }

  public BigInteger[] cbcLoop(BigInteger[] message, BigInteger iv, boolean isEncryption) {
    BigInteger[] outputArray = new BigInteger[message.length];

    for (int i = 0; i < message.length; i++) {
      outputArray[i] = cbcBlock(message[i], iv, isEncryption);
      if (isEncryption) {
        iv = outputArray[i];
      } else {
        iv = message[i];
      }
    }

    return outputArray;
  }

  public BigInteger idea(BigInteger input, boolean isEncryption) {
    // make 4*16bit block array
    BigInteger[] messagePart = Helper.extractValues(input, 16, 4);

    BigInteger[] key = null;
    for (int round = 0; round < 9; round++) {
      // keys based on encryption or decryption
      if (isEncryption) {
        key = encKeys[round];
      } else {
        key = decKeys[round];
      }

      // encryption/decryption
      messagePart = feistelNetwork(messagePart, key, round);
    }

    // from 4*16bit block array to one biginteger
    BigInteger output = Helper.bigIntegerArraySum(messagePart, 16);

    return output;
  }

  private BigInteger xor(BigInteger a, BigInteger b) {
    return a.xor(b);
  }

  private BigInteger add(BigInteger a, BigInteger b) {
    BigInteger addMod = new BigInteger("65536"); // 2^16

    return a.add(b).mod(addMod);
  }

  private BigInteger multiply(BigInteger a, BigInteger b) {
    BigInteger addMod = new BigInteger("65536"); // 2^16
    BigInteger multMod = new BigInteger("65537"); // (2^16)+1

    if (a.intValue() == 0) {
      a = addMod;
    }
    if (b.intValue() == 0) {
      b = addMod;
    }

    BigInteger ret = a.multiply(b).mod(multMod);
    if (ret.compareTo(addMod) == 0) {
      return new BigInteger("0");
    } else {
      return ret;
    }
  }

  /**
   * 
   * @param input
   * @param round
   *          0-8 = 9 Rounds possible
   * @param isEnc
   *          switch for enc/dec
   * @return
   */
  public BigInteger[] feistelNetwork(BigInteger[] M, BigInteger[] K, int round) {
    BigInteger[] output = new BigInteger[4];

    if (round < 8) {

      BigInteger[] calc = new BigInteger[14];

      calc[0] = multiply(K[0], M[0]);
      calc[1] = add(K[1], M[1]);
      calc[2] = add(K[2], M[2]);
      calc[3] = multiply(K[3], M[3]);
      calc[4] = xor(calc[0], calc[2]);
      calc[5] = xor(calc[1], calc[3]);
      calc[6] = multiply(K[4], calc[4]);
      calc[7] = add(calc[6], calc[5]);
      calc[8] = multiply(K[5], calc[7]);
      calc[9] = add(calc[8], calc[6]);
      calc[10] = xor(calc[8], calc[0]);
      calc[11] = xor(calc[8], calc[2]);
      calc[12] = xor(calc[9], calc[1]);
      calc[13] = xor(calc[9], calc[3]);

      output[0] = calc[10];
      output[1] = calc[11];
      output[2] = calc[12];
      output[3] = calc[13];

    } else {

      BigInteger[] calc = new BigInteger[4];

      calc[0] = multiply(K[0], M[0]);
      calc[1] = add(K[1], M[2]);
      calc[2] = add(K[2], M[1]);
      calc[3] = multiply(K[3], M[3]);

      output[0] = calc[0];
      output[1] = calc[1];
      output[2] = calc[2];
      output[3] = calc[3];
    }

    return output;
  }

  public BigInteger[] getSubBlocks(String textPart) {
    BigInteger[] array = new BigInteger[(textPart.length()) / 2];

    BigInteger[] bigArray = Helper.stringToBigIntegerArray(textPart);

    for (int i = 0, j = 0; i < bigArray.length; i = i + 2, j++) {
      BigInteger val1 = bigArray[i];
      BigInteger val2 = bigArray[i + 1];

      array[j] = Helper.byteToShort(val1, val2);
    }

    return array;
  }

  public BigInteger[][] getEncryptionKeys(BigInteger[] keyArray) {
    // String keyString
    BigInteger[] outputArray = new BigInteger[52];

    // BigInteger[] keyArray = Helper.stringToBigIntegerArray(keyString);
    BigInteger key = Helper.bigIntegerArraySum(keyArray, 8);

    BigInteger[] shortKeyArray = Helper.extractValues(key, 16, 8);

    // get keys
    int i = 0;
    while (i != 52) {

      for (int j = 0; j < shortKeyArray.length; j++) {
        BigInteger tmp = shortKeyArray[j];
        outputArray[i++] = tmp;
        if (i == 52) {
          break;
        }
      }

      if (i != 52) {
        key = Helper.shift(key, 16, 25);
        shortKeyArray = Helper.extractValues(key, 16, 8);
      }
    }

    // get as 2d array
    BigInteger[][] nicerArray = new BigInteger[9][6];

    int counter = 0;
    for (int zeile = 0; zeile < nicerArray.length; zeile++) {
      for (int spalte = 0; spalte < nicerArray[zeile].length; spalte++) {
        nicerArray[zeile][spalte] = outputArray[counter++];
        if (counter == 52) {
          return nicerArray;
        }
      }
    }

    return nicerArray;
  }

  public BigInteger[][] getDecryptionKeys(BigInteger[][] encryptionKeys) {
    BigInteger[][] dencryptionKeys = new BigInteger[9][6];

    // reverse array
    for (int column = 0; column < 9; column++) {
      if (column == 0) {
        dencryptionKeys[column][0] = encryptionKeys[8 - column][0];
        dencryptionKeys[column][1] = encryptionKeys[8 - column][1];
        dencryptionKeys[column][2] = encryptionKeys[8 - column][2];
        dencryptionKeys[column][3] = encryptionKeys[8 - column][3];
        dencryptionKeys[column][4] = encryptionKeys[7 - column][4];
        dencryptionKeys[column][5] = encryptionKeys[7 - column][5];
      } else if (column > 0 && column < 8) {
        dencryptionKeys[column][0] = encryptionKeys[8 - column][0];
        dencryptionKeys[column][1] = encryptionKeys[8 - column][2];
        dencryptionKeys[column][2] = encryptionKeys[8 - column][1];
        dencryptionKeys[column][3] = encryptionKeys[8 - column][3];
        dencryptionKeys[column][4] = encryptionKeys[7 - column][4];
        dencryptionKeys[column][5] = encryptionKeys[7 - column][5];
      } else {
        dencryptionKeys[column][0] = encryptionKeys[8 - column][0];
        dencryptionKeys[column][1] = encryptionKeys[8 - column][1];
        dencryptionKeys[column][2] = encryptionKeys[8 - column][2];
        dencryptionKeys[column][3] = encryptionKeys[8 - column][3];
        dencryptionKeys[column][4] = null;
        dencryptionKeys[column][5] = null;
      }
    }

    BigInteger addMod = new BigInteger("65536"); // 2^16
    BigInteger multMod = new BigInteger("65537"); // (2^16)+1

    // calculate multiplicative inverse and negate mod
    for (int column = 0; column < dencryptionKeys.length; column++) {
      for (int row = 0; row < dencryptionKeys[column].length; row++) {
        if (row == 0 || row == 3) {
          BigInteger val = dencryptionKeys[column][row];
          val = val.modInverse(multMod);
          dencryptionKeys[column][row] = val;
        } else if (row == 1 || row == 2) {
          BigInteger val = dencryptionKeys[column][row];
          val = val.negate();
          val = val.mod(addMod);
          dencryptionKeys[column][row] = val;
        } else {
          dencryptionKeys[column][row] = dencryptionKeys[column][row];
        }
      }
    }

    return dencryptionKeys;
  }

  public BigInteger merge(BigInteger[] array) {
    BigInteger output = new BigInteger("0");

    for (int i = 0; i < array.length; i++) {
      int shifting = 64;
      if (i == 0) {
        shifting = 0;
      }
      output = output.shiftLeft(shifting);
      output = output.add(array[i]);
    }

    return output;
  }

  public BigInteger[] unmerge(BigInteger msg) {
    BigInteger max = new BigInteger("18446744073709551615");
    LinkedList<BigInteger> list = new LinkedList<BigInteger>();

    BigInteger message = new BigInteger(msg.toString());
    while (message.bitLength() > 0) {
      list.addFirst(message.and(max));
      message = message.shiftRight(64);
    }

    BigInteger[] output = new BigInteger[list.size()];
    Iterator<BigInteger> it = list.iterator();
    int i=  0;
    while(it.hasNext()) {
      output[i] = it.next();
      i++;
    }
    return output;
  }

  private void Logger(String event) {
    System.out.println("IDEA$  " + event);
  }
}
