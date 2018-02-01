package edu.cnm.deepdive.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Test {

  public static void main(String[] args) 
      throws FileNotFoundException, NoSuchAlgorithmException, IOException {
    File file = new File("eff_large_wordlist.txt");
    Diceware dw = new Diceware(file);
    String[] passphrase = dw.generate(6);
    System.out.println(Arrays.toString(passphrase));
  }

}
