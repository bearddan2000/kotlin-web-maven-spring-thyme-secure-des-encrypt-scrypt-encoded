package example.security;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.apache.commons.codec.binary.Base64;

class DESUtils ()
{

  lateinit var encryptCipher: Cipher 

  init {
    this.encryptCipher = genKey();
  }

  /**
   * Construct a new object which can be utilized to encrypt
   * with a DES encryption algorithm.
   *
   * @param key The secret key used in the crypto operations.
   * @throws Exception If an error occurs.
   *
   */
  @Throws(Exception::class)
  fun genCipher(key: SecretKey): Cipher {
      val cipher = Cipher.getInstance("DES");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return cipher
  }

  @Throws(Exception::class)
  fun genKey(): Cipher {
      //Generate the secret key
      val password = "abcd1234";
      val key = DESKeySpec(password.toByteArray());
      val keyFactory = SecretKeyFactory.getInstance("DES");
      val secretKey = keyFactory.generateSecret(key);
      val salt = java.util.Base64.getEncoder().encodeToString(secretKey.getEncoded());
      println("Salt String: "+salt);
      return genCipher(secretKey)
  }

  @Throws(Exception::class)
  fun encrypt(message: String): ByteArray? {
      // Encode the string into bytes using utf-8
      val unencryptedByteArray: ByteArray = message.toByteArray();

      if(this.encryptCipher == null) {
        return null;
      }

      // Encrypt
      val encryptedBytes: ByteArray = this.encryptCipher.doFinal(unencryptedByteArray);

      // Encode bytes to base64 to get a string
      return Base64.encodeBase64(encryptedBytes);
  }

}
