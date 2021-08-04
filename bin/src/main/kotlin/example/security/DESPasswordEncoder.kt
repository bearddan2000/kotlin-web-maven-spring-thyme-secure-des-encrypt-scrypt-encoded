package example.security

import javax.xml.bind.DatatypeConverter;
import org.springframework.security.crypto.password.PasswordEncoder;

class DESPasswordEncoder : org.springframework.security.crypto.scrypt.SCryptPasswordEncoder()
, PasswordEncoder {

  val utils: DESUtils = DESUtils()

   override fun encode(rawPassword: CharSequence): String {
     try {
       val plainText = rawPassword.toString();
       val rsaText = utils.encrypt(plainText);
       return super.encode(DatatypeConverter.printHexBinary(rsaText));
     } catch (e: Exception) {}
     return super.encode(rawPassword);
   }

   override fun matches(rawPassword: CharSequence, encodedPassword: String): Boolean
   {
    try {
       val plainText = rawPassword.toString();
        val rsaText = utils.encrypt(plainText);
       val plain = DatatypeConverter.printHexBinary(rsaText);
      return super.matches(plain, encodedPassword);
    } catch (e: Exception) {}
    return false;
   }
}
