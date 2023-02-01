import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException

public class JWTToken {
   private static boolean validateSignature(String secretKey, String jwt) {
        if (hasText(secretKey)) {
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setVerificationKey(new HmacKey(secretKey.getBytes(UTF_8)))
                    .setRelaxVerificationKeyValidation()
                    .build();
            try {
                jwtConsumer.processToClaims(jwt);
                return true;
            } catch (InvalidJwtException e) {
                return false;
            }
        }
        return false;
    }
}
