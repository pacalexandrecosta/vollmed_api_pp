package med.voll.api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import med.voll.api.domain.usuario.Usuario;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.Instant;

import com.auth0.jwt.JWTVerifier;

@Service
public class TokenService {

    public static final String ISSUER = "API Voll.med";
    @Value("${api.security.token.secret}")
    private String secret;

    public String gerarToken(Usuario usuario) {
        try {

            var algoritmo = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withSubject(usuario.getLogin())
                    .withExpiresAt(dataExpiracao())
                    .withIssuer(ISSUER)
                    .sign(algoritmo);
        } catch (JWTCreationException exception) {
            throw new RuntimeException("erro ao gerar token jwt", exception);
        }

    }

    public String getSubject(String tokenJwt) {
        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    // specify any specific claim validations
                    .withIssuer("API Voll.med")
                    // reusable verifier instance
                    .build();

            decodedJWT = verifier.verify(tokenJwt);
            return decodedJWT.getSubject();
        } catch (JWTVerificationException exception) {
            // Invalid signature/claims
            throw new RuntimeException("Token Jwt inválido ou expirado");
        }
    }

    private Instant dataExpiracao() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
