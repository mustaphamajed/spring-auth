package com.example.springauth.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service class for JWT token processing.
 */
@Service
public class JwtService {

    // Secret key used for signing and verifying JWT tokens
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    /**
     * Extracts the username from a JWT token.
     *
     * @param token the JWT token
     * @return the username extracted from the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts a claim from a JWT token using a provided claims resolver function.
     *
     * @param token           the JWT token
     * @param claimsResolver  the claims resolver function to extract the desired claim
     * @param <T>             the type of the claim
     * @return the extracted claim
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from a JWT token.
     *
     * @param token the JWT token
     * @return all claims extracted from the token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
    }


    /**
     * Generates a JWT token for the provided UserDetails.
     *
     * @param userDetails  UserDetails object representing the authenticated user
     * @return the generated JWT token
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with the provided extra claims and UserDetails.
     *
     * @param extraClaims  additional claims to include in the token (e.g., custom user attributes)
     * @param userDetails  UserDetails object representing the authenticated user
     * @return the generated JWT token
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims) // Set additional claims (if any)
                .setSubject(userDetails.getUsername()) // Set the subject (username) of the token
                .setIssuedAt(new Date(System.currentTimeMillis())) // Set the token issuance date
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Set the token expiration date
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Sign the token with the HMAC SHA-256 algorithm
                .compact(); // Compact the token into its final string representation
    }

    /**
     * Checks whether the provided JWT token is valid for the given UserDetails.
     *
     * @param token        the JWT token to be validated
     * @param userDetails UserDetails object representing the expected user
     * @return true if the token is valid for the user, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * Checks whether the expiration date of the JWT token has passed.
     *
     * @param token the JWT token
     * @return true if the token has expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date from the JWT token.
     *
     * @param token the JWT token
     * @return the expiration date extracted from the token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    /**
     * Retrieves the signing key used for JWT token verification.
     *
     * @return the signing key
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
