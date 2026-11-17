package me.zhyd.oauth.utils;

import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.exception.AuthException;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class FacebookLimitedLoginVerifierTest {

    private static final String APP_ID = "1234567890";

    @Test
    public void verifyValidToken() throws Exception {
        KeyPair keyPair = generateKeyPair();
        JSONObject claims = validClaims();
        String token = createToken(keyPair.getPrivate(), claims);

        JSONObject verifiedClaims = verifier(keyPair.getPublic(), new TestCache()).verify(token);

        Assert.assertEquals("facebook-user-id", verifiedClaims.getString("sub"));
        Assert.assertEquals("Jack", verifiedClaims.getString("name"));
        Assert.assertEquals("jack@example.com", verifiedClaims.getString("email"));
    }

    @Test
    public void rejectReplayedToken() throws Exception {
        KeyPair keyPair = generateKeyPair();
        String token = createToken(keyPair.getPrivate(), validClaims());
        FacebookLimitedLoginVerifier verifier = verifier(keyPair.getPublic(), new TestCache());

        verifier.verify(token);
        assertIllegalToken(verifier, token);
    }

    @Test
    public void rejectWrongAudience() throws Exception {
        KeyPair keyPair = generateKeyPair();
        JSONObject claims = validClaims();
        claims.put("aud", "other-app-id");
        String token = createToken(keyPair.getPrivate(), claims);

        assertIllegalToken(verifier(keyPair.getPublic(), new TestCache()), token);
    }

    @Test
    public void rejectWrongIssuer() throws Exception {
        KeyPair keyPair = generateKeyPair();
        JSONObject claims = validClaims();
        claims.put("iss", "https://example.com");
        String token = createToken(keyPair.getPrivate(), claims);

        assertIllegalToken(verifier(keyPair.getPublic(), new TestCache()), token);
    }

    @Test
    public void rejectExpiredToken() throws Exception {
        KeyPair keyPair = generateKeyPair();
        JSONObject claims = validClaims();
        long now = System.currentTimeMillis() / 1000;
        claims.put("exp", now - 3600);
        String token = createToken(keyPair.getPrivate(), claims);

        assertIllegalToken(verifier(keyPair.getPublic(), new TestCache()), token);
    }

    @Test
    public void rejectNoneAlgorithm() throws Exception {
        KeyPair keyPair = generateKeyPair();
        String token = createToken(keyPair.getPrivate(), validClaims(), "none");

        assertIllegalToken(verifier(keyPair.getPublic(), new TestCache()), token);
    }

    @Test
    public void rejectForgedSignature() throws Exception {
        KeyPair facebookKeyPair = generateKeyPair();
        KeyPair attackerKeyPair = generateKeyPair();
        String token = createToken(attackerKeyPair.getPrivate(), validClaims());

        // JWKS 中只有 Facebook 的公钥，攻击者私钥签发的 token 不能通过验签
        assertIllegalToken(verifier(facebookKeyPair.getPublic(), new TestCache()), token);
    }

    private FacebookLimitedLoginVerifier verifier(PublicKey publicKey, TestCache cache) {
        String jwksJson = jwks(publicKey);
        return new FacebookLimitedLoginVerifier(APP_ID, cache, null) {
            @Override
            protected String fetchJwks() {
                return jwksJson;
            }
        };
    }

    private static void assertIllegalToken(FacebookLimitedLoginVerifier verifier, String token) {
        try {
            verifier.verify(token);
            Assert.fail("Expected AuthException");
        } catch (AuthException e) {
            Assert.assertEquals(AuthResponseStatus.ILLEGAL_TOKEN.getCode(), e.getErrorCode());
        }
    }

    private static JSONObject validClaims() {
        long now = System.currentTimeMillis() / 1000;
        JSONObject claims = new JSONObject();
        claims.put("iss", "https://www.facebook.com");
        claims.put("aud", APP_ID);
        claims.put("sub", "facebook-user-id");
        claims.put("name", "Jack");
        claims.put("email", "jack@example.com");
        claims.put("iat", now);
        claims.put("exp", now + 3600);
        return claims;
    }

    private static String createToken(PrivateKey privateKey, JSONObject claims) throws Exception {
        return createToken(privateKey, claims, "RS256");
    }

    private static String createToken(PrivateKey privateKey, JSONObject claims, String algorithm) throws Exception {
        JSONObject header = new JSONObject();
        header.put("alg", algorithm);
        header.put("typ", "JWT");

        String signingInput = base64Url(header.toJSONString().getBytes(StandardCharsets.UTF_8))
            + "." + base64Url(claims.toJSONString().getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64Url(signer.sign());
    }

    private static String jwks(PublicKey publicKey) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        JSONObject key = new JSONObject();
        key.put("kty", "RSA");
        key.put("kid", "test-kid");
        key.put("n", base64Url(unsignedBytes(rsaPublicKey.getModulus())));
        key.put("e", base64Url(unsignedBytes(rsaPublicKey.getPublicExponent())));
        JSONObject jwks = new JSONObject();
        jwks.put("keys", Collections.singletonList(key));
        return jwks.toJSONString();
    }

    private static byte[] unsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /**
     * 测试用的内存缓存，避免依赖全局缓存影响其它用例
     */
    private static final class TestCache implements AuthStateCache {

        private final Map<String, String> values = new HashMap<>();
        private final Map<String, Long> expires = new HashMap<>();

        @Override
        public void cache(String key, String value) {
            cache(key, value, Long.MAX_VALUE);
        }

        @Override
        public void cache(String key, String value, long timeout) {
            values.put(key, value);
            expires.put(key, System.currentTimeMillis() + timeout);
        }

        @Override
        public String get(String key) {
            return containsKey(key) ? values.get(key) : null;
        }

        @Override
        public boolean containsKey(String key) {
            Long expire = expires.get(key);
            return null != expire && System.currentTimeMillis() <= expire;
        }
    }
}
