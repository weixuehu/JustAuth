package me.zhyd.oauth.utils;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.config.HttpConfig;
import me.zhyd.oauth.cache.AuthDefaultStateCache;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.exception.AuthException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Facebook Limited Login 身份令牌（authenticationToken）校验器
 * <p>
 * iOS 版 Facebook SDK 的 Limited Login 模式下，客户端拿到的是 Facebook 签发的 OIDC JWT，
 * 而不是可用来调用 Graph API 的 access token。服务端必须自行校验该 JWT 后才能信任其中的用户身份：
 * <ol>
 *     <li>使用 {@link #JWKS_URL} 公布的 RSA 公钥验签，且只接受 {@code RS256}，防止 alg=none / HS256 算法混淆攻击；</li>
 *     <li>校验 {@code iss}、{@code aud}（必须包含当前 App ID）、{@code exp}，并允许 {@code 120s} 的时钟偏差；</li>
 *     <li>同一串 JWT 只允许使用一次，防止重放。</li>
 * </ol>
 * JWKS 会缓存 6 小时，签名校验失败时会强制刷新一次（Facebook 轮换密钥后无需等待缓存过期）。
 * <p>
 * 注意：Facebook 签发的 JWT header 中通常不包含 {@code kid}，因此这里会遍历 JWKS 中的所有 RSA 公钥逐个尝试。
 *
 * @since 1.16.8
 */
public class FacebookLimitedLoginVerifier {

    /**
     * Facebook 公布的 OIDC JWKS 地址
     */
    public static final String JWKS_URL = "https://www.facebook.com/.well-known/oauth/openid/jwks/";

    private static final String EXPECTED_ISSUER = "https://www.facebook.com";
    private static final String JWT_ALGORITHM = "RS256";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String JWKS_CACHE_KEY = "justauth:facebook:limited-login:jwks";
    private static final String USED_TOKEN_CACHE_KEY_PREFIX = "justauth:facebook:limited-login:used:";
    private static final long JWKS_CACHE_TIMEOUT = TimeUnit.HOURS.toMillis(6);
    private static final long USED_TOKEN_MIN_TIMEOUT = TimeUnit.MINUTES.toMillis(1);
    private static final long ALLOWED_CLOCK_SKEW_SECONDS = 120L;
    private static final int JWT_PART_COUNT = 3;

    private final String appId;
    private final AuthStateCache cache;
    private final HttpConfig httpConfig;

    /**
     * @param appId      Facebook 应用的 App ID，同时作为 JWT 的 aud 校验值
     * @param cache      用于缓存 JWKS 与已使用的 token，为 {@code null} 时使用默认缓存
     * @param httpConfig 自定义 Http 配置，可为 {@code null}
     */
    public FacebookLimitedLoginVerifier(String appId, AuthStateCache cache, HttpConfig httpConfig) {
        this.appId = appId;
        this.cache = null == cache ? AuthDefaultStateCache.INSTANCE : cache;
        this.httpConfig = httpConfig;
    }

    /**
     * 校验 Facebook Limited Login 的 authenticationToken
     *
     * @param authenticationToken Facebook SDK 返回的 JWT
     * @return 校验通过后的 JWT payload（claims），包含 {@code sub}、{@code name}、{@code email}、{@code picture} 等字段
     * @throws AuthException token 非法、过期、aud 不匹配、签名错误或已被使用
     */
    public JSONObject verify(String authenticationToken) {
        if (StringUtils.isEmpty(authenticationToken)) {
            throw invalidToken("authenticationToken is empty");
        }
        String[] parts = authenticationToken.split("\\.");
        if (parts.length != JWT_PART_COUNT) {
            throw invalidToken("authenticationToken is not a valid JWT");
        }
        JSONObject header = decodePart(parts[0]);
        JSONObject claims = decodePart(parts[1]);
        if (!JWT_ALGORITHM.equals(header.getString("alg"))) {
            throw invalidToken("unsupported JWT algorithm: " + header.getString("alg"));
        }
        byte[] signature;
        try {
            signature = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw invalidToken("invalid JWT signature encoding");
        }
        String signingInput = parts[0] + "." + parts[1];
        if (!verifySignature(signingInput, signature, false) && !verifySignature(signingInput, signature, true)) {
            throw invalidToken("invalid JWT signature");
        }
        long now = System.currentTimeMillis() / 1000;
        checkClaims(claims, now);
        consumeToken(authenticationToken, claims, now);
        return claims;
    }

    /**
     * 拉取 Facebook JWKS，测试时可覆盖该方法以提供本地公钥
     *
     * @return JWKS 的 JSON 字符串
     */
    protected String fetchJwks() {
        return new HttpUtils(httpConfig).get(JWKS_URL).getBody();
    }

    private boolean verifySignature(String signingInput, byte[] signature, boolean forceRefreshJwks) {
        byte[] data = signingInput.getBytes(StandardCharsets.US_ASCII);
        for (PublicKey publicKey : loadJwks(forceRefreshJwks)) {
            try {
                Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
                verifier.initVerify(publicKey);
                verifier.update(data);
                if (verifier.verify(signature)) {
                    return true;
                }
            } catch (Exception ignored) {
                // 单个公钥验签失败时继续尝试下一个
            }
        }
        return false;
    }

    private List<PublicKey> loadJwks(boolean forceRefresh) {
        String jwksJson = forceRefresh ? null : cache.get(JWKS_CACHE_KEY);
        if (StringUtils.isEmpty(jwksJson)) {
            jwksJson = fetchJwks();
            if (StringUtils.isEmpty(jwksJson)) {
                throw new AuthException(AuthResponseStatus.FAILURE.getCode(), "Failed to load Facebook JWKS");
            }
            cache.cache(JWKS_CACHE_KEY, jwksJson, JWKS_CACHE_TIMEOUT);
        }
        List<PublicKey> publicKeys = parseJwks(jwksJson);
        if (publicKeys.isEmpty()) {
            throw new AuthException(AuthResponseStatus.FAILURE.getCode(), "Facebook JWKS contains no RSA public key");
        }
        return publicKeys;
    }

    private List<PublicKey> parseJwks(String jwksJson) {
        List<PublicKey> publicKeys = new ArrayList<>();
        try {
            JSONObject jwks = JSONObject.parseObject(jwksJson);
            JSONArray keys = null == jwks ? null : jwks.getJSONArray("keys");
            if (null == keys) {
                return publicKeys;
            }
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            for (int i = 0; i < keys.size(); i++) {
                JSONObject keyObject = keys.getJSONObject(i);
                if (null == keyObject || !"RSA".equalsIgnoreCase(keyObject.getString("kty"))) {
                    continue;
                }
                String modulus = keyObject.getString("n");
                String publicExponent = keyObject.getString("e");
                if (StringUtils.isEmpty(modulus) || StringUtils.isEmpty(publicExponent)) {
                    continue;
                }
                publicKeys.add(keyFactory.generatePublic(new RSAPublicKeySpec(
                    new BigInteger(1, Base64.getUrlDecoder().decode(modulus)),
                    new BigInteger(1, Base64.getUrlDecoder().decode(publicExponent)))));
            }
        } catch (Exception e) {
            throw new AuthException(AuthResponseStatus.FAILURE.getCode(), "Failed to parse Facebook JWKS: " + e.getMessage());
        }
        return publicKeys;
    }

    private void checkClaims(JSONObject claims, long now) {
        String issuer = claims.getString("iss");
        if (!EXPECTED_ISSUER.equals(issuer)) {
            throw invalidToken("illegal iss: " + issuer);
        }
        if (!audienceContains(claims.get("aud"))) {
            throw invalidToken("illegal aud, expected app id: " + appId);
        }
        Long expiresAt = getSeconds(claims, "exp");
        if (null == expiresAt) {
            throw invalidToken("exp is required");
        }
        if (now > expiresAt + ALLOWED_CLOCK_SKEW_SECONDS) {
            throw invalidToken("token expired");
        }
        Long issuedAt = getSeconds(claims, "iat");
        if (null != issuedAt && issuedAt > now + ALLOWED_CLOCK_SKEW_SECONDS) {
            throw invalidToken("token issued in the future");
        }
        Long notBefore = getSeconds(claims, "nbf");
        if (null != notBefore && notBefore > now + ALLOWED_CLOCK_SKEW_SECONDS) {
            throw invalidToken("token is not valid yet");
        }
        if (StringUtils.isEmpty(claims.getString("sub"))) {
            throw invalidToken("sub is required");
        }
    }

    private boolean audienceContains(Object audience) {
        if (audience instanceof String) {
            return appId.equals(audience);
        }
        if (audience instanceof JSONArray) {
            return ((JSONArray) audience).contains(appId);
        }
        return false;
    }

    private Long getSeconds(JSONObject claims, String field) {
        Object value = claims.get(field);
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    /**
     * 同一串 JWT 只允许使用一次：以 token 摘要作为 key 缓存到 exp 时刻。
     * <p>
     * 说明：get 与 cache 非原子操作，极端并发下存在同一 token 被同时消费的窗口；
     * 若需要严格的一次性语义，可将 {@link AuthStateCache} 换成带 setnx 的实现，例如 Redis。
     */
    private void consumeToken(String authenticationToken, JSONObject claims, long now) {
        Long expiresAt = getSeconds(claims, "exp");
        long timeout = null == expiresAt ? USED_TOKEN_MIN_TIMEOUT : Math.max(USED_TOKEN_MIN_TIMEOUT, (expiresAt - now) * 1000);
        String cacheKey = USED_TOKEN_CACHE_KEY_PREFIX + hex(Sha256.digest(authenticationToken));
        if (cache.containsKey(cacheKey)) {
            throw invalidToken("token has been used");
        }
        cache.cache(cacheKey, "1", timeout);
    }

    private JSONObject decodePart(String part) {
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(part);
            JSONObject jsonObject = JSONObject.parseObject(new String(bytes, StandardCharsets.UTF_8));
            if (null == jsonObject) {
                throw invalidToken("JWT payload is not a JSON object");
            }
            return jsonObject;
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw invalidToken("failed to decode JWT: " + e.getMessage());
        }
    }

    private static String hex(byte[] bytes) {
        if (null == bytes) {
            return "";
        }
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(Character.forDigit((b >> 4) & 0xF, 16));
            builder.append(Character.forDigit(b & 0xF, 16));
        }
        return builder.toString();
    }

    private AuthException invalidToken(String message) {
        return new AuthException(AuthResponseStatus.ILLEGAL_TOKEN.getCode(), "Invalid Facebook Limited Login token: " + message);
    }
}
