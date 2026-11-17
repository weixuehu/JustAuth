package me.zhyd.oauth.request;

import me.zhyd.oauth.cache.AuthDefaultStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.model.AuthCallback;
import org.junit.Assert;
import org.junit.Test;

public class AuthTiktokRequestTest {

    private AuthConfig config(boolean pkce) {
        return AuthConfig.builder()
            .clientId("client_key_123")
            .clientSecret("client_secret_123")
            .redirectUri("https://www.justauth.cn/callback/tiktok")
            .pkce(pkce)
            .build();
    }

    @Test
    public void authorizeUrl() {
        AuthTiktokRequest request = new AuthTiktokRequest(config(false));
        String url = request.authorize("state_123");
        Assert.assertTrue(url.startsWith("https://www.tiktok.com/v2/auth/authorize/?"));
        Assert.assertTrue(url.contains("client_key=client_key_123"));
        Assert.assertTrue(url.contains("response_type=code"));
        Assert.assertTrue(url.contains("state=state_123"));
        Assert.assertTrue(url.contains("redirect_uri=https://www.justauth.cn/callback/tiktok"));
        Assert.assertTrue(url.contains("scope=user.info.basic"));
        Assert.assertFalse(url.contains("code_challenge="));
    }

    @Test
    public void authorizeUrlWithCustomScopes() {
        AuthConfig config = config(false);
        config.setScopes(java.util.Arrays.asList("user.info.basic", "user.info.profile"));
        String url = new AuthTiktokRequest(config).authorize("state_123");
        // 多个 scope 以英文逗号分隔，并对整个 scope 字符串做 url encode
        Assert.assertTrue(url.contains("scope=user.info.basic%2Cuser.info.profile"));
    }

    @Test
    public void authorizeUrlWithPkce() {
        AuthDefaultStateCache cache = AuthDefaultStateCache.INSTANCE;
        AuthTiktokRequest request = new AuthTiktokRequest(config(true), cache);
        String url = request.authorize("pkce_state");
        Assert.assertTrue(url.contains("code_challenge="));
        Assert.assertTrue(url.contains("code_challenge_method=S256"));
        // code_verifier 以 state 为 key 缓存，回调时凭 state 取回
        Assert.assertNotNull(cache.get("TIKTOK:code_verifier:pkce_state"));
    }

    @Test
    public void callbackSupportsExplicitCodeVerifier() {
        // App 端无法依赖 state 缓存时，可以直接把 code_verifier 放进 AuthCallback
        AuthCallback callback = AuthCallback.builder()
            .code("code_123")
            .state("state_123")
            .codeVerifier("verifier_123")
            .build();
        Assert.assertEquals("code_123", callback.getCode());
        Assert.assertEquals("verifier_123", callback.getCodeVerifier());
    }
}
