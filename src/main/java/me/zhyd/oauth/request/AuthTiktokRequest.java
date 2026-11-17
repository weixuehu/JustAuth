package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.constants.Constants;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthTiktokScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.PkceUtil;
import me.zhyd.oauth.utils.StringUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * TikTok 登录
 *
 * <a href="https://developers.tiktok.com/doc/login-kit-web">Login Kit for Web</a>
 * <a href="https://developers.tiktok.com/doc/manage-user-access-tokens">Manage user access tokens</a>
 *
 * @since 1.16.8
 */
public class AuthTiktokRequest extends AuthDefaultRequest {

    /**
     * TikTok 用户信息接口需要显式声明返回字段
     */
    private static final String USER_INFO_FIELDS = "open_id,union_id,avatar_url,display_name";
    private static final String PKCE_CACHE_KEY = ":code_verifier:";
    private static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded;charset=UTF-8";

    public AuthTiktokRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TIKTOK);
    }

    public AuthTiktokRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TIKTOK, authStateCache);
    }

    /**
     * TikTok 的授权参数与标准 OAuth2 略有差异：使用 {@code client_key} 而不是 {@code client_id}，
     * 且 scope 之间以英文逗号分隔
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        String realState = getRealState(state);
        UrlBuilder builder = UrlBuilder.fromBaseUrl(source.authorize())
            .queryParam("client_key", config.getClientId())
            .queryParam("scope", this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthTiktokScope.values())))
            .queryParam("response_type", "code")
            .queryParam("redirect_uri", config.getRedirectUri())
            .queryParam("state", realState);
        if (config.isPkce()) {
            String cacheKey = source.getName().concat(PKCE_CACHE_KEY).concat(realState);
            String codeVerifier = PkceUtil.generateCodeVerifier();
            String codeChallengeMethod = "S256";
            builder.queryParam("code_challenge", PkceUtil.generateCodeChallenge(codeChallengeMethod, codeVerifier))
                .queryParam("code_challenge_method", codeChallengeMethod);
            // code_verifier 由 state 关联，回调时凭 state 取回
            authStateCache.cache(cacheKey, codeVerifier, TimeUnit.MINUTES.toMillis(10));
        }
        return builder.build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(8);
        form.put("client_key", config.getClientId());
        form.put("client_secret", config.getClientSecret());
        form.put("code", authCallback.getCode());
        form.put("grant_type", "authorization_code");
        form.put("redirect_uri", config.getRedirectUri());
        String codeVerifier = authCallback.getCodeVerifier();
        if (StringUtils.isEmpty(codeVerifier) && config.isPkce() && StringUtils.isNotEmpty(authCallback.getState())) {
            // 服务端应用：authorize 时以 state 为 key 缓存过 code_verifier
            codeVerifier = authStateCache.get(source.getName().concat(PKCE_CACHE_KEY).concat(authCallback.getState()));
        }
        if (StringUtils.isNotEmpty(codeVerifier)) {
            form.put("code_verifier", codeVerifier);
        }
        return this.getToken(form);
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        Map<String, String> form = new HashMap<>(5);
        form.put("client_key", config.getClientId());
        form.put("client_secret", config.getClientSecret());
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", oldToken.getRefreshToken());
        return AuthResponse.<AuthToken>builder()
            .code(AuthResponseStatus.SUCCESS.getCode())
            .data(this.getToken(form))
            .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add("Authorization", "Bearer " + authToken.getAccessToken());
        String url = UrlBuilder.fromBaseUrl(source.userInfo())
            .queryParam("fields", USER_INFO_FIELDS)
            .build();
        String response = new HttpUtils(config.getHttpConfig()).get(url, new HashMap<>(0), httpHeader, false).getBody();
        JSONObject jsonObject = JSONObject.parseObject(response);
        this.checkUserInfoResponse(jsonObject);
        JSONObject data = jsonObject.getJSONObject("data");
        JSONObject user = null == data ? null : data.getJSONObject("user");
        if (null == user) {
            throw new AuthException(AuthResponseStatus.FAILURE, source);
        }
        authToken.setOpenId(user.getString("open_id"));
        authToken.setUnionId(user.getString("union_id"));
        return AuthUser.builder()
            .rawUserInfo(user)
            .uuid(user.getString("open_id"))
            .username(user.getString("display_name"))
            .nickname(user.getString("display_name"))
            .avatar(user.getString("avatar_url"))
            .gender(AuthUserGender.UNKNOWN)
            .token(authToken)
            .source(source.toString())
            .build();
    }

    /**
     * 授权码换 token / 刷新 token 共用
     *
     * @param form 表单参数
     * @return AuthToken
     */
    private AuthToken getToken(Map<String, String> form) {
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(Constants.CONTENT_TYPE, CONTENT_TYPE_FORM);
        String response = new HttpUtils(config.getHttpConfig())
            .post(source.accessToken(), form, httpHeader, false)
            .getBody();
        JSONObject jsonObject = JSONObject.parseObject(response);
        this.checkTokenResponse(jsonObject);
        return AuthToken.builder()
            .accessToken(jsonObject.getString("access_token"))
            .openId(jsonObject.getString("open_id"))
            .expireIn(jsonObject.getIntValue("expires_in"))
            .refreshToken(jsonObject.getString("refresh_token"))
            .refreshTokenExpireIn(jsonObject.getIntValue("refresh_expires_in"))
            .scope(jsonObject.getString("scope"))
            .tokenType(jsonObject.getString("token_type"))
            .build();
    }

    /**
     * 检查 token 响应内容是否正确
     * <p>
     * 成功响应：{@code {"access_token":"...","open_id":"...","expires_in":86400}}
     * 失败响应：{@code {"error":"invalid_request","error_description":"...","log_id":"..."}}
     *
     * @param jsonObject 请求响应内容
     */
    private void checkTokenResponse(JSONObject jsonObject) {
        String error = jsonObject.getString("error");
        if (StringUtils.isNotEmpty(error)) {
            String errorDescription = jsonObject.getString("error_description");
            throw new AuthException(AuthResponseStatus.FAILURE.getCode(),
                StringUtils.isEmpty(errorDescription) ? error : errorDescription);
        }
    }

    /**
     * 检查用户信息响应内容是否正确
     * <p>
     * 成功响应：{@code {"data":{"user":{...}},"error":{"code":"ok","message":"","log_id":"..."}}}
     *
     * @param jsonObject 请求响应内容
     */
    private void checkUserInfoResponse(JSONObject jsonObject) {
        Object error = jsonObject.get("error");
        if (error instanceof JSONObject) {
            JSONObject errorObject = (JSONObject) error;
            String code = errorObject.getString("code");
            if (StringUtils.isNotEmpty(code) && !"ok".equalsIgnoreCase(code)) {
                String message = errorObject.getString("message");
                throw new AuthException(AuthResponseStatus.FAILURE.getCode(),
                    StringUtils.isEmpty(message) ? code : message);
            }
        }
    }
}
