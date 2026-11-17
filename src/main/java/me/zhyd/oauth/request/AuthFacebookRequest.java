package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthFacebookScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.FacebookLimitedLoginVerifier;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.StringUtils;
import me.zhyd.oauth.utils.UrlBuilder;

/**
 * Facebook登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.3.0
 */
public class AuthFacebookRequest extends AuthDefaultRequest {

    private static final String DEBUG_TOKEN_URL = "https://graph.facebook.com/debug_token";

    public AuthFacebookRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FACEBOOK);
    }

    public AuthFacebookRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FACEBOOK, authStateCache);
    }

    /**
     * 使用 Facebook Limited Login（iOS SDK）返回的 authenticationToken 登录
     * <p>
     * Limited Login 模式下 Facebook 不返回 access token，而是返回一个 OIDC JWT，
     * 服务端需要校验签名（RS256）、iss、aud、exp 后才能信任其中的用户身份。
     * <p>
     * 仅做 App 端登录时，可在 {@link AuthConfig} 中设置 {@code ignoreCheckRedirectUri(true)} 并留空 redirectUri。
     *
     * @param authenticationToken Facebook SDK 返回的 JWT
     * @return 登录结果
     * @since 1.16.8
     */
    public AuthResponse<AuthUser> loginByAuthenticationToken(String authenticationToken) {
        try {
            JSONObject claims = new FacebookLimitedLoginVerifier(config.getClientId(), authStateCache, config.getHttpConfig())
                .verify(authenticationToken);
            return AuthResponse.<AuthUser>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthUser.builder()
                    .rawUserInfo(claims)
                    .uuid(claims.getString("sub"))
                    .username(claims.getString("name"))
                    .nickname(claims.getString("name"))
                    .avatar(claims.getString("picture"))
                    .email(claims.getString("email"))
                    .gender(AuthUserGender.UNKNOWN)
                    .token(AuthToken.builder().idToken(authenticationToken).build())
                    .source(source.toString())
                    .build())
                .build();
        } catch (Exception e) {
            return this.responseError(e);
        }
    }

    /**
     * 使用 App 端已经拿到的 Facebook user access token 登录
     * <p>
     * 先用 app access token（{@code clientId|clientSecret}）调用 {@code debug_token} 校验该 token 是否有效、
     * 是否属于当前应用，校验通过后再调用 Graph API 获取用户信息。
     * <p>
     * 仅做 App 端登录时，可在 {@link AuthConfig} 中设置 {@code ignoreCheckRedirectUri(true)} 并留空 redirectUri。
     *
     * @param accessToken Facebook user access token
     * @return 登录结果
     * @since 1.16.8
     */
    public AuthResponse<AuthUser> loginByAccessToken(String accessToken) {
        try {
            if (StringUtils.isEmpty(accessToken)) {
                throw new AuthException(AuthResponseStatus.ILLEGAL_TOKEN, source);
            }
            JSONObject data = this.debugToken(accessToken).getJSONObject("data");
            if (null == data || !data.getBooleanValue("is_valid") || !config.getClientId().equals(data.getString("app_id"))) {
                throw new AuthException(AuthResponseStatus.ILLEGAL_TOKEN, source);
            }
            AuthUser authUser = this.getUserInfo(AuthToken.builder().accessToken(accessToken).build());
            return AuthResponse.<AuthUser>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(authUser)
                .build();
        } catch (Exception e) {
            return this.responseError(e);
        }
    }

    /**
     * 调用 Facebook debug_token 接口校验 access token
     *
     * @param accessToken 待校验的 user access token
     * @return debug_token 的响应内容
     */
    private JSONObject debugToken(String accessToken) {
        String url = UrlBuilder.fromBaseUrl(DEBUG_TOKEN_URL)
            .queryParam("input_token", accessToken)
            .queryParam("access_token", config.getClientId() + "|" + config.getClientSecret())
            .build(true);
        String response = new HttpUtils(config.getHttpConfig()).get(url).getBody();
        return JSONObject.parseObject(response);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
            .accessToken(accessTokenObject.getString("access_token"))
            .expireIn(accessTokenObject.getIntValue("expires_in"))
            .tokenType(accessTokenObject.getString("token_type"))
            .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);
        JSONObject object = JSONObject.parseObject(userInfo);
        this.checkResponse(object);
        return AuthUser.builder()
            .rawUserInfo(object)
            .uuid(object.getString("id"))
            .username(object.getString("name"))
            .nickname(object.getString("name"))
            .blog(object.getString("link"))
            .avatar(getUserPicture(object))
            .location(object.getString("locale"))
            .email(object.getString("email"))
            .gender(AuthUserGender.getRealGender(object.getString("gender")))
            .token(authToken)
            .source(source.toString())
            .build();
    }

    private String getUserPicture(JSONObject object) {
        String picture = null;
        if (object.containsKey("picture")) {
            JSONObject pictureObj = object.getJSONObject("picture");
            pictureObj = pictureObj.getJSONObject("data");
            if (null != pictureObj) {
                picture = pictureObj.getString("url");
            }
        }
        return picture;
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
            .queryParam("access_token", authToken.getAccessToken())
            .queryParam("fields", "id,name,birthday,gender,hometown,email,devices,picture.width(400),link")
            .build();
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        // facebook的回调地址必须为https的链接
        // App 端登录（Limited Login / access token）不依赖回调地址，允许不配置 redirectUri
        if (AuthDefaultSource.FACEBOOK == source
            && StringUtils.isNotEmpty(config.getRedirectUri())
            && !GlobalAuthUtils.isHttpsProtocol(config.getRedirectUri())) {
            // Facebook's redirect uri must use the HTTPS protocol
            throw new AuthException(AuthResponseStatus.ILLEGAL_REDIRECT_URI, source);
        }
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if (object.containsKey("error")) {
            throw new AuthException(object.getJSONObject("error").getString("message"));
        }
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
            .queryParam("scope", this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthFacebookScope.values())))
            .build();
    }
}
