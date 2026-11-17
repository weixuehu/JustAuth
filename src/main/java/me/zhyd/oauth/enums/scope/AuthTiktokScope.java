package me.zhyd.oauth.enums.scope;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * TikTok 平台 OAuth 授权范围
 *
 * <a href="https://developers.tiktok.com/doc/login-kit-web">Login Kit for Web</a>
 *
 * @since 1.16.8
 */
@Getter
@AllArgsConstructor
public enum AuthTiktokScope implements AuthScope {

    /**
     * 默认开启，无需申请
     */
    USER_INFO_BASIC("user.info.basic", "获取用户基础信息（open_id、union_id、头像、昵称）", true),
    /**
     * 需在开发者后台申请
     */
    USER_INFO_PROFILE("user.info.profile", "获取用户资料信息（简介、认证状态、主页链接等）", false),
    /**
     * 需在开发者后台申请
     */
    USER_INFO_STATS("user.info.stats", "获取用户数据（粉丝数、关注数、点赞数、作品数）", false),
    /**
     * 需在开发者后台申请
     */
    VIDEO_LIST("video.list", "读取用户已发布的视频列表", false),
    /**
     * 需在开发者后台申请
     */
    VIDEO_PUBLISH("video.publish", "直接发布视频到用户账号", false),
    /**
     * 需在开发者后台申请
     */
    VIDEO_UPLOAD("video.upload", "上传视频到用户草稿箱，由用户在 App 内完成发布", false),
    ;

    private final String scope;
    private final String description;
    private final boolean isDefault;

}
