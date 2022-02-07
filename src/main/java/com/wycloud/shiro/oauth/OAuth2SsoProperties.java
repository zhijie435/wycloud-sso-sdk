package com.wycloud.shiro.oauth;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * OAuth2ClientProperties
 *
 * @author wushanxi（wushanxi@gmail.com）
 * @date 2019/10/23
 * @since 1.0
 */
@Data
@ConfigurationProperties("oauth2")
public class OAuth2SsoProperties {
    private OAuth2ClientProperties client;
    private ProtectedOAuth2Resource resource;

    /**
     * OAuth2 客户端配置
     */
    @Data
    public static class OAuth2ClientProperties {
        private String clientId;
        private String clientSecret;
        private String ssoServerUri;
        private String redirectUri;
        private String logoutUri;
        private String targetUri;
        private String scope;
    }

    /**
     * 受保护的OAuth2资源(需要access token才能访问)
     */
    @Data
    public static class ProtectedOAuth2Resource {
        private String checkTokenUri;
    }
}
