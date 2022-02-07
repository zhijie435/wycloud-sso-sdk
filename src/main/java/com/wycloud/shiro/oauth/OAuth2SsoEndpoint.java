package com.wycloud.shiro.oauth;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

/**
 * OAuth2SsoController
 *
 * @author wushanxi@gmail.com
 * @date 2019/10/24
 * @since 1.0
 */
@Slf4j
@Controller
public class OAuth2SsoEndpoint {
    private final static String PARAM_KEY_CODE = "code";
    private final static String PARAM_KEY_STATE = "state";
    private final static String PARAM_KEY_PROVIDER = "provider";
    private final static String SSO_LOGIN = "LOGIN";
    private final static String SSO_ACCOUNT_BINDING = "BIND";
    @Autowired
    private OAuth2SsoProperties oauth2SsoProperties;
    @Autowired
    private HttpServletRequest httpServletRequest;

    @GetMapping("/sso/login")
    public RedirectView oauth2Login(@RequestParam Map<String, String> param) throws UnsupportedEncodingException {
        if (param.isEmpty() || !param.containsKey(PARAM_KEY_CODE)) {
            return acquireCode(param.get(PARAM_KEY_PROVIDER));
        }

        Assert.isTrue(param.containsKey(PARAM_KEY_STATE));
        Assert.isTrue(param.containsKey(PARAM_KEY_CODE));
        String[] stateValues = param.get(PARAM_KEY_STATE).split("-");
        if (stateValues.length < 2) {
            throw new RuntimeException("Bad request");
        }
        if (SSO_LOGIN.equals(stateValues[1])) {
            return handleLogin(stateValues[0], param.get(PARAM_KEY_CODE));
        } else if (SSO_ACCOUNT_BINDING.equals(stateValues[1])) {
            return handleAccountBinding();
        } else {
            throw new RuntimeException("Bad request");
        }
    }

    @SneakyThrows
    private RedirectView acquireCode(String providerId) {
        String callbackUrl = !StringUtils.isEmpty(oauth2SsoProperties.getClient().getRedirectUri()) ? oauth2SsoProperties.getClient().getRedirectUri() : httpServletRequest.getRequestURL().toString();

        String url = String.format("%s?response_type=code&scope=%s&client_id=%s&state=%s&redirect_uri=%s",
                oauth2SsoProperties.getClient().getSsoServerUri() + "/oauth/authorize",
                oauth2SsoProperties.getClient().getScope(),
                oauth2SsoProperties.getClient().getClientId(),
                providerId + "-" + SSO_LOGIN,
                URLEncoder.encode(callbackUrl, "UTF-8"));
        return new RedirectView(url);
    }

    private RedirectView handleLogin(String providerId, String code) {
        try {
            Subject subject = SecurityUtils.getSubject();
            OAuth2SsoAuthenticationToken token = new OAuth2SsoAuthenticationToken(providerId, code);
            subject.login(token);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;
        }
        return new RedirectView(oauth2SsoProperties.getClient().getTargetUri());
    }

    private RedirectView handleAccountBinding() {
        throw new UnsupportedOperationException("账号绑定尚未实现");
    }
}
