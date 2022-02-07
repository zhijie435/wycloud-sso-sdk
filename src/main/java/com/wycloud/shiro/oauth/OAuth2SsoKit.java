/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.wycloud.shiro.oauth;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.codec.Base64;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

/**
 * @author wushanxi@gmail.com
 * @date 2019-10-25
 */
@Slf4j
@Component
@AllArgsConstructor
public class OAuth2SsoKit {
    private OAuth2SsoProperties oAuth2SsoProperties;
    private HttpServletRequest httpServletRequest;
    private HttpServletResponse httpServletResponse;

    /**
     * 通过code 换取 accessToken 等信息
     *
     * @param code 授权码
     * @return
     */
    public Map<String, Object> getAccessToken(String code) {
        final String url = tokenRequestUrl(code);
        log.debug("resuest {}", url);
        HttpHeaders headers = buildRequestHeader();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        try {
            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "authorization_code");
            map.add("scope", oAuth2SsoProperties.getClient().getScope());
            map.add("code", code);

            String callbackUrl = !StringUtils.isEmpty(oAuth2SsoProperties.getClient().getRedirectUri())
                    ? oAuth2SsoProperties.getClient().getRedirectUri() : httpServletRequest.getRequestURL().toString();

            map.add("redirect_uri", callbackUrl);
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            ResponseEntity<String> response = new RestTemplate().postForEntity(oAuth2SsoProperties.getClient().getSsoServerUri() + "/oauth/token", request, String.class);
            log.debug("response status: {}", response.getStatusCode());
            log.debug("payload : {}", response.getBody());
            Map<String, Object> objectMap = jsonToMap(response.getBody());
            SecurityUtils.getSubject().getSession().setAttribute(Constant.token, objectMap);
            return objectMap;
        } catch (Exception e) {
            log.error("获取access_token失败:" + e.getMessage(), e);
            throw new AuthenticationException("获取access_token失败:" + e.getMessage(), e);
        }
    }


    @SneakyThrows
    public void logout() {
        // 跳转至用户指定的页面
        String logoutUrl = String.format("%s/logout?redirect_url=%s"
                , oAuth2SsoProperties.getClient().getSsoServerUri()
                , URLEncoder.encode(oAuth2SsoProperties.getClient().getLogoutUri()));
        httpServletResponse.sendRedirect(logoutUrl);
    }

    public String deleteToken(){
        Object result = SecurityUtils
                .getSubject().getSession().getAttribute(Constant.token);
        if (result == null) {
            log.warn("sso 退出失败，当前session 不包含token");
            return "empty token";
        }

        Map<String, Object> objectMap = (Map<String, Object>) SecurityUtils
                .getSubject().getSession().getAttribute(Constant.token);

        String token = (String) objectMap.get("access_token");
        String url = oAuth2SsoProperties.getClient().getSsoServerUri() + "/token/logout";

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
        return  new RestTemplate().exchange(url, HttpMethod.DELETE, request, String.class).getBody();
    }


    @SneakyThrows
    private String tokenRequestUrl(String code) {
        String template = "%s?grant_type=authorization_code&scope=%s&code=%s&redirect_uri=%s";
        return String.format(template,
                oAuth2SsoProperties.getClient().getSsoServerUri() + "/oauth/token",
                oAuth2SsoProperties.getClient().getScope(),
                code,
                oAuth2SsoProperties.getClient().getRedirectUri());
    }

    @SneakyThrows
    private HttpHeaders buildRequestHeader() {
        final String basicAuthorization = oAuth2SsoProperties.getClient().getClientId() + ":" + oAuth2SsoProperties.getClient().getClientSecret();
        HttpHeaders headers = new HttpHeaders();

        String encodeToString = Base64.encodeToString(basicAuthorization.getBytes());
        headers.add(HttpHeaders.AUTHORIZATION, "Basic " + encodeToString);
        return headers;
    }


    private Map<String, Object> jsonToMap(String json) throws IOException {
        if (StringUtils.isEmpty(json)) {
            return new HashMap<>();
        }
        ObjectMapper mapper = new ObjectMapper();
        TypeReference<Map<String, Object>> typeRef = new TypeReference<Map<String, Object>>() {
        };
        return mapper.readValue(json, typeRef);
    }
}
