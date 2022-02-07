package com.wycloud.shiro.oauth;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * OAuth2SsoAuthenticationToken
 *
 * @author wushanxi@gmail.com
 * @date 2019/10/23
 * @since 1.0
 */
@Data
@AllArgsConstructor
public class OAuth2SsoAuthenticationToken extends UsernamePasswordToken {
    private String provider;
    private String code;
}
