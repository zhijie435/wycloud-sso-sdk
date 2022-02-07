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

package com.wycloud.shiro;

import com.wycloud.shiro.oauth.OAuth2SsoProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * OAuth2SsoConfig
 *
 * @author wushanxi (wushanxi@gmail.com)
 * @date 2019/10/23
 * @since 1.0
 */
@Configuration
@ComponentScan("com.wycloud.shiro.oauth")
@EnableConfigurationProperties(OAuth2SsoProperties.class)
public class OAuth2SsoConfiguration {
}
