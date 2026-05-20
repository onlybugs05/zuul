/**
 * Copyright 2018 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.zuul.sample.push;

import com.google.common.base.Strings;
import com.netflix.zuul.message.http.Cookies;
import com.netflix.zuul.netty.server.push.PushAuthHandler;
import com.netflix.zuul.netty.server.push.PushUserAuth;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.cookie.Cookie;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Validates the "userAuthCookie" using HMAC-SHA256 so that forged/tampered cookies are rejected.
 * Expected cookie format: {@code <customerId>.<base64url-HMAC-SHA256>}
 * The HMAC is computed over the customerId using a shared secret configured via the
 * {@code zuul.sample.auth.cookieSecret} system property (falls back to a default for demo purposes).
 *
 * In production, replace the hardcoded fallback with a securely managed secret and use
 * encrypted, short-lived tokens instead of HMAC-signed plain-text identifiers.
 *
 * Author: Susheel Aroskar
 * Date: 5/16/18
 */
@ChannelHandler.Sharable
public class SamplePushAuthHandler extends PushAuthHandler {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    /** Separator between customerId and its HMAC signature in the cookie value. */
    private static final char COOKIE_SEPARATOR = '.';

    /**
     * Secret used to sign cookie values.  Override via the {@code zuul.sample.auth.cookieSecret}
     * system property in any real deployment.
     */
    private static final byte[] COOKIE_SECRET = System.getProperty(
                    "zuul.sample.auth.cookieSecret", "change-me-in-production-to-a-long-random-secret")
            .getBytes(StandardCharsets.UTF_8);

    public SamplePushAuthHandler(String path) {
        super(path, ".sample.netflix.com");
    }

    /**
     * We support only cookie based auth in this sample
     */
    @Override
    protected boolean isDelayedAuth(FullHttpRequest req, ChannelHandlerContext ctx) {
        return false;
    }

    /**
     * Compute the HMAC-SHA256 of {@code data} using {@link #COOKIE_SECRET}.
     */
    private String computeHmac(String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(COOKIE_SECRET, HMAC_ALGORITHM));
            byte[] raw = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC setup failed", e);
        }
    }

    @Override
    protected PushUserAuth doAuth(FullHttpRequest req, ChannelHandlerContext ctx) {
        Cookies cookies = parseCookies(req);
        for (Cookie c : cookies.getAll()) {
            if (c.name().equals("userAuthCookie")) {
                String cookieValue = c.value();
                if (!Strings.isNullOrEmpty(cookieValue)) {
                    int sepIdx = cookieValue.indexOf(COOKIE_SEPARATOR);
                    // Require a non-empty customerId before the separator and a non-empty HMAC after it
                    if (sepIdx > 0 && sepIdx < cookieValue.length() - 1) {
                        String customerId = cookieValue.substring(0, sepIdx);
                        String providedMac = cookieValue.substring(sepIdx + 1);
                        String expectedMac = computeHmac(customerId);
                        // Constant-time comparison to prevent timing attacks
                        if (MessageDigest.isEqual(
                                expectedMac.getBytes(StandardCharsets.UTF_8),
                                providedMac.getBytes(StandardCharsets.UTF_8))) {
                            return new SamplePushUserAuth(customerId);
                        }
                    }
                }
            }
        }
        return new SamplePushUserAuth(HttpResponseStatus.UNAUTHORIZED.code());
    }
}
