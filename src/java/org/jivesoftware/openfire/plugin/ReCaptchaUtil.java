/*
 * Copyright (C) 2021 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware.openfire.plugin;

import org.directwebremoting.json.JsonUtil;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Utilities to work with Google's ReCaptcha.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class ReCaptchaUtil
{
    private static final Logger Log = LoggerFactory.getLogger(ReCaptchaUtil.class);

    /**
     * The expected value is a boolean, if true any users will be need to verify its a human at the
     * following url http://[SERVER_NAME}:9090/plugins/registration/sign-up.jsp
     */
    private static final String RECAPTCHA_ENABLED = "registration.recaptcha.enabled";

    /**
     * The expected value is a double between 0.0 and 1.0, representing the minimal value that is considered to be 'pass'.
     */
    private static final String RECAPTCHA_MINIMAL_SCORE = "registration.recaptcha.score.minimal";

    /**
     * The expected value is a String that contains the site key for recaptcha.
     */
    private static final String RECAPTCHA_SITE_KEY = "registration.recaptcha.key.site";

    /**
     * The expected value is a String that contains the site secret for recaptcha.
     */
    private static final String RECAPTCHA_SECRET_KEY = "registration.recaptcha.key.secret";

    public static void setReCaptchaEnabled(boolean enable) {
        JiveGlobals.setProperty(RECAPTCHA_ENABLED, enable ? "true" : "false");
    }

    public static boolean reCaptchaEnabled() {
        return JiveGlobals.getBooleanProperty(RECAPTCHA_ENABLED, false);
    }

    public static void setReCaptchaMinimalScore(double score) {
        JiveGlobals.setProperty(RECAPTCHA_MINIMAL_SCORE, Double.toString(score) );
    }

    public static double getReCaptchaMinimalScore() {
        return Double.parseDouble(JiveGlobals.getProperty(RECAPTCHA_MINIMAL_SCORE, "0.5"));
    }

    public static void setReCaptchaSiteKey(String siteKey) {
        JiveGlobals.setProperty(RECAPTCHA_SITE_KEY, siteKey);
    }

    public static String getReCaptchaSiteKey() {
        return JiveGlobals.getProperty(RECAPTCHA_SITE_KEY);
    }

    public static void setReCaptchaSecretKey(String secretKey) {
        JiveGlobals.setPropertyEncrypted(RECAPTCHA_SECRET_KEY, false);
        JiveGlobals.setProperty(RECAPTCHA_SECRET_KEY, secretKey);
    }

    public static String getReCaptchaSecretKey() {
        return JiveGlobals.getProperty(RECAPTCHA_SECRET_KEY);
    }

    /**
     * Verifies the recaptchaResponse (returned by the client of the end-user), by submitting it to Google's verification
     * web-service.
     *
     * This method invokes a webservice call to a remote domain, and will block until a response is returned.
     *
     * @param recaptchaResponse The ReCaptcha response to be verified.
     * @param remoteIP The IP address of the client that provided the response.
     * @return true if the captcha challenge passed, otherwise false.
     */
    public static boolean verify(final String recaptchaResponse, final String remoteIP)
    {
        Log.debug("Verifying reCaptcha response from '{}'", remoteIP);
        try
        {
            final String secret = URLEncoder.encode(getReCaptchaSecretKey(), StandardCharsets.UTF_8.toString());
            final String response = URLEncoder.encode(recaptchaResponse, StandardCharsets.UTF_8.toString());
            final String ip = URLEncoder.encode(remoteIP, StandardCharsets.UTF_8.toString());
            final String entity = "secret=" + secret + "&response=" + response + "&remoteip=" + ip;

            final URL url = new URL("https://www.google.com/recaptcha/api/siteverify");
            final HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");

            con.setDoOutput(true);
            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream()) ) {
                 wr.writeBytes(entity);
                 wr.flush();
            }

            final int responseCode = con.getResponseCode();
            if (responseCode != 200) {
                Log.debug("Failed reCaptcha verification of '{}': Google's service responded with status code {}", new Object[] {remoteIP, responseCode});
                return false;
            }

            try (final InputStreamReader in = new InputStreamReader(con.getInputStream())) {
                final Map<String, Object> json = JsonUtil.toSimpleObject(in);
                if (!json.get("success").equals(true)) {
                    Log.debug("Failed reCaptcha verification of '{}': Google's service did not respond with 'success'.", remoteIP);
                    return false;
                }
                final double score = (Double) json.get("score");
                if (!(score >= getReCaptchaMinimalScore())) {
                    Log.debug("Failed reCaptcha verification of '{}': Google's service responded with score {}. Minimal score to pass is: {}", new Object[] {remoteIP, score, getReCaptchaMinimalScore()});
                    return false;
                }
                return true;
            }
        } catch (Exception e) {
            Log.warn("Failed reCaptcha verification of '{}': An exception occurred.", new Object[] {remoteIP}, e);
            return false;
        }
    }
}
