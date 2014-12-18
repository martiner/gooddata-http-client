/*
 * Copyright (C) 2007-2014, GoodData(R) Corporation. All rights reserved.
 * This program is made available under the terms of the BSD License.
 */
package com.gooddata.http.client;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;

import java.io.IOException;

import static org.apache.commons.lang.Validate.notNull;

/**
 * This strategy obtains super-secure token via login and password.
 */
public class LoginSSTRetrievalStrategy implements SSTRetrievalStrategy {

    public static final String LOGIN_URL = "/gdc/account/login";
    public static final String SST_ENTITY = "userLogin";

    /** SST and TT must be present in the HTTP header. */
    private static final int VERIFICATION_LEVEL = 2;

    private final Log log = LogFactory.getLog(getClass());

    private final String login;

    private final String password;

    /**
     * Construct object.
     * @param login user login
     * @param password user password
     */
    public LoginSSTRetrievalStrategy(final String login, final String password) {
        notNull(login, "Login cannot be null");
        notNull(password, "Password cannot be null");
        this.login = login;
        this.password = password;
    }

    @Override
    public String obtainSst(final HttpClient httpClient, final HttpHost httpHost) throws IOException {
        log.debug("Obtaining STT");
        final HttpPost postLogin = new HttpPost(LOGIN_URL);
        try {
            final HttpEntity requestEntity = new StringEntity(createLoginJson(), ContentType.APPLICATION_JSON);
            postLogin.setEntity(requestEntity);
            postLogin.setHeader("Accept", ContentType.APPLICATION_JSON.toString());
            final HttpResponse response = httpClient.execute(httpHost, postLogin);
            int status = response.getStatusLine().getStatusCode();
            if (status != HttpStatus.SC_OK) {
                throw new GoodDataAuthException("Unable to login: " + status);
            }
            final String sst = extractSST(response);
            if (sst == null) {
                throw new GoodDataAuthException("Unable to login. Missing SST Set-Cookie header.");
            }
            return sst;
        } finally {
            postLogin.releaseConnection();
        }
    }

    private String createLoginJson() {
        return "{\"postUserLogin\":{\"login\":\"" + StringEscapeUtils.escapeJavaScript(login) +
                "\",\"password\":\"" + StringEscapeUtils.escapeJavaScript(password) + "\",\"remember\":0" +
                ",\"verify_level\":" + VERIFICATION_LEVEL + "}}";
    }

    private String extractSST(final HttpResponse response) throws IOException {
        return TokenUtils.extractTokenFromBody(response, SST_ENTITY);
    }
}
