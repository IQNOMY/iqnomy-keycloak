package com.iqnomy.commons.keycloak;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.LoginException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.OAuth2Constants;
import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.ServerRequest.HttpFailure;
import org.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.util.JsonSerialization;

/**
 * Use {@linkplain #authenticate()} to get an access token for a Keycloak service account.
 * 
 * Instances of this class are not thread-safe.
 * 
 * Based on https://github.com/keycloak/keycloak/blob/master/examples/demo-template/service-account/src/main/java/org/keycloak/example/ProductServiceAccountServlet.java
 * 
 */
public class ServiceAccountAuthenticator {

	private static KeycloakDeployment deployment;
	private static CloseableHttpClient client;

	private String token;
	private String refreshToken;
	private AccessToken accessToken;
	

	public ServiceAccountAuthenticator(final AdapterConfig adapterConfig) {
		init(adapterConfig);
	}

	public ServiceAccountAuthenticator(final InputStream keycloakConfigInputStream) {
		init(KeycloakDeploymentBuilder.loadAdapterConfig(keycloakConfigInputStream));
	}

	public void cleanup() throws IOException, LoginException, HttpFailure {
		finalize();
	}

	private void init(final AdapterConfig adapterConfig) {
		deployment = KeycloakDeploymentBuilder.build(adapterConfig);
		client = HttpClientBuilder.create().build();
	}

	@Override
	public void finalize() throws IOException, LoginException, HttpFailure {
		try {
			logout();
		} finally {
			client.close();
		}
	}

	public AccessToken getAccessToken() {
		return accessToken;
	}

	public String getToken() {
		return token;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	private void setTokens(final AccessTokenResponse tokenResponse) throws IOException, VerificationException {
		token = tokenResponse.getToken();
		refreshToken = tokenResponse.getRefreshToken();
		accessToken = RSATokenVerifier.verifyToken(token, deployment.getRealmKey(), deployment.getRealmInfoUrl());
	}

	private String getContent(final HttpEntity entity) throws IOException {
		if (entity == null)
			return null;
		final InputStream is = entity.getContent();
		try {
			final ByteArrayOutputStream os = new ByteArrayOutputStream();
			int c;
			while ((c = is.read()) != -1) {
				os.write(c);
			}
			final byte[] bytes = os.toByteArray();
			final String data = new String(bytes);
			return data;
		} finally {
			is.close();
		}
	}

	public void login() throws LoginException, IOException, VerificationException {
		final HttpPost post = new HttpPost(deployment.getTokenUrl());
		final List<NameValuePair> formparams = new ArrayList<NameValuePair>();
		formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS));

		// Add client credentials according to the method configured in
		// keycloak-client-secret.json or keycloak-client-signed-jwt.json file
		final Map<String, String> reqHeaders = new HashMap<>();
		final Map<String, String> reqParams = new HashMap<>();
		ClientCredentialsProviderUtils.setClientCredentials(deployment, reqHeaders, reqParams);
		for (final Map.Entry<String, String> header : reqHeaders.entrySet()) {
			post.setHeader(header.getKey(), header.getValue());
		}
		for (final Map.Entry<String, String> param : reqParams.entrySet()) {
			formparams.add(new BasicNameValuePair(param.getKey(), param.getValue()));
		}

		final UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
		post.setEntity(form);

		final HttpResponse response = client.execute(post);
		final int status = response.getStatusLine().getStatusCode();
		final HttpEntity entity = response.getEntity();
		if (status != 200) {
			final String json = getContent(entity);
			throw new LoginException("Service account login failed. Bad status: " + status + " response: " + json);
		} else if (entity == null) {
			throw new LoginException("No entity");
		} else {
			final String json = getContent(entity);
			final AccessTokenResponse tokenResp = JsonSerialization.readValue(json, AccessTokenResponse.class);
			setTokens(tokenResp);
		}
	}

	public void refreshToken() throws LoginException, IOException, VerificationException, HttpFailure {
		if (refreshToken == null) {
			throw new LoginException("No refresh token available. Please login first");
		} else {
			setTokens(ServerRequest.invokeRefresh(deployment, refreshToken));
		}
	}

	public void logout() throws LoginException, IOException, HttpFailure {
		if (token == null) {
			throw new LoginException("No token available. Please login first");
		} else {
			ServerRequest.invokeLogout(deployment, refreshToken);
			token = null;
			refreshToken = null;
			accessToken = null;
		}
	}

	public boolean isLoggedIn() {
		return null != accessToken;
	}

	public boolean isExpired() {
		if (isLoggedIn()) {
			return accessToken.isExpired();
		}
		return false;
	}
	
	public void authenticate() throws LoginException, IOException, VerificationException, HttpFailure {
		if (!isLoggedIn()) {
			login();
		} else {
			if (isExpired()) {
				refreshToken();
			}
		}
	}

}