# iqnomy-keycloak
IQNOMY Keycloak commons 'library' contains Keycloak supporting classes used by https://www.humanswitch.io.
For now only the class `com.iqnomy.commons.keycloak.ServiceAccountAuthenticator` is available, which can be used to get a token for a Keycloak service account.
Basically this can be done like this:

```java
ServiceAccountAuthenticator serviceAccountAuthenticator = new ServiceAccountAuthenticator(keycloakConfigInputStream);
serviceAccountAuthenticator.authenticate();
````
The `authenticate()` method will log you in if not logged, or will refresh the token if expired.
