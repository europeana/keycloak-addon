package eu.europeana.keycloak.password;

import org.apache.commons.codec.binary.Base64;

import org.jboss.logging.Logger;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;

import java.nio.charset.StandardCharsets;
import org.springframework.security.crypto.bcrypt.BCrypt;


/**
 * Created by luthien on 27/05/2020.
 */
public class BCryptPasswordHashProvider implements PasswordHashProvider  {

    private static final Logger LOG = Logger.getLogger(BCryptPasswordHashProvider.class);
    private final int    logRounds;
    private final String providerId;
    private final String pepper;


    public BCryptPasswordHashProvider(String providerId, int logRounds, String pepper) {
        LOG.debug("BCryptPasswordHashProvider created");
        this.providerId     = providerId;
        this.logRounds      = logRounds;
        this.pepper         = pepper;
    }

    @Override
    public boolean policyCheck(PasswordPolicy passwordPolicy, CredentialModel credentialModel) {
        LOG.debug("BCryptPasswordHashProvider policy check");
        return passwordPolicy.getHashAlgorithm().equals(credentialModel.getAlgorithm())
               && (passwordPolicy.getHashIterations() == credentialModel.getHashIterations());
    }

    @Override
    public void encode(String rawPassword, int iterations, CredentialModel credentialModel) {
        LOG.debug("BCryptPasswordHashProvider encoding password ...");
        String salt     = BCrypt.gensalt(logRounds);
        String hashedPassword = getHash(rawPassword, salt);

        credentialModel.setAlgorithm(providerId);
        credentialModel.setType(UserCredentialModel.PASSWORD);
        credentialModel.setSalt(salt.getBytes(StandardCharsets.UTF_8));
        credentialModel.setValue(hashedPassword);
        credentialModel.setHashIterations(iterations);
    }

    private String getHash(String rawPassword, String salt) {
        LOG.debug("BCryptPasswordHashProvider adding salt and pepper ...");
        String pepperedPassword = rawPassword + pepper;
        String base64PepperedPw = new String(Base64.encodeBase64(pepperedPassword.getBytes(StandardCharsets.UTF_8)),
                                             StandardCharsets.UTF_8);
        return BCrypt.hashpw(base64PepperedPw, salt);
    }

    @Override
    public boolean verify(String rawPassword, CredentialModel credentialModel) {
        LOG.debug("BCryptPasswordHashProvider verifying password ...");
        return getHash(rawPassword, new String(credentialModel.getSalt(), StandardCharsets.UTF_8))
                .equals(credentialModel.getValue());
    }

    @Override
    public void close() {
        // no need to do anything
    }
}
