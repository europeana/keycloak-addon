package eu.europeana.keycloak.password;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for creating BCrypt password hashing provider
 * Created by luthien on 27/05/2020.
 */
public class BCryptPasswordHashProviderFactory implements PasswordHashProviderFactory {

    private static final Logger LOG = Logger.getLogger(BCryptPasswordHashProviderFactory.class);

    private static final String ID = "BCrypt";

    private static final int DEFAULT_LOG_ROUNDS = 13;
    private static final int MIN_LOG_ROUNDS = 4;
    private static final int MAX_LOG_ROUNDS = 31;

    private int logRounds = DEFAULT_LOG_ROUNDS;

    private static final String PEPPER =  "KTY7Alni99sMkVH2rslK";

    @Override
    public PasswordHashProvider create(KeycloakSession keycloakSession) {
        LOG.debug("Creating BCryptPasswordHashProvider ...");
        return new BCryptPasswordHashProvider(ID, logRounds, PEPPER);
    }

    @Override
    public void init(Config.Scope scope) {
        LOG.debug("Initialising BCryptPasswordHashProviderFactory ...");
        Integer configLogRounds = scope.getInt("log-rounds");
        if (configLogRounds != null && configLogRounds >= MIN_LOG_ROUNDS && configLogRounds <= MAX_LOG_ROUNDS) {
            logRounds = configLogRounds;
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // no need to do anything
    }

    @Override
    public void close() {
        // no need to do anything
    }

    @Override
    public String getId() {
        return ID;
    }
}
