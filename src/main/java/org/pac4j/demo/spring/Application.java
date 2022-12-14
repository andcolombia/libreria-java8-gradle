package org.pac4j.demo.spring;

import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.http.adapter.JEEHttpActionAdapter;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.http.client.indirect.FormClient;
import org.pac4j.jwt.config.encryption.SecretEncryptionConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.profile.JwtGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;
import java.util.Optional;

@Controller
public class Application {

    private static final String PROFILES = "profiles";
    private static final String SESSION_ID = "sessionId";

    @Value("${salt}")
    private String salt;

    @Autowired
    private Config config;

    @Autowired
    private JEEContext jeeContext;

    @Autowired
    private ProfileManager profileManager;

    @RequestMapping("/")
    public String root(Map<String, Object> map) throws HttpAction {
        return index(map);
    }

    @RequestMapping("/index.html")
    public String index(Map<String, Object> map) throws HttpAction {
        map.put(PROFILES, profileManager.getAll(true));
        map.put(SESSION_ID, jeeContext.getSessionStore().getOrCreateSessionId(jeeContext));
        return "index";
    }

    @RequestMapping("/oidc/index.html")
    public String oidc(Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/protected/index.html")
    public String protect(Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/rest-jwt/index.html")
    public String restJwt(Map<String, Object> map) {
        return protectedIndex(map);
    }

    @RequestMapping("/jwt.html")
    public String jwt(Map<String, Object> map) {
        final JwtGenerator generator = new JwtGenerator(new SecretSignatureConfiguration(salt), new SecretEncryptionConfiguration(salt));
        String token = "";
        final Optional<CommonProfile> profile = profileManager.get(true);
        if (profile.isPresent()) {
            token = generator.generate(profile.get());
        }
        map.put("token", token);
        return "jwt";
    }

    @RequestMapping("/forceLogin")
    @ResponseBody
    public String forceLogin() {

        final Client client = config.getClients().findClient(jeeContext.getRequestParameter(Pac4jConstants.DEFAULT_CLIENT_NAME_PARAMETER).get()).get();
        HttpAction action;
        try {
            action = (HttpAction) client.getRedirectionAction(jeeContext).get();
        } catch (final HttpAction e) {
            action = e;
        }
        JEEHttpActionAdapter.INSTANCE.adapt(action, jeeContext);
        return null;
    }

    protected String protectedIndex(Map<String, Object> map) {
        map.put(PROFILES, profileManager.getAll(true));
        return "protectedIndex";
    }

    @ExceptionHandler(HttpAction.class)
    public void httpAction(final HttpAction action) {
        JEEHttpActionAdapter.INSTANCE.adapt(action, jeeContext);
    }
}
