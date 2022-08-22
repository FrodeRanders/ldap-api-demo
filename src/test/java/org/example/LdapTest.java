package org.example;


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;

public class LdapTest extends TestCase {
    private static Logger log = LogManager.getLogger(LdapTest.class);

    private static LocalLdapServer server = null;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        try {
            System.out.println();
            server = new LocalLdapServer();
            server.start();

        }
        catch (Exception e) {
            String info = "Failed to initiate: " + e.getMessage();
            System.out.println(info);
            log.warn(info, e);
        }
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        if (null != server)
            server.stop();
    }

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public LdapTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite(){
        return new TestSuite(LdapTest.class);
    }


    public void testFindingUser() {
        Map<String, String> adapterConfig = new HashMap<>();

        // Where to locate directory service
        adapterConfig.put(LdapAdapter.LDAP_HOST, "localhost");
        adapterConfig.put(LdapAdapter.LDAP_PORT, "10389"); // See line 137 in LocalLdapServer.java

        // How to bind to directory service in order to search for users, etc.
        adapterConfig.put(LdapAdapter.LDAP_READER_DN, "uid=Searcher,dc=test");
        adapterConfig.put(LdapAdapter.LDAP_READER_CREDENTIALS, "notsosecret"); // See line 97 in LocalLdapServer.java

        Map<String, String> templates = new HashMap<>();

        try (LdapAdapter adapter = new LdapAdapter(adapterConfig)) {

            ApplicationDomain appDomain = new ApplicationDomain(templates, adapter);

            String userId = "tester"; // See line 122 in LocalLdapServer.java
            System.out.println("Looking for user with id = " + userId);
            System.out.println("  by means of ApplicationDomain::findUserDn()");
            System.out.println("  using the (configurable) parameters");
            System.out.println("    userObjectClass = " + appDomain.userObjectClass);
            System.out.println("    userIdAttribute = " + appDomain.userIdAttribute);
            System.out.println("    usersContext = " + appDomain.usersContext);


            String userDn = appDomain.findUserDn(userId);
            System.out.println("Found " + userId + " to be " + userDn + " (a distinguished name)");
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }
}
