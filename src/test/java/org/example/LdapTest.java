package org.example;


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.message.SearchRequest;
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


    public void testFindingUserUsingAdapterDirectly() {
        Map<String, String> adapterConfig = Map.of(
                // Where to locate directory service
                LdapAdapter.LDAP_HOST, "localhost",
                LdapAdapter.LDAP_PORT, "10389", // See line 137 in LocalLdapServer.java
                //
                // How to bind to directory service in order to search for users, etc.
                LdapAdapter.LDAP_READER_DN, "uid=Searcher,dc=test",
                LdapAdapter.LDAP_READER_CREDENTIALS, "notsosecret" // See line 97 in LocalLdapServer.java
        );

        try (LdapAdapter adapter = new LdapAdapter(adapterConfig)) {

            String userId = "tester"; // See line 122 in LocalLdapServer.java

            System.out.println("Looking for user with id = " + userId);
            System.out.println("  by means of LdapAdapter::findObject()");

            //------------------------------------------------------------------------
            // Search expression:         (&(objectClass=inetOrgPerson)(uid=tester))
            // Starting point in tree:    ou=Members,dc=test
            //------------------------------------------------------------------------
            final String filter = LdapAdapter.compose("(&(objectClass=%s)(%s=%s))", "inetOrgPerson", "uid", userId);
            SearchRequest req = adapter.shallowSearchWithFilter("ou=Members,dc=test", filter, "uid");

            Entry user = adapter.findObject(req);
            if (null == user) {
                fail("Could not locate user");
            }

            String userDn = user.getDn().toString();
            System.out.println("Found " + userId + " to be " + userDn + " (a distinguished name)");
        }
        catch (ConfigurationException | DirectoryException e) {
            fail(e.getMessage());
        }
    }


    public void testFindingUserUsingAdditionalEncapsulation() {
        Map<String, String> adapterConfig = Map.of(
                // Where to locate directory service
                LdapAdapter.LDAP_HOST, "localhost",
                LdapAdapter.LDAP_PORT, "10389", // See line 137 in LocalLdapServer.java
                //
                // How to bind to directory service in order to search for users, etc.
                LdapAdapter.LDAP_READER_DN, "uid=Searcher,dc=test",
                LdapAdapter.LDAP_READER_CREDENTIALS, "notsosecret" // See line 97 in LocalLdapServer.java
        );


        try (LdapAdapter adapter = new LdapAdapter(adapterConfig)) {

            Map<String, String> templates = new HashMap<>();
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
