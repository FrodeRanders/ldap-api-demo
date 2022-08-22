package org.example;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


/**
 * Manages a connection to an LDAP directory service and executes
 * queries and updates through it.
 */
public class ApplicationDomain {

    static final Logger log = LoggerFactory.getLogger(ApplicationDomain.class);


    /**
     * Base distinguished name.
     * A typical value is
     * <I>"dc=test"</I>
     */
    // public static final String LDAP_BASE_DN = "LDAP_BASE_DN";

    /**
     * The archives context
     * <p/>
     * A typical value is
     * <I>"ou=Archives,dc=dm"</I>
     */
    public static final String LDAP_ARCHIVES_CONTEXT = "LDAP_ARCHIVES_CONTEXT";

    /**
     * The user (member) context
     * <p/>
     * A typical value is
     * <I>"ou=Members,dc=test"</I>
     */
    public static final String LDAP_USER_CONTEXT = "LDAP_USER_CONTEXT";

    /**
     * The global group context
     * <p/>
     * A typical value is
     * <I>"ou=Groups,dc=test"</I>
     */
    public static final String LDAP_GROUP_CONTEXT = "LDAP_GROUP_CONTEXT";


    /**
     * The archive roles distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=Roles,ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_ROLES_DN_TEMPLATE = "LDAP_ROLES_DN_TEMPLATE";

    /**
     * The user object class.
     * <p/>
     * A typical value is
     * <I>"dsUser"</I>
     */
    public static final String LDAP_USER_OBJECT_CLASS = "LDAP_USER_OBJECT_CLASS";

    /**
     * The archive administration role distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=Administrator,ou=Roles,ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_ADMIN_ROLE_DN_TEMPLATE = "LDAP_ADMIN_ROLE_DN_TEMPLATE";

    /**
     * The archive user role distinguished name template
     * <P>
     * A typical value is
     * <I>"ou=User,ou=Roles,ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_USER_ROLE_DN_TEMPLATE = "LDAP_USER_ROLE_DN_TEMPLATE";

    /**
     * The archive specific role distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=Roles,ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_ROLE_DN_TEMPLATE = "LDAP_ROLE_DN_TEMPLATE";

    /**
     * The global specific group distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=Groups,dc=test"</I>
     */
    public static final String LDAP_GROUP_DN_TEMPLATE = "LDAP_GROUP_DN_TEMPLATE";

    /**
     * The user in archive specific role distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=Roles,ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_USER_IN_ROLE_DN_TEMPLATE = "LDAP_USER_IN_ROLE_DN_TEMPLATE";

    /**
     * The global group in archive specific role distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=%s,ou=Roles,ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_GROUP_IN_ROLE_DN_TEMPLATE = "LDAP_GROUP_IN_ROLE_DN_TEMPLATE";

    /**
     * The user in specific global group distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=Groups,dc=test"</I>
     */
    public static final String LDAP_USER_IN_GROUP_DN_TEMPLATE = "LDAP_USER_IN_GROUP_DN_TEMPLATE";

    /**
     * The archive distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=Archives,dc=test"</I>
     */
    public static final String LDAP_ARCHIVE_DN_TEMPLATE = "LDAP_ARCHIVE_DN_TEMPLATE";

    /**
     * The user distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=Members,dc=test"</I>
     */
    public static final String LDAP_USER_DN_TEMPLATE = "LDAP_USER_DN_TEMPLATE";

    /**
     * The foreign user distinguished name template
     * <p/>
     * A typical value is
     * <I>"cn=%s,ou=%s,ou=ForeignUsers,dc=test"</I>
     */
    public static final String LDAP_FOREIGN_USER_DN_TEMPLATE = "LDAP_FOREIGN_USER_DN_TEMPLATE";

    /**
     * The foreign domain distinguished name template
     * <p/>
     * A typical value is
     * <I>"ou=%s,ou=ForeignUsers,dc=test"</I>
     */
    public static final String LDAP_FOREIGN_DOMAIN_DN_TEMPLATE = "LDAP_FOREIGN_DOMAIN_DN_TEMPLATE";

    /**
     * The user (member) search filter
     * <p/>
     * A typical value is
     * <I>"(cn=*)"</I>
     */
    public static final String LDAP_USER_SEARCH_FILTER = "LDAP_USER_SEARCH_FILTER";

    /**
     * The global group search filter
     * <p/>
     * A typical value is
     * <I>"(ou=*)"</I>
     */
    public static final String LDAP_GROUP_SEARCH_FILTER = "LDAP_GROUP_SEARCH_FILTER";

    /**
     * The archive specific role search filter
     * <p/>
     * A typical value is
     * <I>"(ou=*)"</I>
     */
    public static final String LDAP_ROLE_SEARCH_FILTER = "LDAP_ROLE_SEARCH_FILTER";

    /**
     * The archive search filter
     * <p/>
     * A typical value is
     * <I>"(ou=*)"</I>
     */
    public static final String LDAP_ARCHIVE_SEARCH_FILTER = "LDAP_ARCHIVE_SEARCH_FILTER";

    /**
     * The user (member) id attribute name
     * <p/>
     * A typical value is
     * <I>"uid"</I>
     */
    public static final String LDAP_USER_ID = "LDAP_USER_ID";

    /**
     * The user (member) password attribute name
     * <p/>
     * A typical value is
     * <I>"userPassword"</I>
     */
    public static final String LDAP_USER_PASSWORD = "LDAP_USER_PASSWORD";

    /**
     * The user (member) given name attribute name
     * <p/>
     * A typical value is
     * <I>"givenName"</I>
     */
    public static final String LDAP_USER_FIRST_NAME = "LDAP_USER_FIRST_NAME";

    /**
     * The user (member) surname attribute name
     * <p/>
     * A typical value is
     * <I>"sn"</I>
     */
    public static final String LDAP_USER_LAST_NAME = "LDAP_USER_LAST_NAME";

    /**
     * The user (member) language attribute name
     * <p/>
     * A typical value is
     * <I>"language"</I>
     */
    public static final String LDAP_USER_LANGUAGE = "LDAP_USER_LANGUAGE";

    /**
     * The user (member) authrization level attribute name
     * <p/>
     * A typical value is
     * <I>"authorizationLevel"</I>
     */
    public static final String LDAP_USER_AUTHORIZATION_LEVEL = "LDAP_USER_AUTHORIZATION_LEVEL";

    /**
     * The user (member) detail level attribute name
     * <p/>
     * A typical value is
     * <I>"detailLevel"</I>
     */
    public static final String LDAP_USER_DETAIL_LEVEL = "LDAP_USER_DETAIL_LEVEL";

    /**
     * The user (member) email attribute name
     * <p/>
     * A typical value is
     * <I>"mail"</I>
     */
    public static final String LDAP_USER_MAIL = "LDAP_USER_MAIL";

    /**
     * The global group id attribute name
     * <p/>
     * A typical value is
     * <I>"ou"</I>
     */
    public static final String LDAP_GROUP_ID = "LDAP_GROUP_ID";

    /**
     * The global group description attribute name
     * <p/>
     * A typical value is
     * <I>"description"</I>
     */
    public static final String LDAP_GROUP_DESCRIPTION = "LDAP_GROUP_DESCRIPTION";

    /**
     * The archive name attribute name
     * <p/>
     * A typical value is
     * <I>"ou"</I>
     */
    public static final String LDAP_ARCHIVE_NAME_ATTRIBUTE = "LDAP_ARCHIVE_NAME_ATTRIBUTE";

    /**
     * The name of the Administrator role
     */
    public final static String ADMINISTRATOR_ROLE = "Administrator";

    /**
     * The name of the User role
     */
    public final static String USER_ROLE = "User";

    /**
     * The name of the global administrators group
     */
    public final static String ADMINISTRATORS_GROUP = "Administrators";

    //------------------------------------------------------------------------
    private final static Rdn[] RdnT = {};

    // Archive
    protected final String archiveDNTemplate;
    protected final String archiveSearchFilter;
    protected final String archiveNameAttribute;

    // Object classes
    protected final String userObjectClass;

    // User
    protected final String userDNTemplate;
    protected final String userSearchFilter;

    // Foreign users
    protected final String foreignUserDNTemplate;
    protected final String foreignDomainDNTemplate;

    // User attributes names
    protected final String userIdAttribute;
    protected final String passwordAttribute;
    protected final String firstNameAttribute;
    protected final String lastNameAttribute;


    // Role
    protected final String roleDNTemplate;
    protected final String roleSearchFilter;
    protected final String userInRoleDNTemplate;
    protected final String groupInRoleDNTemplate;

    // Group
    protected final String groupDNTemplate;
    protected final String groupSearchFilter;
    protected final String userInGroupDNTemplate;
    protected final String groupIdAttribute;
    protected final String groupDescriptionAttribute;

    // Roles
    protected final String rolesDNTemplate;

    //
    protected final String usersContext;
    protected final String groupsContext;
    protected final String archivesContext;

    //
    protected final LdapAdapter adapter;

    public ApplicationDomain(Map<String, String> config) throws ConfigurationException {
        this(config, new LdapAdapter(config));
    }
    public ApplicationDomain(Map<String, String> config, LdapAdapter adapter) {
        this.adapter = adapter;

        // === Init application specifics ===

        //--------------------------------------------------------------------------
        // -- Object classes --
        //
        // Examples; "Person", "inetOrgPerson", ...
        //--------------------------------------------------------------------------
        userObjectClass =
                config.getOrDefault(LDAP_USER_OBJECT_CLASS, "inetOrgPerson");

        //--------------------------------------------------------------------------
        // -- User attributes --
        //--------------------------------------------------------------------------
        userIdAttribute =
                config.getOrDefault(LDAP_USER_ID, "uid"); // or cn, sAMAccountName, ...
        passwordAttribute =
                config.getOrDefault(LDAP_USER_PASSWORD, "userPassword");
        firstNameAttribute =
                config.getOrDefault(LDAP_USER_FIRST_NAME, "givenName");
        lastNameAttribute =
                config.getOrDefault(LDAP_USER_LAST_NAME, "sn");

        //--------------------------------------------------------------------------
        // -- Templates for various distinguished names --
        //--------------------------------------------------------------------------
        roleDNTemplate =
                config.getOrDefault(LDAP_ROLE_DN_TEMPLATE, "ou=%s,ou=Roles,ou=%s,ou=Communities,dc=test");
        groupDNTemplate =
                config.getOrDefault(LDAP_GROUP_DN_TEMPLATE, "ou=%s,ou=Groups,dc=test");
        userInRoleDNTemplate =
                config.getOrDefault(LDAP_USER_IN_ROLE_DN_TEMPLATE, "cn=%s,ou=%s,ou=Roles,ou=%s,ou=Archives,dc=test");
        groupInRoleDNTemplate =
                config.getOrDefault(LDAP_GROUP_IN_ROLE_DN_TEMPLATE, "ou=%s,ou=%s,ou=Roles,ou=%s,ou=Archives,dc=test");
        userInGroupDNTemplate =
                config.getOrDefault(LDAP_USER_IN_GROUP_DN_TEMPLATE, "cn=%s,ou=%s,ou=Groups,dc=test");
        archiveDNTemplate =
                config.getOrDefault(LDAP_ARCHIVE_DN_TEMPLATE, "ou=%s,ou=Archives,dc=test");
        rolesDNTemplate =
                config.getOrDefault(LDAP_ROLES_DN_TEMPLATE, "ou=Roles,ou=%s,ou=Archives,dc=test");
        userDNTemplate =
                config.getOrDefault(LDAP_USER_DN_TEMPLATE, "cn=%s,ou=Members,dc=test");
        foreignUserDNTemplate =
                config.getOrDefault(LDAP_FOREIGN_USER_DN_TEMPLATE, "cn=%s,ou=%s,ou=ForeignUsers,dc=test");
        foreignDomainDNTemplate =
                config.getOrDefault(LDAP_FOREIGN_DOMAIN_DN_TEMPLATE, "ou=%s,ou=ForeignUsers,dc=test");

        //--------------------------------------------------------------------------
        // -- Archive attributes --
        //--------------------------------------------------------------------------
        archiveNameAttribute =
                config.getOrDefault(LDAP_ARCHIVE_NAME_ATTRIBUTE, "ou");

        //--------------------------------------------------------------------------
        // -- Global group attributes --
        //--------------------------------------------------------------------------
        groupIdAttribute =
                config.getOrDefault(LDAP_GROUP_ID, "ou");
        groupDescriptionAttribute =
                config.getOrDefault(LDAP_GROUP_DESCRIPTION, "description");

        //--------------------------------------------------------------------------
        // -- Subcontexts and search filters (within subcontexts) --
        //--------------------------------------------------------------------------
        usersContext =
                config.getOrDefault(LDAP_USER_CONTEXT, "ou=Members,dc=test");
        userSearchFilter =
                config.getOrDefault(LDAP_USER_SEARCH_FILTER, "(cn=*)");
        groupsContext =
                config.getOrDefault(LDAP_GROUP_CONTEXT, "ou=Groups,dc=test");
        groupSearchFilter =
                config.getOrDefault(LDAP_GROUP_SEARCH_FILTER, "(ou=*)");
        archivesContext =
                config.getOrDefault(LDAP_ARCHIVES_CONTEXT, "ou=Archives,dc=test");
        archiveSearchFilter =
                config.getOrDefault(LDAP_ARCHIVE_SEARCH_FILTER, "(ou=*)");

        //--------------------------------------------------------------------------
        // -- Search filter for finding roles in a specific archive --
        //--------------------------------------------------------------------------
        roleSearchFilter = config.getOrDefault(LDAP_ROLE_SEARCH_FILTER, "(ou=*)");
    }

    /**
     * Find object by it's distinguished name (regardless of objectClass)
     * <p/>
     * @param dn some distinguished name
     * @return The distinguished name (DN) of the object if user exists in LDAP, null otherwise
     */
    public String findObjectByDn(final String dn) throws ConfigurationException, DirectoryException {
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");

        Entry obj = adapter.findObject(req);
        if (null != obj) {
            // Return the distinguished name of the object
            return obj.getDn().toString();
        }
        return null;
    }

    /**
     * Creates an archive in the directory.
     * <p/>
     * It is the responsibility of the caller to verify that an archive object does not already
     * exist.
     */
    public String createArchive(final String archiveName) throws ConfigurationException, DirectoryException {

        String _archiveDn = LdapAdapter.compose(archiveDNTemplate, archiveName);

        try {
            Dn archiveDn = new Dn(_archiveDn);

            DefaultEntry archiveEntry = new DefaultEntry(archiveDn);
            archiveEntry.add("objectclass", "organizationalUnit");
            archiveEntry.add("ou", archiveName);

            adapter.createObject(archiveEntry);
        }
        catch (LdapInvalidDnException e) {
            String info = "Invalid archive DN: " + _archiveDn;
            throw new ConfigurationException(info);
        }
        catch (LdapException e) {
            String info = "Could not assemble a new entry for archive " + archiveName;
            info += ": " + e.getMessage();
            throw new DirectoryWriteException(info, e);
        }

        return _archiveDn; // If all OK
    }


    /**
     * Assigns a user, identified by an id, to a role.
     */
    public String assignUserToRole(final String userId, final String roleId, final String archiveName) throws InvalidParameterException, ConfigurationException, DirectoryException {

        final String _userDn = LdapAdapter.compose(userDNTemplate, userId);
        if (null == findObjectByDn(_userDn)) {
            String info = "The specified user is unknown to the system: \"" + userId + "\" (" + _userDn + ")";
            throw new InvalidParameterException(info);
        }

        // ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        String _rolesDn = LdapAdapter.compose(rolesDNTemplate, archiveName);
        if (null == findObjectByDn(_rolesDn)) {
            try {
                Dn rolesDn = new Dn(_rolesDn);

                DefaultEntry rolesEntry = new DefaultEntry(rolesDn);
                rolesEntry.add("objectclass", "organizationalUnit");
                rolesEntry.add("ou", "Roles");

                adapter.createObject(rolesEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid roles DN: " + _rolesDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not create roles base entry in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }

        // ou=<roleId>,ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        String _roleDn = LdapAdapter.compose(roleDNTemplate, roleId, archiveName);
        if (null == findObjectByDn(_roleDn)) {
            try {
                Dn roleDn = new Dn(_roleDn);

                DefaultEntry roleEntry = new DefaultEntry(roleDn);
                roleEntry.add("objectclass", "organizationalUnit");
                roleEntry.add(groupIdAttribute, roleId);

                adapter.createObject(roleEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role DN: " + _roleDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new entry for role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }

        // cn=<userId>,ou=<roleId>,ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        final String _participationDn = LdapAdapter.compose(userInRoleDNTemplate, userId, roleId, archiveName);
        if (null == findObjectByDn(_participationDn)) {
            try {
                Dn participationDn = new Dn(_participationDn);

                DefaultEntry participationEntry = new DefaultEntry(participationDn);
                participationEntry.add("objectclass", "dsGroupMember");
                participationEntry.add("cn", userId);
                participationEntry.add("memberObject", _userDn);

                adapter.createObject(participationEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role participation DN: " + _participationDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new participation entry for user " + userId + " in role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }
        return _participationDn; // If all OK
    }

    /**
     * Assigns a group, identified by an id, to a role.
     */
    public String assignGroupToRole(final String groupId, final String roleId, final String archiveName) throws InvalidParameterException, ConfigurationException, DirectoryException {

        final String _groupDn = LdapAdapter.compose(groupDNTemplate, groupId);
        if (null == findObjectByDn(_groupDn)) {
            String info = "The specified global group is unknown to the system: \"" + groupId + "\" (" + _groupDn + ")";
            throw new InvalidParameterException(info);
        }

        // ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        String _rolesDn = LdapAdapter.compose(rolesDNTemplate, archiveName);
        if (null == findObjectByDn(_rolesDn)) {
            try {
                Dn rolesDn = new Dn(_rolesDn);

                DefaultEntry rolesEntry = new DefaultEntry(rolesDn);
                rolesEntry.add("objectclass", "organizationalUnit");
                rolesEntry.add("ou", "Roles");

                adapter.createObject(rolesEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid roles DN: " + _rolesDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not create roles base entry in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
            catch (DirectoryWriteException e) {
                String info = "Could not create roles base entry in archive " + archiveName;
                info += ": " + e.getMessage();
                throw e;
            }
        }

        // ou=<roleId>,ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        String _roleDn = LdapAdapter.compose(roleDNTemplate, roleId, archiveName);
        if (null == findObjectByDn(_roleDn)) {
            try {
                Dn roleDn = new Dn(_roleDn);

                DefaultEntry roleEntry = new DefaultEntry(roleDn);
                roleEntry.add("objectclass", "organizationalUnit");
                roleEntry.add(groupIdAttribute, roleId);

                adapter.createObject(roleEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role DN: " + _roleDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new entry for role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
            catch (DirectoryWriteException e) {
                String info = "Could not assemble a new entry for role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw e;
            }
        }

        // cn=<groupId>,ou=<roleId>,ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        final String _groupParticipationDn = LdapAdapter.compose(groupInRoleDNTemplate, groupId, roleId, archiveName);
        if (null == findObjectByDn(_groupParticipationDn)) {
            try {
                Dn participationDn = new Dn(_groupParticipationDn);

                DefaultEntry participationEntry = new DefaultEntry(participationDn);
                participationEntry.add("objectclass", "dsGroupMember");
                participationEntry.add("memberObject", _groupDn); // group (DN) participates in role
                participationEntry.add("cn", groupId);

                adapter.createObject(participationEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role participation DN: " + _groupParticipationDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new participation entry for group " + groupId + " in role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
            catch (DirectoryWriteException e) {
                String info = "Could not assemble a new participation entry for group " + groupId + " in role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw e;
            }
        }

        // TODO Check
        // cn=<userId>,ou=<roleId>,ou=Roles,ou=<archiveName>,ou=Archives,dc=test
        final String _roleParticipationDn = LdapAdapter.compose(userInRoleDNTemplate, groupId, roleId, archiveName);
        if (null == findObjectByDn(_roleParticipationDn)) {
            try {
                Dn participationDn = new Dn(_roleParticipationDn);

                DefaultEntry participationEntry = new DefaultEntry(participationDn);
                participationEntry.add("objectclass", "dsGroupMember");
                participationEntry.add("cn", groupId);
                participationEntry.add("memberObject", _groupDn); // group (DN) participates in role

                adapter.createObject(participationEntry);
            }
            catch (LdapInvalidDnException e) {
                String info = "Invalid role participation DN: " + _roleParticipationDn;
                throw new ConfigurationException(info);
            }
            catch (LdapException e) {
                String info = "Could not assemble a new participation entry for group " + groupId + " in role " + roleId + " in archive " + archiveName;
                info += ": " + e.getMessage();
                throw new DirectoryWriteException(info, e);
            }
        }
        return _roleParticipationDn; // If all OK
    }


    /**
     * Does the named user exist in the directory?
     * <p/>
     * @param userId user ID (value associated with the 'cn' or 'uid' attributes)
     * @return The distinguished name (DN) of the user if user exists in LDAP, null otherwise
     */
    public String findUserDn(final String userId) throws ConfigurationException, DirectoryException {
        final String filter = LdapAdapter.compose("(&(objectClass=%s)(%s=%s))", userObjectClass, userIdAttribute, userId);
        SearchRequest req = adapter.shallowSearchWithFilter(usersContext, filter, userIdAttribute);

        Entry user = adapter.findObject(req);
        if (null != user) {
            // Return the distinguished name of the user
            return user.getDn().toString();
        }
        return null;
    }

    /**
     * Checks whether the named global group exists or not.
     * <p/>
     * @param groupName
     * @return
     * @throws ConfigurationException
     * @throws DirectoryException
     */
    public boolean globalGroupExists(final String groupName) throws ConfigurationException, DirectoryException {
        String dn = LdapAdapter.compose(groupDNTemplate, groupName);
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");

        Entry group = adapter.findObject(req);
        return null != group;
    }

    /**
     * Checks whether the named archive exists or not.
     * <p/>
     * @param archiveName
     * @return
     * @throws ConfigurationException
     * @throws DirectoryException
     */
    public boolean archiveExists(final String archiveName) throws ConfigurationException, DirectoryException {
        String dn = LdapAdapter.compose(archiveDNTemplate, archiveName);
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");

        Entry archive = adapter.findObject(req);
        return null != archive;
    }

    /**
     * Checks if a named user is member of a named (global) group.
     * <p/>
     * @param userId
     * @param groupName
     * @return
     * @throws ConfigurationException
     * @throws DirectoryException
     */
    public boolean isMemberOfGlobalGroup(final String userId, final String groupName) throws ConfigurationException, DirectoryException {

        //------------------------------------------------------------------------
        // Global groups live under "ou=Groups, dc=test".
        // Strategy: Compose a DN for a user dsGroupMember and try to locate it.
        //------------------------------------------------------------------------
        String dn;
        if (groupName.startsWith("ou=")) {
            // Backwards compatibility: Whole ou= stored in ACL in database
            dn = LdapAdapter.compose("cn=%s, %s", userId, groupName);
        } else {
            // "cn=<userName>,ou=<groupName>,ou=Groups,dc=test"
            dn = LdapAdapter.compose(userInGroupDNTemplate, userId, groupName);
        }
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.searchForDn(dn, filter, "*");
        Entry user = adapter.findObject(req);
        return null != user;
    }




    public Collection<String> getUsersInGlobalGroup(final String groupName) throws ConfigurationException, DirectoryException {
        Collection<String> users = new LinkedList<>();

        //------------------------------------------------------------------------
        // Global groups live under "ou=Groups, dc=test".
        // Strategy: Get all entries directly thereunder
        //------------------------------------------------------------------------

        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(groupsContext, filter, "*");
        Collection<Entry> _users = adapter.findObjects(req);
        for (Entry user : _users) {
            try {
                Attribute a = user.get("cn");
                if (null != a) {
                    String cn = a.getString();
                    users.add(cn); // userId
                }

                a = user.get("memberObject");
                if (null != a) {
                    String memberObject = a.getString();
                    // users.add(memberObject); // userDN
                }
            }
            catch (LdapInvalidAttributeValueException e) {
                String info = "User in group entry attribute has unexpected type: " + e.getMessage();
                throw new DirectoryReadException(info, e);
            }
        }
        return users;
    }

    public Collection<String> getUsersInRole(final String roleName, final String archiveName) throws ConfigurationException, DirectoryException {
        Collection<String> users = new LinkedList<>();

        //------------------------------------------------------------------------
        // Roles live under "ou=<roleName>, ou=Roles, ou=<archiveName>, ou=Archive, dc=test"
        // Strategy: Get all entries directly thereunder.
        // BEWARE: There may be groups entries there as well!
        //------------------------------------------------------------------------

        String dn = LdapAdapter.compose(roleDNTemplate, roleName, archiveName);
        final String filter = "(objectClass=dsGroupMember)";
        SearchRequest req = adapter.shallowSearchWithFilter(dn, filter, "*");
        Collection<Entry> _users = adapter.findObjects(req);
        for (Entry user : _users) {
            try {
                Attribute a = user.get("cn");
                if (null != a) {
                    String cn = a.getString();
                    users.add(cn); // userId
                }

                a = user.get("memberObject");
                if (null != a) {
                    String memberObject = a.getString();
                    // users.add(memberObject); // userDN
                }
            }
            catch (LdapInvalidAttributeValueException e) {
                String info = "User in role entry attribute has unexpected type: " + e.getMessage();
                throw new DirectoryReadException(info, e);
            }
        }
        return users;
    }


    /**
     * Returns the groupIds in the searched LDAP context
     */
    public Collection<String> getGlobalGroups() throws ConfigurationException, DirectoryException {
        Collection<String> groups = new LinkedList<>();

        //------------------------------------------------------------------------
        // Global groups live under "ou=Groups, dc=test".
        // Strategy: Get all entries directly thereunder
        //------------------------------------------------------------------------

        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(groupsContext, filter, "*");
        Collection<Entry> _groups = adapter.findObjects(req);
        for (Entry group : _groups) {
            String dn = group.getDn().toString();

            try {
                Attribute a = group.get("ou");
                if (null != a) {
                    String cn = a.getString();
                    groups.add(cn); // groupId
                }
            }
            catch (LdapInvalidAttributeValueException e) {
                String info = "Group in group entry attribute has unexpected type: " + e.getMessage();
                throw new DirectoryReadException(info, e);
            }
        }
        return groups;
    }

    public Collection<String> getArchives() throws ConfigurationException, DirectoryException {
        Collection<String> archives = new LinkedList<>();

        //------------------------------------------------------------------------
        // Archives live under "ou=Archives, dc=test".
        // Strategy: Get all entries under "ou=Archives, dc=test"
        //------------------------------------------------------------------------
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(archivesContext, filter, "*");
        Collection<Entry> _archives = adapter.findObjects(req);
        for (Entry archive : _archives) {
            archives.add(adapter.getSimpleName(archive.getDn()));
        }

        return archives;
    }

    /**
     * Returns the groupids in the searched LDAP context
     *
     * @return Vector a Vector of roles
     */
    public Collection<String> getRolesInArchive(final String archiveName) throws ConfigurationException, DirectoryException{
        Collection<String> roles = new LinkedList<>();

        //------------------------------------------------------------------------
        // Roles of an archives live under "ou=Roles, ou=<archiveName>, ou=Archives, dc=test".
        // Strategy: Get all entries directly thereunder
        //------------------------------------------------------------------------
        final String base = LdapAdapter.compose(rolesDNTemplate, archiveName);
        final String filter = "(objectClass=*)";
        SearchRequest req = adapter.shallowSearchWithFilter(base, filter, "*");
        Collection<Entry> _roles = adapter.findObjects(req);
        for (Entry role : _roles) {
            roles.add(adapter.getSimpleName(role.getDn()));
        }

        return roles;
    }


    /*
     *
     */
    private void groupsAndRolesAnalysis(
            final String userId,
            final String userDn,
            final HashSet<String> globalGroups,
            Hashtable<String, HashSet<String>> roles
    ) throws ConfigurationException, DirectoryException {

        /* --------------------------------------------------------------------------------
         * Determine list of global group memberships
         *
         * Membership is determined by a having a dsGroupMember object under the
         * global group with memberObject = user DN.
         *
         * The result is a list of "simple" group names (and not DNs to these groups)
         * -------------------------------------------------------------------------------*/
        log.trace("Analyzing global group memberships of user \"{}\" ({})", userId, userDn);

        final String filter = LdapAdapter.compose("(&(objectClass=dsGroupMember)(memberObject=%s))", userDn);
        SearchRequest req = adapter.deepSearchWithFilter(groupsContext, filter, "*");
        Collection<Entry> memberships = adapter.findObjects(req);

        for (Entry membership : memberships) {
            // From: cn=<userId>, ou=<groupName>, ou=Groups, dc=test
            // To:  {cn=<userId>, ou=<groupName>, ou=Groups, dc=test}
            Rdn[] membershipRdns = membership.getDn().getRdns().toArray(RdnT);

            //
            Rdn groupRdn = membershipRdns[1];
            Value _groupName = groupRdn.getAva().getValue();
            String groupName = _groupName.getString();

            globalGroups.add(groupName);

            log.trace("User \"{}\" ({}) is a member of the global group \"{}\"", userId, userDn, groupName);
        }

        /* --------------------------------------------------------------------------------
         * Determine list of direct role participations for user
         *
         * Direct participation is determined by a having a dsGroupMember object under the
         * global group with memberObject = user DN.
         *
         * The result is a hashtable (hashed on archive name) with lists of "simple"
         * role names (and not DNs to these roles).
         * -------------------------------------------------------------------------------*/
        log.trace("Analyzing direct role participation of user \"{}\" ({})", userId, userDn);

        req = adapter.deepSearchWithFilter(archivesContext, filter, "*");
        Collection<Entry> participations = adapter.findObjects(req);

        for (Entry participation : participations) {
            // From: cn=<userId>, ou=<roleName>, ou=Roles, ou=<archiveName>, ou=Archives, dc=test
            // To:  {cn=<userId>, ou=<roleName>, ou=Roles, ou=<archiveName>, ou=Archives, dc=test}
            Rdn[] participationRdns = participation.getDn().getRdns().toArray(RdnT);

            //
            Rdn roleRdn = participationRdns[1];
            Value _roleName = roleRdn.getAva().getValue();
            String roleName = _roleName.getString();

            //
            Rdn archiveRdn = participationRdns[3];
            Value _archiveName = archiveRdn.getAva().getValue();
            String archiveName = _archiveName.getString();

            //
            HashSet<String> _roles = roles.computeIfAbsent(archiveName, k -> new HashSet<>());
            _roles.add(roleName);

            log.trace("User \"{}\" ({}) participates directly in role \"{}\" in archive \"{}\"", userId, userDn, roleName, archiveName);
        }

        /* --------------------------------------------------------------------------------
         * Determine list of indirect role participations for groups that user is part of
         *
         * Indirect participation is determined by a having a dsGroupMember object under the
         * global group with memberObject = group DN (and not the user DN). Since we don't
         * have stored the group DN (from above) we will recreate these using groupDNTemplate.
         *
         * The result is a hashtable (hashed on archive name) with lists of "simple"
         * role names (and not DNs to these roles).
         * -------------------------------------------------------------------------------*/
        log.trace("Analyzing indirect role participation user \"{}\" ({})", userId, userDn);

        int numberOfGroups = globalGroups.size();
        if (numberOfGroups > 0) {

            StringBuilder groupFilter = new StringBuilder("(&(objectClass=dsGroupMember)");
            if (numberOfGroups > 1) {
                groupFilter.append("(|");
            }
            for (String groupId : globalGroups) {
                log.trace("Looking for group membership \"{}\" in roles", groupId);
                String groupDn = LdapAdapter.compose(groupDNTemplate, groupId);
                groupFilter.append("(memberObject=").append(groupDn).append(")");
            }
            if (numberOfGroups > 1) {
                groupFilter.append(")");
            }
            groupFilter.append(")");

            log.trace("Searching from \"{}\" using filter {}", archivesContext, groupFilter);

            req = adapter.deepSearchWithFilter(archivesContext, groupFilter.toString(), "*");
            participations = adapter.findObjects(req);

            for (Entry participation : participations) {
                // From: cn=<groupId>, ou=<roleName>, ou=Roles, ou=<archiveName>, ou=Archives, dc=test
                // To:  {cn=<groupId>, ou=<roleName>, ou=Roles, ou=<archiveName>, ou=Archives, dc=test}
                Rdn[] participationRdns = participation.getDn().getRdns().toArray(RdnT);

                //
                Rdn roleRdn = participationRdns[1];
                Value _roleName = roleRdn.getAva().getValue();
                String roleName = _roleName.getString();

                //
                Rdn archiveRdn = participationRdns[3];
                Value _archiveName = archiveRdn.getAva().getValue();
                String archiveName = _archiveName.getString();

                //
                HashSet<String> _roles = roles.computeIfAbsent(archiveName, k -> new HashSet<>());
                _roles.add(roleName);

                log.trace("User \"{}\" ({}) participates indirectly in role \"{}\" in archive \"{}\" through a group membership", userId, userDn, roleName, archiveName);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("Analysis ready");
        }
    }
}

