package org.example;

/**
 * Exception used when problems occur when connecting to an LDAP directory service
 * or disconnecting from an LDAP directory service.
 */
public class DirectoryConnectionException extends DirectoryException {

    public DirectoryConnectionException(String msg) {
        super(msg);
    }

    public DirectoryConnectionException(String msg, Throwable t) {
        super(msg, t);
    }
}




