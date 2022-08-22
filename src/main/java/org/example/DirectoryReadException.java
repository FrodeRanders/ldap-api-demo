package org.example;

/**
 * Exception used when problems occur when reading from an LDAP directory.
 */
public class DirectoryReadException extends DirectoryException {
    public DirectoryReadException(String msg, Throwable t) {
        super(msg, t);
    }
}




