package org.example;

/**
 * Exception used when problems occur with the LDAP directory.
 * <p/>
 * You must choose one of {@link org.example.DirectoryReadException} or
 * {@link org.example.DirectoryWriteException} when throwing an exception.
 */
public abstract class DirectoryException extends Exception {

    public DirectoryException(String msg) {
        super(msg);
    }

    public DirectoryException(String msg, Throwable t) {
        super(msg, t);
    }
}




