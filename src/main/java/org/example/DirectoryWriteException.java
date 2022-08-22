package org.example;

/**
 * Exception used when problems occur when writing to database.
 */
public class DirectoryWriteException extends DirectoryException {

    public DirectoryWriteException(String msg, Throwable t) {
        super(msg, t);
    }
}
