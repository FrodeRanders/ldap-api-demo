package org.example;

/**
 * Exception used when method called with invalid parameter such
 * as a 'null' where a valid object is expected.
 */
public class InvalidParameterException extends Exception {

    public InvalidParameterException() {
    }

    public InvalidParameterException(String msg) {
        super(msg);
    }
}




