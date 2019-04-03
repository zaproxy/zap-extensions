import groovy.transform.Field

// Auxiliary variables/constants for payload generation.
@Field static final long NUMBER_OF_PAYLOADS = 10
@Field static final long INITIAL_VALUE = 1
@Field long count = INITIAL_VALUE

/**
 * Returns the number of generated payloads, zero to indicate unknown number.
 * The number is used as a hint for progress calculations.
 *
 * @return {number} The number of generated payloads.
 */
long getNumberOfPayloads() {
    return NUMBER_OF_PAYLOADS
}

/**
 * Returns true if there are still payloads to generate, false otherwise.
 *
 * Called before each call to next().
 *
 * @return {boolean} If there are still payloads to generate.
 */
boolean hasNext() {
    return count <= NUMBER_OF_PAYLOADS
}

/**
 * Returns the next generated payload.
 *
 * This method is called while hasNext() returns true.
 *
 * @return {string} The next generated payload.
 */
String next() {
    def payload = count.toString()
    count++
    return payload
}

/**
 * Resets the internal state of the payload generator, as if no calls to
 * hasNext() or next() have been previously made.
 *
 * Normally called once the method hasNext() returns false and while payloads
 * are still needed.
 */
void reset() {
    count = INITIAL_VALUE
}

/**
 * Releases any resources used for generation of payloads (for example, a file).
 *
 * Called once the payload generator is no longer needed.
 */
void close() {
}
