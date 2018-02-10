Payload Generator scripts
=========================

Scripts that can generate payloads to be used in fuzzer.

## JavaScript template

```JavaScript
// Auxiliary variables/constants for payload generation.
var NUMBER_OF_PAYLOADS = 10;
var INITIAL_VALUE = 1;
var count = INITIAL_VALUE;

/**
 * Returns the number of generated payloads, zero to indicate unknown number.
 * The number is used as a hint for progress calculations.
 * 
 * @return {number} The number of generated payloads.
 */
function getNumberOfPayloads() {
    return NUMBER_OF_PAYLOADS;
}

/**
 * Returns true if there are still payloads to generate, false otherwise.
 * 
 * Called before each call to next().
 * 
 * @return {boolean} If there are still payloads to generate.
 */
function hasNext() {
    return (count <= NUMBER_OF_PAYLOADS);
}

/**
 * Returns the next generated payload.
 * 
 * This method is called while hasNext() returns true.
 * 
 * @return {string} The next generated payload.
 */
function next() {
    payload = count;
    count++;
    return payload;
}

/**
 * Resets the internal state of the payload generator, as if no calls to
 * hasNext() or next() have been previously made.
 * 
 * Normally called once the method hasNext() returns false and while payloads
 * are still needed.
 */
function reset() {
    count = INITIAL_VALUE;
}

/**
 * Releases any resources used for generation of payloads (for example, a file).
 * 
 * Called once the payload generator is no longer needed.
 */
function close() {
}
```

## Useful Links
* [String](https://docs.oracle.com/javase/7/docs/api/java/lang/String.html)

