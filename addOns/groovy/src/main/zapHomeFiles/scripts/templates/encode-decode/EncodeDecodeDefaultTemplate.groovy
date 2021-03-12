import org.zaproxy.addon.encoder.processors.EncodeDecodeResult
import groovy.transform.Field

@Field final int test =  1

/**
 * Process the input value and return the encoded/decoded/hashed etc. value
 *
 * Use EncodeDecodeResult.withError("Error Description") to provide an error description
 * inside the result view
 *
 * @param {String} value - The input value
 * @returns {EncodeDecodeResult} - The value that was encoded/decoded/hashed etc.
 */
EncodeDecodeResult process(String value){
    return new EncodeDecodeResult(String.valueOf(test++) + "|" + value)
}
