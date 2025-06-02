import org.zaproxy.addon.encoder.processors.script.EncodeDecodeScriptHelper
import groovy.transform.Field

@Field final int test =  1

/**
 * Process the input value and return the encoded/decoded/hashed etc. value
 *
 * Use helper.newError("Error Description") to provide an error description
 * inside the result view
 *
 * @param {EncodeDecodeScriptHelper} helper - A helper object with various utility methods.
 *     For more details see https://github.com/zaproxy/zap-extensions/tree/main/addOns/encoder/src/main/java/org/zaproxy/addon/encoder/processors/script/EncodeDecodeScriptHelper.java
 * @param {String} value - The input value.
 * @returns {EncodeDecodeResult} - The value that was encoded/decoded/hashed etc. easiest via helper.newResult(result).
 */
Object process(EncodeDecodeScriptHelper helper, String value){
    return helper.newResult(String.valueOf(test++) + "|" + value)
}
