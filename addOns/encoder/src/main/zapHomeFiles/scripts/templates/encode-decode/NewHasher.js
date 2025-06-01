var Hasher = Java.type("org.zaproxy.addon.encoder.processors.predefined.HashProcessor");

/**
 * Process the input value and return the encoded/decoded/hashed etc. value
 *
 * Use helper.newError("Error Description") to provide an error description
 * inside the result view.
 * 
 * The Hasher accepts MessageDigest algorithms as defined via:
 *     https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#messagedigest-algorithms
 *
 * @param {EncodeDecodeScriptHelper} helper - A helper object with various utility methods.
 *     For more details see https://github.com/zaproxy/zap-extensions/tree/main/addOns/encoder/src/main/java/org/zaproxy/addon/encoder/processors/script/EncodeDecodeScriptHelper.java
 * @param {String} value - The input value
 * @returns {EncodeDecodeResult} - The value that was encoded/decoded/hashed etc. easiest via helper.newResult(result).
 */
function process(helper, value){
	var output = new Hasher("sha3-256").process(value).getResult();
	return helper.newResult(output);
}
