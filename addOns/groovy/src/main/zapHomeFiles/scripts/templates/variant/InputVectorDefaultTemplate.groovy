import groovy.transform.Field
import org.apache.commons.lang.StringUtils
import org.parosproxy.paros.core.scanner.VariantCustom
import org.parosproxy.paros.network.HttpMessage

import java.nio.charset.StandardCharsets

/*
A script that provides custom input vectors that can be used during active
scans.
The option Enable Script Input Vectors must be enabled before starting the
scans.
Note that new scripts will initially be disabled, right click the script in the
Scripts tree and select Enable Script.
*/

@Field final String CUSTOM_HEADER = 'My-Custom-Header'

/*
Parses/extracts the parameters from the HTTP message (request), to be
later tested by the scanners.
Args:
    helper (VariantCustom): Helper class that provides functions to add new
                            parameters and process its values.
    msg (HttpMessage):      The HTTP message (request) that will be scanned.
*/
void parseParameters(VariantCustom helper, HttpMessage msg){

    //Extract the attributes of a custom header...
    def header = msg.getRequestHeader().getHeader(CUSTOM_HEADER)
    if (header == null){
        return
    }

    def attributes = header.split(';')
    for (def attribute : attributes){
        if(StringUtils.isEmpty(attribute)){
            continue
        }

        def data = attribute.split('=')
        if(data.length != 2){
            continue
        }

        def name = data[0]
        def value = URLDecoder.decode(data[1], StandardCharsets.ISO_8859_1.name())
        helper.addParamHeader(name, value)
    }
}

/*
Sets the new value (attack) of a parameter, called by the scanners
during the active scan.

Args:
    helper (VariantCustom): Helper class that provides functions to get the
                            parameters and process its values.
    msg (HttpMessage):      The HTTP message where the value should be injected.
    param (String):         The name of the current parameter, that should contain the payload.
    value (String):         The value of the payload to inject.
    escaped (bool):         True if the value is already escaped, False otherwise.
 */
void setParameter(VariantCustom helper, HttpMessage msg, String param, String value, boolean escaped) {
    // Rebuild the header with the attack value...
    def header = ""
    for(def parameter : helper.getParamList()){
        header += parameter.getName() + '='
        if (parameter.getName() == param){
            header += escaped ? value : URLEncoder.encode(value, StandardCharsets.ISO_8859_1.name())
        }else{
            header += parameter.getValue()
        }
        header += '; '
    }

    msg.getRequestHeader().setHeader(CUSTOM_HEADER, header)
}
