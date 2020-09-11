import org.apache.commons.httpclient.URI
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials

val PARAM_TARGET_URL = "targetUrl"

fun authenticate(
        helper: AuthenticationHelper,
        paramsValues: Map<String, String>,
        credentials: GenericAuthenticationCredentials): HttpMessage {

    println("Kotlin auth template")

    println("TARGET_URL: ${paramsValues[PARAM_TARGET_URL]}")
    val msg = helper.prepareMessage()
    msg.requestHeader = HttpRequestHeader(HttpRequestHeader.GET, URI(paramsValues[PARAM_TARGET_URL], true),
            HttpHeader.HTTP11)
    println("msg: $msg ${msg.requestHeader.headers.size}")
    msg.requestHeader.headers.forEach { println(it) }
    helper.sendAndReceive(msg)
    return msg
}

fun getRequiredParamsNames(): Array<String> {
    return arrayOf(PARAM_TARGET_URL)
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}

fun getCredentialsParamsNames(): Array<String> {
    return arrayOf("username", "password")
}

fun getLoggedInIndicator(): String {
    return "Sign Out"
}

fun getLoggedOutIndicator(): String {
    return "Sign In"
}