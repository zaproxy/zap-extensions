import org.zaproxy.zap.ZAP

fun f(): Class<ZAP> {
    return ZAP::class.java
}
f()