import org.zaproxy.gradle.addon.AddOnStatus

version = "21.1.0"
description = "Technology detection using Wappalyzer: wappalyzer.com"

zapAddOn {
    addOnName.set("Wappalyzer - Technology Detection")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.10.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/technology-detection/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.wappalyzer.WappalyzerAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/wappalyzer/resources/Messages.properties"))
    }
}

dependencies {
    implementation("com.google.re2j:re2j:1.5")

    val batikVersion = "1.13"
    implementation("org.apache.xmlgraphics:batik-anim:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-bridge:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-ext:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-gvt:$batikVersion")
    implementation("org.apache.xmlgraphics:batik-util:$batikVersion")

    testImplementation(project(":testutils"))
}
