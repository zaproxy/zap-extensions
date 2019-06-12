version = "4"
description = "Imports and scans WSDL files containing SOAP endpoints."

zapAddOn {
    addOnName.set("SOAP Scanner")
    zapVersion.set("2.8.0")

    manifest {
        author.set("Alberto (albertov91) + ZAP Core team")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.soap.SoapAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/soap/resources/Messages.properties"))
    }
}

dependencies {
    implementation("com.predic8:soa-model-core:1.6.0")
    implementation("com.sun.xml.ws:jaxws-rt:2.3.2")

    testImplementation(project(":testutils"))
}
