version = "4"
description = "Imports and scans WSDL files containing SOAP endpoints."

zapAddOn {
    addOnName.set("SOAP Scanner")
    zapVersion.set("2.9.0")

    manifest {
        author.set("Alberto (albertov91) + ZAP Dev Team")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.soap.SoapAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/soap/resources/Messages.properties"))
    }
}

dependencies {
    implementation("com.predic8:soa-model-core:1.6.0")
    implementation("jakarta.xml.soap:jakarta.xml.soap-api:1.4.2")
    implementation("com.sun.xml.messaging.saaj:saaj-impl:1.5.2")

    testImplementation(project(":testutils"))
}
