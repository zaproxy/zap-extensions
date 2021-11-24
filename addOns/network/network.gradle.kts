import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core networking capabilities."

zapAddOn {
    addOnName.set("Network")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.11.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/network/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.network.NetworkApi")
        messages.set(file("src/main/resources/org/zaproxy/addon/network/resources/Messages.properties"))
    }
}

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/")
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    zap("org.zaproxy:zap:2.11.0")

    val nettyVersion = "4.1.70.Final"
    implementation("io.netty:netty-codec:$nettyVersion")

    testImplementation(project(":testutils"))
}
