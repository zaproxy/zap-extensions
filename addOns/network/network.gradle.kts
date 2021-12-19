import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core networking capabilities."

val bouncyCastle by configurations.creating
configurations.api { extendsFrom(bouncyCastle) }

zapAddOn {
    addOnName.set("Network")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/network/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(bouncyCastle)
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
    val nettyVersion = "4.1.70.Final"
    implementation("io.netty:netty-codec:$nettyVersion")

    val bcVersion = "1.69"
    bouncyCastle("org.bouncycastle:bcmail-jdk15on:$bcVersion")
    bouncyCastle("org.bouncycastle:bcprov-jdk15on:$bcVersion")
    bouncyCastle("org.bouncycastle:bcpkix-jdk15on:$bcVersion")

    testImplementation(project(":testutils"))
    testImplementation("org.apache.logging.log4j:log4j-core:2.17.0")
}
