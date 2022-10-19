import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core networking capabilities."

val bouncyCastle by configurations.creating
configurations.api { extendsFrom(bouncyCastle) }

zapAddOn {
    addOnName.set("Network")
    addOnStatus.set(AddOnStatus.BETA)
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

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(8))
    }
    sourceCompatibility = null
    targetCompatibility = null
}

crowdin {
    configuration {
        tokens.put("%messagesPath%", "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/")
        tokens.put("%helpPath%", "")
    }
}

spotless {
    java {
        target(
            fileTree(projectDir) {
                include("src/**/*.java")
                exclude("src/main/java/org/apache/hc/client5/**/Zap*.java")
            }
        )
    }
}

dependencies {
    val nettyVersion = "4.1.81.Final"
    implementation("io.netty:netty-codec:$nettyVersion")
    implementation("io.netty:netty-handler:$nettyVersion")

    implementation("org.apache.httpcomponents.client5:httpclient5:5.2-beta1")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.17.2") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    val bcVersion = "1.70"
    bouncyCastle("org.bouncycastle:bcmail-jdk15on:$bcVersion")
    bouncyCastle("org.bouncycastle:bcprov-jdk15on:$bcVersion")
    bouncyCastle("org.bouncycastle:bcpkix-jdk15on:$bcVersion")

    implementation("org.jitsi:ice4j:3.0-24-g34c2ce5") {
        // Don't need its dependencies, for now.
        setTransitive(false)
    }

    testImplementation(project(":testutils"))
    testImplementation("org.apache.logging.log4j:log4j-core:2.17.2")
}
