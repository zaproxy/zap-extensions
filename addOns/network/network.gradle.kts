import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides core networking capabilities."

val bouncyCastle by configurations.creating
configurations.api { extendsFrom(bouncyCastle) }

val brotli by configurations.creating
val hc by configurations.creating
configurations.implementation {
    extendsFrom(brotli)
    extendsFrom(hc)
}

zapAddOn {
    addOnName.set("Network")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/network/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(bouncyCastle)
            libs.from(brotli)
            libs.from(hc)
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

spotless {
    java {
        target(
            fileTree(projectDir) {
                include("src/**/*.java")
                exclude("src/main/java/org/apache/hc/client5/**/Zap*.java")
                exclude("src/main/java/org/apache/hc/client5/**/cookie/*.java")
                exclude("src/main/java/org/apache/hc/core5/**/*.java")
                exclude("src/main/java/org/zaproxy/addon/network/internal/codec/netty/*.java")
            },
        )
    }
}

dependencies {
    val nettyVersion = "4.1.100.Final"
    implementation("io.netty:netty-codec:$nettyVersion")
    implementation("io.netty:netty-handler:$nettyVersion")
    implementation("io.netty:netty-codec-http2:$nettyVersion")

    hc("org.apache.httpcomponents.client5:httpclient5:5.2.1")
    implementation(libs.log4j.slf4j) {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    val bcVersion = "1.77"
    val bcJava = "jdk18on"
    bouncyCastle("org.bouncycastle:bcmail-$bcJava:$bcVersion")
    bouncyCastle("org.bouncycastle:bcprov-$bcJava:$bcVersion")
    bouncyCastle("org.bouncycastle:bcpkix-$bcJava:$bcVersion")

    val brotliVersion = "1.16.0"
    brotli("com.aayushatharva.brotli4j:brotli4j:$brotliVersion")
    brotli("com.aayushatharva.brotli4j:native-windows-x86_64:$brotliVersion")
    brotli("com.aayushatharva.brotli4j:native-linux-x86_64:$brotliVersion")
    brotli("com.aayushatharva.brotli4j:native-osx-x86_64:$brotliVersion")
    brotli("com.aayushatharva.brotli4j:native-osx-aarch64:$brotliVersion")

    implementation("org.jitsi:ice4j:3.0-24-g34c2ce5") {
        // Don't need its dependencies, for now.
        setTransitive(false)
    }

    testImplementation("org.hamcrest:hamcrest-library:2.2")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-junit-jupiter:5.10.0")
    testImplementation(libs.log4j.core)
}
