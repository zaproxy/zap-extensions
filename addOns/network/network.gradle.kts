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
    compileOnly(libs.log4j.core)

    implementation(libs.network.netty.codec)
    implementation(libs.network.netty.handler)
    implementation(libs.network.netty.codec.http2)

    hc(libs.network.httpclient)
    implementation(libs.log4j.slf4j)

    bouncyCastle(libs.network.bouncycastle.bcmail)
    bouncyCastle(libs.network.bouncycastle.bcprov)
    bouncyCastle(libs.network.bouncycastle.bcpkix)

    brotli(libs.network.brotli)
    brotli(libs.network.brotli.windows.amd64)
    brotli(libs.network.brotli.linux.amd64)
    brotli(libs.network.brotli.osx.amd64)
    brotli(libs.network.brotli.osx.aarch64)

    implementation(libs.network.ice4j) {
        // Don't need its dependencies, for now.
        setTransitive(false)
    }

    testImplementation(libs.test.hamcrest)
    testImplementation(libs.test.junit.jupiter)
    testRuntimeOnly(libs.test.junit.platformLauncher)
    testImplementation(libs.test.mockito.junit.jupiter)
    testImplementation(libs.log4j.core)
}
