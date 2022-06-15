import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    `maven-publish`
    signing
}

group = "org.zaproxy.addon"

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

spotless {
    java {
        target(fileTree(projectDir) {
            include("src/**/*.java")
            exclude("src/main/java/org/apache/hc/client5/**/Zap*.java")
        })
    }
}

dependencies {
    val nettyVersion = "4.1.73.Final"
    implementation("io.netty:netty-codec:$nettyVersion")
    implementation("io.netty:netty-handler:$nettyVersion")

    implementation("org.apache.httpcomponents.client5:httpclient5:5.2-beta1")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.17.2") {
        // Provided by ZAP.
        exclude(group = "org.apache.logging.log4j")
    }

    val bcVersion = "1.69"
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

val sourceSets = extensions.getByName("sourceSets") as SourceSetContainer

tasks.register<Jar>("javadocJar") {
    from(tasks.named("javadoc"))
    archiveClassifier.set("javadoc")
}

tasks.register<Jar>("sourcesJar") {
    from(sourceSets.named("main").map { it.allJava })
    archiveClassifier.set("sources")
}

val ossrhUsername: String? by project
val ossrhPassword: String? by project

publishing {
    repositories {
        maven {
            val releasesRepoUrl = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsRepoUrl = uri("https://oss.sonatype.org/content/repositories/snapshots/")
            setUrl(provider { if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl })

            if (ossrhUsername != null && ossrhPassword != null) {
                credentials {
                    username = ossrhUsername
                    password = ossrhPassword
                }
            }
        }
    }

    publications {
        register<MavenPublication>("addon") {
            from(components["java"])

            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set("OWASP ZAP - Network Add-on")
                packaging = "jar"
                description.set(project.description)
                url.set("https://github.com/zaproxy/zap-extensions")
                inceptionYear.set("2021")

                organization {
                    name.set("OWASP")
                    url.set("https://www.zaproxy.org/")
                }

                mailingLists {
                    mailingList {
                        name.set("OWASP ZAP Developer Group")
                        post.set("zaproxy-develop@googlegroups.com")
                        archive.set("https://groups.google.com/group/zaproxy-develop")
                    }
                }

                scm {
                    url.set("https://github.com/zaproxy/zap-extensions")
                    connection.set("scm:git:https://github.com/zaproxy/zap-extensions.git")
                    developerConnection.set("scm:git:https://github.com/zaproxy/zap-extensions.git")
                }

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }

                developers {
                    developer {
                        id.set("AllAddOnDevs")
                        name.set("Everyone who has contributed to the add-on")
                        email.set("zaproxy-develop@googlegroups.com")
                    }
                }
            }
        }
    }
}

signing {
    if (project.hasProperty("signing.keyId")) {
        sign(publishing.publications["addon"])
    }
}
