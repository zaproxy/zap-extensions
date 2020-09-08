import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    `maven-publish`
    signing
}

group = "org.zaproxy.addon"

version = "13.1.0"
description = "Advanced fuzzer for manual testing"

tasks.withType<JavaCompile> {
    options.compilerArgs = options.compilerArgs - "-Werror"
}

zapAddOn {
    addOnName.set("Fuzzer")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/fuzzer/")
    }
}

dependencies {
    implementation("com.natpryce:snodge:2.1.2.2")
    implementation("org.owasp.jbrofuzz:jbrofuzz-core:2.5.1") {
        // Only "jbrofuzz-core" is needed.
        setTransitive(false)
    }
    implementation(files("lib/generex-0.0.5-SNAPSHOT.jar"))
    implementation("dk.brics.automaton:automaton:1.11-8")

    testImplementation(project(":testutils"))
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
                name.set("OWASP ZAP - Fuzzer Add-on")
                packaging = "jar"
                description.set(project.description)
                url.set("https://github.com/zaproxy/zap-extensions")
                inceptionYear.set("2015")

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
