import me.champeau.gradle.japicmp.JapicmpTask
import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    `maven-publish`
    signing
    id("me.champeau.gradle.japicmp") version "0.2.9"
}

group = "org.zaproxy.addon"

version = "1.3.0"
val versionBC = "1.0.0"
description = "A common library, for use by other add-ons."

zapAddOn {
    addOnName.set("Common Library")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        notBeforeVersion.set("2.10.0")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

dependencies {
    implementation("commons-io:commons-io:2.6")
    implementation("org.apache.commons:commons-csv:1.8")
    implementation("org.apache.commons:commons-collections4:4.4")

    testImplementation(project(":testutils"))
}

val japicmp by tasks.registering(JapicmpTask::class) {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Checks ${project.name}.jar binary compatibility with latest version ($versionBC)."

    oldClasspath = files(addOnJar(versionBC))
    newClasspath = files(tasks.named<Jar>(JavaPlugin.JAR_TASK_NAME).map { it.archivePath })
    setIgnoreMissingClasses(true)

    richReport {
        destinationDir = file("$buildDir/reports/japicmp/")
        reportName = "japi.html"
        isAddDefaultRules = true
    }
}

fun addOnJar(version: String): File {
    val oldGroup = group
    try {
        // https://discuss.gradle.org/t/is-the-default-configuration-leaking-into-independent-configurations/2088/6
        group = "virtual_group_for_japicmp"
        val conf = configurations.detachedConfiguration(dependencies.create("$oldGroup:$name:$version"))
        conf.isTransitive = false
        return conf.singleFile
    } finally {
        group = oldGroup
    }
}

tasks.named(LifecycleBasePlugin.CHECK_TASK_NAME) {
    dependsOn(japicmp)
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
                name.set("OWASP ZAP - Common Library Add-on")
                packaging = "jar"
                description.set(project.description)
                url.set("https://github.com/zaproxy/zap-extensions")
                inceptionYear.set("2020")

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
