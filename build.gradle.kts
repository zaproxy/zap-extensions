plugins {
    id("com.diffplug.gradle.spotless")
    id("com.github.ben-manes.versions") version "0.27.0"
    id("org.sonarqube") version "3.0"
}

apply(from = "$rootDir/gradle/travis-ci.gradle.kts")
apply(from = "$rootDir/gradle/lgtm.gradle.kts")

allprojects {
    apply(plugin = "com.diffplug.gradle.spotless")
    apply(plugin = "com.github.ben-manes.versions")

    repositories {
        mavenCentral()
    }

    spotless {
        kotlinGradle {
            ktlint()
        }

        project.plugins.withType(JavaPlugin::class) {
            java {
                licenseHeaderFile("$rootDir/gradle/spotless/license.java")
                googleJavaFormatAosp(project)
            }
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "utf-8"
        options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}

sonarqube {
    properties {
        property("sonar.projectKey", "zaproxy_zap-extensions")
        property("sonar.organization", "zaproxy")
        property("sonar.host.url", "https://sonarcloud.io")
    }
}
