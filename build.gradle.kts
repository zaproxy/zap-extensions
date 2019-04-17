plugins {
    id("com.diffplug.gradle.spotless") version "3.20.0"
}

apply(from = "$rootDir/gradle/travis-ci.gradle.kts")
apply(from = "$rootDir/gradle/lgtm.gradle.kts")

allprojects {
    apply(plugin = "com.diffplug.gradle.spotless")

    repositories {
        mavenCentral()
    }

    spotless {
        kotlinGradle {
            ktlint()
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "utf-8"
        options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
    }
}