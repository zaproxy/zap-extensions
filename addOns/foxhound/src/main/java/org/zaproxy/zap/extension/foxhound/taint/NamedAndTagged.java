package org.zaproxy.zap.extension.foxhound.taint;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public abstract class NamedAndTagged<T extends Enum<T>> {

    private String name;
    private Set<T> tags;

    private static <T> List<T> enumValuesInList(Class<T> enumCls) {
        T[] arr = enumCls.getEnumConstants();
        return arr == null ? Collections.emptyList() : Arrays.asList(arr);
    }

    public static <T extends Enum<T>> T getTagForString(String s, Class<T> enumCls) {
        for (T t : enumValuesInList(enumCls)) {
            if (t.name().equals(s)) {
                return t;
            }
        }
        return null;
    }

    public NamedAndTagged(String name) {
        this.name = name;
        this.tags = new HashSet<>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<T> getTags() {
        return tags;
    }

    public void setTags(Set<T> tags) {
        this.tags = tags;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof NamedAndTagged<?> that)) return false;
        return Objects.equals(name, that.name) && Objects.equals(tags, that.tags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, tags);
    }
}
