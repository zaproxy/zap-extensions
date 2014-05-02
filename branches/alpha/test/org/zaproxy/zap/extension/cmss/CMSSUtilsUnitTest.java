package org.zaproxy.zap.extension.cmss;

import org.hamcrest.Matchers;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.cmss.CMSSUtils.*;

public class CMSSUtilsUnitTest {

    @Test
    public void checksumOfInputStringShouldReturnMD5Hash() throws Exception {
        // expected results generated using http://www.miraclesalad.com/webtools/md5.php
        assertThat(checksum("".getBytes()), is("d41d8cd98f00b204e9800998ecf8427e"));
        assertThat(checksum(" ".getBytes()), is("7215ee9c7d9dc229d2921a40e899ec5f"));
        assertThat(checksum("test1".getBytes()), is("5a105e8b9d40e1329780d62ea2265d8a"));
        assertThat(checksum("test2".getBytes()), is("ad0234829205b9033196ba818f7a872b"));
    }

    @Test(expected = NullPointerException.class)
    public void checksumOfNullShouldThrowException() throws Exception {
        checksum(null);
    }

    @Test
    public void checksumOfEmptyBytesArrayIsEqualToMD5HashOfEmptyString() throws Exception {
        assertThat(checksum(new byte[0]), is(checksum("".getBytes())));
    }

}