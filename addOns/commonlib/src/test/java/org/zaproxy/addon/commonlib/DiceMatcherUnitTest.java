/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DiceMatcherUnitTest {

    private static final String ORIGINAL_STRING =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus"
                    + "eget sapien sit amet tortor finibus feugiat sit amet eu tellus. Duis orci"
                    + "ligula, tempor eget ultrices ac, mattis vitae leo. Nam eget neque et quam"
                    + "rutrum feugiat eget eget felis. Mauris ipsum urna, fringilla ut volutpat"
                    + "vitae, fringilla a elit. Aenean quis feugiat quam. Fusce suscipit est"
                    + "sapien, sed ornare elit auctor et. Duis in porttitor eros. Praesent vel"
                    + "imperdiet libero. Etiam eu nulla metus. Etiam ultrices risus eget tellus"
                    + "luctus, ac accumsan purus sollicitudin. Sed lacinia est ornare ex accumsan,"
                    + "nec auctor enim porttitor. Praesent ut nibh eleifend massa consequat"
                    + "fringilla non at tellus. Aenean placerat sit amet dui sed fringilla. Ut"
                    + "iaculis fermentum iaculis.Quisque eu fermentum neque. In imperdiet, massa et"
                    + "accumsan pulvinar, nisl dolor aliquam nunc, a tincidunt augue risus id diam."
                    + "Donec sit amet nulla maximus, blandit nisi nec, lobortis arcu. Sed"
                    + "hendrerit risus non massa gravida, a gravida lectus bibendum. Phasellus quis"
                    + "dictum elit, ut gravida sapien. In quis porta orci. Nunc quis convallis"
                    + "ligula. Nullam quis tincidunt ante. Nullam elementum auctor risus mattis"
                    + "aliquam. Sed sit amet volutpat dolor, eu consectetur nulla. Aenean sapien"
                    + "diam, egestas sit amet feugiat bibendum, molestie ac massa. Donec quis"
                    + "feugiat dolor, quis hendrerit nunc. Pellentesque sit amet velit non quam"
                    + "euismod tincidunt quis vitae lectus. Vestibulum finibus egestas tincidunt."
                    + "Sed eget felis sit amet massa luctus malesuada. Aenean non lacus mattis,"
                    + "tempor ex at, pulvinar risus.";

    private static final String SIMILAR_STRING =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phaselluseget"
                    + "sapien sit amet tortor finibus feugiat sit amet eu tellus. Duis orciligula,"
                    + "tempor eget ultrices ac, mattis vitae leo. Nam eget neque et quamrutrum feugiat"
                    + "eget eget felis. Mauris ipsum urna, fringilla ut volutpatvitae, fringilla a"
                    + "elit. Aenean quis feugiat quam. Fusce suscipit estsapien, sed ornare elit"
                    + "auctor et. Duis in porttitor eros. Praesent velimperdiet libero. Etiam eu nulla"
                    + "metus. Etiam ultrices risus eget tellusluctus, ac accumsan purus sollicitudin."
                    + "Sed lacinia est ornare ex accumsan,nec auctor enim porttitor. Praesent ut"
                    + "nibh eleifend massa consequatfringilla non at tellus. Aenean placerat sit amet"
                    + "dui sed fringilla. Utiaculis fermentum iaculis.Quisque eu fermentum neque. In"
                    + "imperdiet, massa etaccumsan pulvinar, nisl dolor aliquam nunc, a tincidunt augue"
                    + "risus id diam.Donec sit amet nulla maximus, blandit nisi nec, lobortis arcu."
                    + "Sedhendrerit risus non massa gravida, a gravida lectus bibendum. Phasellus quisdictum"
                    + "elit, ut gravida sapien. In quis porta orci. Nunc quis convallisligula. Nullam"
                    + "quis tincidunt ante. Nullam elementum auctor ;{Ta$i2,V- BPN~_2J^B$ h%e.a_9zRt"
                    + "pv4]r[.Ury 6i%F^SZS0c wIFTzTZ<TI uWr?8<j-(2 yba3iJ9_D ?YOo*>i'MW ;ERtYa}V;"
                    + "@R4toBiB9, lX3&kOs_Z% 9bBobiqiG{ |p@.lV<1g  (8e/b.[WZd (IC.PM$3w] B{} %GQT}m"
                    + "Oq{=~!H_,m 3d<k{zqW SsQ*j.,XQW wa.Vi:)VW^ 2t:NGi'YIo BlRB%7(^Ca JHf#@G6H)0"
                    + "4)fofbSAiS fF+oqc#eWa |+ wCxptXM JW}v~x}hhy -<^IgTMmwH k'sP)&x^! 4~AnehXsH"
                    + "9z:q{Q^TM9  D)4q8vKe m^z9A4Zxo Gbo9-,-Wjh <~Nx{r)jXb dShM_~$icx 9f8dIN;CHw"
                    + "yDitJ,d0-/ 8]15T9yfj] (MTLf)Uh Rb?FKVNQ/Z 3e/il;;W_( Yf*|J@uqPT *lOW(W$:I`"
                    + "k|CIH&}fhu ?XI]n-G? #n9&R:%if Kj+>p@#rJ^ 1!6Sp])y x?zn]AK=$ x;?@&r=$/"
                    + "FSy(U*V}ll :sM{H^# )U";

    private static final String DIFFERENT_STRING =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phaselluseget"
                    + "sapien sit amet tortor finibus feugiat sit amet eu tellus. Duis orciligula,"
                    + "tempor eget ultrices ac, mattis vitae leo. Nam eget neque et quamrutrum feugiat"
                    + "eget eget felis. Mauris ipsum urna, fringilla ut volutpatvitae, fringilla a"
                    + "elit. Aenean quis feugiat quam. Fusce suscipit estsapien, sed 7aDw,|*(.]"
                    + "5mgdeqCoLW G5?7T*:yyp {<V`;S2wmd lX4a\5OC:B Bmc CwzQ ]lau[j3B4 nyIXz-m_z."
                    + ",/ozmjqFRD aM.q|eP{o_ H/CO@Ogelq jWWrZ[`cgj j)IpP*[#q+ %Z)R:+Ihdg HM7z@R)wq-"
                    + "-g)=;z^t+^ jsgIx<1a>/ _y0 kb@ED[ `K>4qKSJIu K,!_kqyr,G GkBoB'(4za @nz1Hy>ABp"
                    + ";C)rsS&d ,5lkPRd;cr nlEUj-}7~ >4z:-DQEP- EO0z<bcrjg ANPf1>Sc.  l|U:Z;{=H"
                    + "O.9fPZ?!G0 rs$UE]+)b g:oZM<PmCy :.c!P,rzS v?wEQ5s`N1 j_5LTOx$  |SuF<.a)P="
                    + "lK~J`c`8t< mu/-l,X#/* SajXg?bk<f YprGm|u];  #HW'(*o41~ 28F!XHQ,_H 5m10JL`.x?"
                    + "X+\5(fSSa~ s>#oW .mc %`(^D1#i`* /aN=^o.fK0 6+C24dr($ ,:}JZgOL+A =;~`;xGY?C"
                    + "^sL2dvJ-74 %m.5PG)&xd !S%EUe,@0: 8@?;.=q&D* }3YKmOTr}@ kP`J{p2D'O nph4t9T2gp"
                    + "{?dl)yeOa6 o<5WO1(X@D p4r-[*So? OO[vt$-UX >}JZCP} sK ?#%+v%Mm@- [`sQ)6Q'<n"
                    + "Q[R<QL^A awkg>4Qr+( cju.nq'[i' =;Uv@Y=7JX TezMX*mB+s (Rf(W-[<| `<u:u}KdV"
                    + "#{6AX8b(H] s'Yf6LnS SZF3LeQu# q.11 .1EZ rx.Ezj)T{H YP6KwbrVN3 pXP`zI[;|u NN"
                    + "T}yt{'? /=N%y@|-jH ?{#I8-.n(* GPxQ#0QXXx &1C},73Sfw <[Tkq0aZbV 1 oI4+J  p"
                    + "(uXq4oEWaQ UCet45;xp xP  XIH~7F |i@0-%Rn&< (T1YULn ( WoPzyr0!&< 35 LpE0lN9"
                    + "lv..p)>zwU +bj#*;zjyO 84Dq-qMP -:@!pW7+I4 3c+_}1J/ (M!CbXWZkO gIbD3<%YZ5"
                    + "znws3K($+. U+I`i0eI z}Re7Ky@UY m<6?tpgMb; Ckm09Fu#@0 _%jE0[@ :. 2E8]p<E3]@"
                    + "58#VT=t4a% .3y5ixV;L #q21SkpR! 3i*9ZuDCNU 6}%3~bf/EE P$sVa7|G;R p@A/=St,Z&"
                    + "Y/YH.i^UdD e73KVGbXz& P|^lw^YE&] swmU(XZ,R% kaEgMN-Dqg ;.:?>7wj$x bn2',Vn%X7"
                    + "x9Rqs|X<ag r,Y{so,;w n. >f(TdB  eW}pD)FFO4 (9T)3_$@Qu !|%OO'zAJ_ Dj,x,!h9u"
                    + "z#bk]QDaU U 5yWjpM} q=|y(p(] v=.,E3v:vH q3i|Az:iuS %?}NJqGu&k :R(i{6[3$c"
                    + "XP*])<ux3d 89cZ7rt;Xr L>zyDrY>V' |DQv'A_&9h _{V^3XZPZ  2>a(QIA$mq K*dU6|wZ'["
                    + ";6#Ht/[)do dI31R z6x0 V+O;FIOT I{A96t7v@S !yZz=vydv xMB(#[5qQm O.cK9-3Lf "
                    + "%Ydy[(k8 xyJKwGw,y6 >#]A-=Rx#e ]x.#]2-Ds [r#y;#Ea^Ra)AzHYa%,i z ctr<qUtQ"
                    + "=O.QHn_s5/ p__C0v':a: -O~I,6CRm! Gc_>81{|^* =D.A)umZz` By_;]+<x+| 0K;9*[ln0l";

    @Test
    void shouldGiveCorrectPercentageForSameString() {
        // Given / When
        int sim = DiceMatcher.getMatchPercentage(ORIGINAL_STRING, ORIGINAL_STRING);

        // Then
        assertThat(sim, is(equalTo(100)));
    }

    @Test
    void shouldGiveCorrectPercentageForSimilarString() {
        // Given / When
        int sim = DiceMatcher.getMatchPercentage(ORIGINAL_STRING, SIMILAR_STRING);

        // Then
        assertThat(sim, is(equalTo(70)));
    }

    @Test
    void shouldGiveCorrectPercentageForDifferentString() {
        // Given / When
        int sim = DiceMatcher.getMatchPercentage(ORIGINAL_STRING, DIFFERENT_STRING);

        // Then
        assertThat(sim, is(equalTo(25)));
    }

    static Stream<Arguments> stringSetSource() {
        return Stream.of(
                Arguments.of(null, ORIGINAL_STRING),
                Arguments.of(ORIGINAL_STRING, null),
                Arguments.of(null, null),
                Arguments.of("a", ORIGINAL_STRING),
                Arguments.of(ORIGINAL_STRING, "a"));
    }

    @ParameterizedTest
    @MethodSource("stringSetSource")
    void shouldGiveZeroPercentageForNullOrShortString(String stringA, String stringB) {
        // Given / When
        int sim = DiceMatcher.getMatchPercentage(stringA, stringB);
        // Then
        assertThat(sim, is(equalTo(0)));
    }
}
