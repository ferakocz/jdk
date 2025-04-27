/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/**
 * @test
 * @bug 8351034
 * @summary Add AVX-512 intrinsics for ML-DSA
 * @compile  --add-exports=java.base/sun.security.provider=ALL-UNNAMED TestModuleLatticeDSA.java
 * @run main/othervm  -ea -XX:+UnlockDiagnosticVMOptions -XX:CompileThresholdScaling=0.3  -XX:-TieredCompilation -Xbatch  --add-exports=java.base/sun.security.provider=ALL-UNNAMED compiler.intrinsics.signature.TestModuleLatticeDSA 2 256 1000
 * @run main/othervm  -ea -XX:+UnlockDiagnosticVMOptions -XX:CompileThresholdScaling=0.3  -XX:-TieredCompilation -Xbatch  --add-exports=java.base/sun.security.provider=ALL-UNNAMED compiler.intrinsics.signature.TestModuleLatticeDSA 3 256 1000
 * @run main/othervm  -ea -XX:+UnlockDiagnosticVMOptions -XX:CompileThresholdScaling=0.3  -XX:-TieredCompilation -Xbatch  --add-exports=java.base/sun.security.provider=ALL-UNNAMED compiler.intrinsics.signature.TestModuleLatticeDSA 5 256 1000
 */

package compiler.intrinsics.signature;

import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class TestModuleLatticeDSA {
   public static KeyPairGenerator kg = null;
   public static KeyPair kp = null;
   public static Signature sign = null;
   public static SecureRandom rnd = new java.security.SecureRandom("SEED123".getBytes());

   public static byte [] testSign(byte [] message) throws Exception {
       sign.initSign(kp.getPrivate(), rnd);
       sign.update(message);
       return sign.sign();
   }

   public static boolean testVerify(byte [] message, byte [] signature) throws Exception {
       sign.initVerify(kp.getPublic());
       sign.update(message);
       return sign.verify(signature);
   }

   public static byte [] initBench(int securityLevel, int message_length) throws Exception {
       kg = KeyPairGenerator.getInstance("ML-DSA");
       switch(securityLevel) {
           case 2 : kg.initialize(NamedParameterSpec.ML_DSA_44, rnd);
           break;
           case 3 : kg.initialize(NamedParameterSpec.ML_DSA_65, rnd);
           break;
           case 5 : kg.initialize(NamedParameterSpec.ML_DSA_87, rnd);
           break;
           default:
           assert false : "Incorrect Security Level should be 2,3 or 5";
       }
       kp = kg.genKeyPair();
       sign = Signature.getInstance("ML-DSA");

       byte [] message = new byte[message_length];
       rnd.nextBytes(message);
       return message;
   }

   public static void main(String [] args) throws Exception {
       byte [] message = initBench(Integer.parseInt(args[0]), Integer.parseInt(args[1]));

       int ITER = Integer.parseInt(args[2]);
       for (int i = 0; i < ITER; i++) {
           byte [] signature = testSign(message);
           if (testVerify(message, signature) == false) {
               throw new AssertionError("Signature verification failed!");
           }
       }

       System.out.println("Test Passed");
   }
}
