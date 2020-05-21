package com.im.single;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
//1.模式一，例如tg 一个设备对一个设备的 端对端加密
public class chattest_one_device_to_one_device {

    public static void main(String[] args) throws Exception {
        /*
         *创建2个用户例子 alice和bob 和他们的密钥
         */
        UserEntity alice = new UserEntity(  "alice" );

        UserEntity bob = new UserEntity(  "bob" );

        /*
         * 建立会话
         */
        Session aliceToBobSession = new Session(alice.getStore(), bob.getOtherKeyBundle(), bob.getAddress());

        /*
         *alice 发送消息给 bob
         */
        List<PreKeySignalMessage> toBobMessages = Arrays.stream("31,41,59,26,53".split(","))
                .map(msg -> aliceToBobSession.encrypt(msg))
                .collect(Collectors.toList());

        /*
         *bob 建立会话，准备解密消息
         */
        Session bobToAliceSession = new Session(bob.getStore(), alice.getOtherKeyBundle(), alice.getAddress());

        /*
         * bob解密消息
         */
        String fromAliceMessages = toBobMessages.stream()
                .map(encryptedMsg -> bobToAliceSession.decrypt(encryptedMsg))
                .peek(msg -> System.out.printf("Received from alice: '%s'%n", msg))
                .collect(joining(","));

        if (!fromAliceMessages.equals("31,41,59,26,53")) {
            throw new IllegalStateException("No match");
        }

        /*
         * bob 发送消息给 alice
         */
        List<PreKeySignalMessage> toAliceMessages = Arrays.stream("the quick brown fox".split(" "))
                .map(msg -> bobToAliceSession.encrypt(msg))
                .collect(toList());

        /*
         * alice读bob的加密消息，乱序测试
         */
        Collections.shuffle(toAliceMessages);
        List<String> fromBobMessages = toAliceMessages.stream()
                .map(encryptedMsg -> aliceToBobSession.decrypt(encryptedMsg))
                .peek(msg -> System.out.printf("Received from bob: '%s'%n", msg))
                .collect(Collectors.toList());

        if (!(fromBobMessages.size() == 4
                && fromBobMessages.contains("the")
                && fromBobMessages.contains("quick")
                && fromBobMessages.contains("brown")
                && fromBobMessages.contains("fox"))) {
            throw new IllegalStateException("No match");
        }
    }

}
