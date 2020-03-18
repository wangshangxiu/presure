package com.im.secure;


import org.apache.rocketmq.client.exception.MQBrokerException;
import org.apache.rocketmq.client.exception.MQClientException;
import org.apache.rocketmq.client.producer.DefaultMQProducer;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.client.producer.SendStatus;
import org.apache.rocketmq.common.message.Message;
import org.apache.rocketmq.remoting.exception.RemotingException;

import java.util.UUID;

/**

 */
public class SyncProducer {
    private static DefaultMQProducer producer = null;
public static String serverip="45.248.87.235";
    public static void main(String[] args) {
        System.out.print("[----------]Start\n");
        int pro_count = 1;
        if (args.length > 0) {
            pro_count = Integer.parseInt(args[0]);
        }
        boolean result = false;
        try {
            ProducerStart();

            Thread.sleep(5000);
            for (int i = 0; i < pro_count; i++) {
                String msg = "hello rocketmq "+ i+"".toString();
                SendMessage("qch_20170706",              //topic
                        "Tag"+i,                           //tag
                        "Key"+i,                           //key
                        msg);                                  //body
                System.out.print(msg + "\n");
            }
        }catch (Exception e)
        {

        }
        finally {
            producer.shutdown();
        }
        System.out.print("[----------]Succeed\n");
    }

    private static boolean ProducerStart() {
        producer = new DefaultMQProducer("pro_qch_test");
        producer.setNamesrvAddr(serverip+":9876");
        //producer.setVipChannelEnabled(false);
        //producer.setCreateTopicKey("pro_qch_test");

        producer.setInstanceName(UUID.randomUUID().toString());
        try {
            producer.start();
        } catch(MQClientException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private static boolean SendMessage(String topic,String tag,String key, String str) {
        Message msg = new Message(topic,tag,key,str.getBytes());
        try {
            SendResult result = producer.send(msg);
            SendStatus status = result.getSendStatus();
            System.out.println("___________________________SendMessage: "+status.name());
        } catch (MQClientException | RemotingException | MQBrokerException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
}