package com.im.secure;


import java.util.zip.CRC32;

public class CRC32Util {
    public static void main(String[]args){


        long res=getCrc32("A31d2152a33d83e7");
        long t=System.currentTimeMillis();
        long beg= (t/1000- 86400*365);
        long t1= t-beg*1000;
        res=0xafffffee;
        res=res << 32;

        t1=0xdfffffef;
        res =res | t1;

        System.out.println(Long.toHexString(res));
        System.out.println(getCrc32("ab123"));
    }
    public static long getCrc32(String content){
        CRC32 crc32 = new CRC32();
        crc32.update(content.getBytes());
        Long value = crc32.getValue();
        return value;
    }
//
//    public static String getCrc32(String content){
//        CRC32 crc32 = new CRC32();
//        crc32.update(content.getBytes());
//        Long value = crc32.getValue();
//        return Long.toHexString(value);
//    }
}
