package com.example.imtest;



import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.List;


@SpringBootApplication
public class ImtestApplication {

    public static void main(String[] args)  {
        SpringApplication.run(ImtestApplication.class, args);

    }

}
