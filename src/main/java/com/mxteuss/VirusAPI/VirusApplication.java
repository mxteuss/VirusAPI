package com.mxteuss.VirusAPI;

import com.mxteuss.VirusAPI.service.UrlService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import java.util.Scanner;

@SpringBootApplication
public class VirusApplication {
    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(VirusApplication.class, args);

        UrlService urlService = context.getBean(UrlService.class);

        Scanner scanner = new Scanner(System.in);
        System.out.print("Insira a URL: ");
        String url = scanner.nextLine();

        urlService.scanURL(url);
    }
}