package com.mxteuss.VirusAPI.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

@Service
public class UrlService {


    @Value("${apikey}")
    private String API_KEY;

    public void scanURL(String url) {
        try {
            String params = "url="  + URLEncoder.encode(url, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/urls"))
                    .header("accept", "application/json")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("x-apikey", API_KEY)
                    .method("POST", HttpRequest.BodyPublishers.ofString(params))
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            ObjectMapper mapper = new ObjectMapper();
            String id = mapper.readTree(response.body()).path("data").path("id").asText();
            getReport(id);

        } catch (IOException | InterruptedException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public void getReport(String id) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/analyses/" + id))
                    .header("accept", "application/json")
                    .header("x-apikey", API_KEY)
                    .method("GET", HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200){
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode attrs = root.path("data").path("attributes");
                JsonNode stats = attrs.path("stats");
            if (!stats.equals("completed")) {
                System.out.println("==================== Relatório VirusTotal ====================");
                System.out.println("URL analisada : " + attrs.path("url").asText());
                System.out.println("Status        : " + attrs.path("status").asText());
                System.out.println("--------------------------------------------------------------");
                System.out.println("✅ Seguro      : " + stats.path("harmless").asInt());
                System.out.println("🚨 Malicioso   : " + stats.path("malicious").asInt());
                System.out.println("⚠️  Suspeito    : " + stats.path("suspicious").asInt());
                System.out.println("❓ Não detectado: " + stats.path("undetected").asInt());
                System.out.println("==============================================================");
            }
            }
            else {
                System.out.println(response.statusCode() + " " + response.body());
            }
        }
        catch (IOException | InterruptedException e) {
            System.out.println(e.getMessage());
        }
    }

}
