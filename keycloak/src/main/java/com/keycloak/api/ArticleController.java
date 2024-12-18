package com.keycloak.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/articles")
public class ArticleController {

    private static final Map<Long, Article> articles = createArticles();
    private static final String ROLE_PREMIUM = "ROLE_premium_access";


    private static Map<Long, Article> createArticles() {

        Map<Long, Article> articlesMap = new HashMap<>();
        articlesMap.put(1L, new Article(1L, "Free Article", "This is a free sample article.", false));
        articlesMap.put(2L, new Article(2L, "Premium Article", "This is a premium sample article.", true));
        return Collections.unmodifiableMap(articlesMap);
    }

    // Pre Authorization 1
    @GetMapping("/basic")
    @PreAuthorize("hasAnyRole('basic_access' , 'premium_access')")
    public String getBasicArticle() {
        return "Free Article !";
    }

    // Pre Authorization 2
    @GetMapping("/premium")
    @PreAuthorize("hasRole('premium_access')")
    public String getPremiumArticle() {
        return "Premium Article !";
    }

    // In-Method Authorization
    @GetMapping("/all/{id}")
    public ResponseEntity<?> getArticleById(@PathVariable Long id, Authentication authentication) {
        if (!articles.containsKey(id)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("This content may have already deleted .");
        }

        Article article = articles.get(id);
        if (article.isPremium()) {
            boolean isPremiumUser = authentication.getAuthorities().contains(new SimpleGrantedAuthority(ROLE_PREMIUM));
            if (isPremiumUser) {
                return ResponseEntity.ok(article);
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("This content is only shown to the premium users .");
            }


        }else{
            return ResponseEntity.ok(article);
        }
    }

}
