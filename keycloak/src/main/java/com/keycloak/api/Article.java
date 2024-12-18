package com.keycloak.api;



public class Article {

    private final Long id;
    private final String title;
    private final String content;
    private final boolean isPremium;


    public Article(Long id, String title, String content, boolean isPremium){
        this.id = id;
        this. title = title;
        this.content = content;
        this.isPremium = isPremium;
    }

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getContent() {
        return content;
    }

    public boolean isPremium() {
        return isPremium;
    }
}





