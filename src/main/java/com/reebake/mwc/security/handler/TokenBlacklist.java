package com.reebake.mwc.security.handler;

public interface TokenBlacklist {

    void addToken(String token);

    boolean isTokenBlacklisted(String token);
}