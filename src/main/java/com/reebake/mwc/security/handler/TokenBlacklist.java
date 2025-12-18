package com.reebake.mwc.security.handler;

public interface TokenBlacklist {

    public void addToken(String token);

    public boolean isTokenBlacklisted(String token);
}