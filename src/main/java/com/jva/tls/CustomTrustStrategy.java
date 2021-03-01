package com.jva.tls;

import org.apache.http.conn.ssl.TrustStrategy;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CustomTrustStrategy implements TrustStrategy {
	


    private Map<String, X509Certificate> acceptedIssuersMap;

    public CustomTrustStrategy() {
        loadAllAcceptedIssuers();
        System.out.println("\uD83D\uDE00");
        /*for(String key:acceptedIssuersMap.keySet())
        {
        	System.out.println(key +" : "+acceptedIssuersMap.get(key));
        }*/
      
 
    }


    private void loadAllAcceptedIssuers()  {
        if(acceptedIssuersMap == null) {
            try {
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init((KeyStore) null);
                List<X509Certificate> acceptedIssuers = new ArrayList<>();
                Arrays.asList(trustManagerFactory.getTrustManagers()).stream().forEach(tm -> {
                    acceptedIssuers.addAll(Arrays.asList(((X509TrustManager) tm).getAcceptedIssuers()));
                });
                acceptedIssuersMap = acceptedIssuers.stream().collect(
                        Collectors.toMap(cert -> cert.getSubjectDN().toString(), cert -> cert));
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                //Temp exception
                e.printStackTrace();
            }

        }
    }

    public boolean isTrusted(X509Certificate[] certChain, String authType) throws CertificateException {
         if(acceptedIssuersMap == null){
             throw new IllegalStateException("Unable to determine CA certificates from truststore");
         }
         
         for(X509Certificate cert: certChain){
             if(acceptedIssuersMap.containsKey(cert.getIssuerDN().toString())){
                 return true;
             }
         }
         return false;
    }

}
