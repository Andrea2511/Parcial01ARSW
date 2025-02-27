package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.LinkedList;

public class Busqueda extends Thread {

    private int ocurrencesCount;
    HostBlacklistsDataSourceFacade skds;
    private String ipAddress;
    private final int n;
    private final int initValue;
    private Boolean isInBlackListServer;
    private int blackListCount;
    LinkedList<Integer> blackListOcurrences;
    private int checkedListsCount;

    public Busqueda(String ipaddress, int n, int blackListCount, int serversCountsinit){
        this.n = n;
        ipAddress = ipaddress;
        ocurrencesCount = 0;
        skds = HostBlacklistsDataSourceFacade.getInstance();
        isInBlackListServer = false;
        this.blackListCount = blackListCount;
        blackListOcurrences = new LinkedList<>();
        checkedListsCount = 0;
        initValue= serversCountsinit;
        start();

    }

    @Override
    public void run() {

        for (int i = initValue; i < n && ocurrencesCount < blackListCount; i++){

            checkedListsCount++;

            if (skds.isInBlackListServer(i, ipAddress)){

                blackListOcurrences.add(i);
                ocurrencesCount++;
            }
        }

        if (ocurrencesCount >= blackListCount){
            skds.reportAsNotTrustworthy(ipAddress);
        }
        else{
            skds.reportAsTrustworthy(ipAddress);
        }
    }

    public int getOcurrencesCount() {
        return ocurrencesCount;
    }

    public Boolean getInBlackListServer() {
        return isInBlackListServer;
    }

    public LinkedList<Integer> getBlackListOcurrences() {
        return blackListOcurrences;
    }

    public int getCheckedListsCount() {
        return checkedListsCount;
    }
}
