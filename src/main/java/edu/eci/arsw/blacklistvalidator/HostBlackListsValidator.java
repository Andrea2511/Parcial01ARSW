/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT = 5;
    
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int N){

        CopyOnWriteArrayList<Integer> blackListOcurrences = new CopyOnWriteArrayList<>();
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();
        LinkedList<Busqueda> busquedas = new LinkedList<>();
        
        int checkedListsCount = 0;
        int serversCounts = skds.getRegisteredServersCount() / N;
        int remainingServersCounts = skds.getRegisteredServersCount() % N;
        int serversCountsinit = 0;

        for(int i = 0; i < N; i++) {
            Busqueda b = new Busqueda(ipaddress, serversCounts + (remainingServersCounts != 0 ? 1 : 0), BLACK_LIST_ALARM_COUNT, serversCountsinit);
            remainingServersCounts = remainingServersCounts-1;
            serversCountsinit += serversCounts;
            busquedas.add(b);
        }

        for(Busqueda b : busquedas) {

            try {
                b.join();
                System.out.println("Ocurrencias en " + b.getInitValue() + " hasta " + (b.getInitValue()+b.getN()-1) + ": " + b.getBlackListOcurrences().toString());
                blackListOcurrences.addAll(b.getBlackListOcurrences());


                LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{b.getCheckedListsCount(), skds.getRegisteredServersCount()});
            }
            catch (InterruptedException e){

            }
        }
        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    
}
