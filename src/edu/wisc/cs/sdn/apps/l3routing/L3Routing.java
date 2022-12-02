package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

//OFMatch, OFActionOutput, OFAction, OFInstructionApplyActions, OFInstruction

public class L3Routing implements IFloodlightModule, IOFSwitchListener,
        ILinkDiscoveryListener, IDeviceListener
{
    public static final String MODULE_NAME = L3Routing.class.getSimpleName();

    // Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;

    // Switch table in which rules should be installed
    public static byte table;

    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

    /**
     * Loads dependencies and initializes data structures.
     */
    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException
    {
        log.info(String.format("Initializing %s...", MODULE_NAME));
        Map<String,String> config = context.getConfigParams(this);
        table = Byte.parseByte(config.get("table"));

        this.floodlightProv = context.getServiceImpl(
                IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);

        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
    }
    //helper function to install rule
    private boolean instR(IOFSwitch sw, int dstIP, int port) {

        OFMatch matchCriteria = new OFMatch();
        matchCriteria.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, dstIP);
        OFActionOutput out = new OFActionOutput(port);
        List<OFAction> li = new ArrayList<OFAction>();
        li.add(out);
        OFInstructionApplyActions ofAc = new OFInstructionApplyActions(li);
        List<OFInstruction> instructions = new ArrayList<OFInstruction>();
        instructions.add(ofAc);
        return SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, matchCriteria, instructions);
    }
    //helper function to install rule in each switch to route to host
    private void installRuleForHost(Host h) {
        Map<Long, IOFSwitch> switches = this.getSwitches();
        int dstIP = h.getIPv4Address().intValue();
        spInfo sp = bellmanFord(h);
        int[] dist = sp.distance;
        //int[] prev = sp.previous;
        Long[] swArr = sp.switchesArray;
        int[] ports = sp.ports;
        //rule for each switch: output packet on the right port to reach the next switch in the shortest path
        //find the index of the host
        int s;
        for (s = 0; s < dist.length; s++) {
            if (dist[s] == 0) {
                break;
            }
        }
        for (int i = 0; i < swArr.length; i++) {
            // loop through all switches except for the host's switch
            // put rule in these switches
            IOFSwitch sw = switches.get(swArr[i]);
            if (i != s) {
                instR(sw, dstIP, ports[i]);
            } else { //rule for the host's switch: forward packet to the host
                int port = h.getPort().intValue();
                instR(sw, dstIP, port);
            }

        }
    }
    private void removeRuleForHost(Host h) {
        Collection<IOFSwitch> switches = this.getSwitches().values();
        Iterator<IOFSwitch> it = switches.iterator();
        int dstIP = h.getIPv4Address().intValue();
        OFMatch matchCriteria = new OFMatch();
        matchCriteria.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, dstIP);
        while (it.hasNext()) {
            IOFSwitch sw = it.next();
            SwitchCommands.removeRules(sw, table, matchCriteria);
        }
    }
    /**
     * Subscribes to events and performs other startup tasks.
     */
    @Override
    public void startUp(FloodlightModuleContext context)
            throws FloodlightModuleException
    {
        log.info(String.format("Starting %s...", MODULE_NAME));
        this.floodlightProv.addOFSwitchListener(this);
        this.linkDiscProv.addListener(this);
        this.deviceProv.addListener(this);

        /*********************************************************************/
        /* TODO: Initialize variables or perform startup tasks, if necessary */
        //run shortest path on every host and fill every switch of the info?
        Collection<Host> hosts = this.getHosts();
        //Map<Long, IOFSwitch> switches = this.getSwitches();
        //Collection<Link> links = this.getLinks();
        Iterator<Host> it = hosts.iterator();
        while (it.hasNext()) {
            Host h = it.next();
            installRuleForHost(h);
        }
        /*********************************************************************/
    }
    // class used to return multiple stuff
    class spInfo {
        final int[] distance;
        final int[] previous;
        final Long[] switchesArray;
        final int[] ports;

        spInfo(int[] d, int[] p, Long[] sa, int[] ports) {
            this.distance = d;
            this.previous = p;
            this.switchesArray = sa;
            this.ports = ports;
        }
    }
    private int searchArr(IOFSwitch sw, Long[] swArr, int swCount) {
        int s;
        for (s = 0; s < swCount; ++s) {
            if (swArr[s].longValue() == sw.getId()) {
                return s;
            }
        }
        return -1;
    }
    /**
     * find shortest path from host's switch to every other switch, when used might need the reverse of the path
     */
    private spInfo bellmanFord(Host host)
    {
        //idea: switches are vertices since the getLinks gets the link between switches
        // return the shortest route among switches? perhaps assume each host will only be connected to a switch
        //assume all links have weight 1, graph based on set of edges(links)
        // algorithm based on https://www.programiz.com/dsa/bellman-ford-algorithm
        //how to change rule in flow table? remove then install again
        Collection<Host> hosts = this.getHosts();
        Map<Long, IOFSwitch> switches = this.getSwitches();
        Collection<Link> links = this.getLinks(); //should only consider links between switches
        int hostCount = hosts.size();
        int switchCount = switches.size();
        int linkCount = links.size();
        Long [] switchesArr = switches.keySet().toArray(new Long[switchCount]); //to use index to address switches
        Link [] linkArr = links.toArray(new Link[linkCount]);
        //stores dpid of switches
        //find the switch associated with host
        IOFSwitch srcSwitch = null;
        if (host.isAttachedToSwitch()) {
            srcSwitch = host.getSwitch();
        } else {
            return null;
        }
        // each element correspond to the one in the same position as switchesArr
        int dist[] = new int[switchCount]; // distance of each switch from src switch (in hops)
        int prev[] = new int[switchCount]; // store the index of the previous sw in the shortest path
        int ports[] = new int[switchCount]; // store the dst ports that reach the switches in the paths
        //initiate
        for (int i = 0; i < switchCount; ++i) {
            dist[i] = Integer.MAX_VALUE;
            prev[i] = -1; //prev used for back trace the path
            // in the end the src switch will have prev value -1 so we know its the source
            ports[i] = -1;
        }
        //search switchesArr for index of srcSwitch
        int s = searchArr(srcSwitch, switchesArr, switchCount);

        dist[s] = 0;

        for (int i = 0; i < switchCount; ++i) {
            for (int j = 0; j < linkCount; ++j) {
                //get indices of the src and dst of the link
                long srcId = linkArr[j].getSrc(); //assume getSrc() of Link gets the dpid of a switch
                long dstId = linkArr[j].getDst();
                //if either srcId or dstId is 0, it means that one end of the link is a host, so discard this link.
                if (srcId == 0 || dstId == 0) {
                    continue;
                }
                //need to store the destination ports, since they will be the output port when tracing back to the source host
                int dstPort = linkArr[j].getDstPort();
                IOFSwitch srcSw = switches.get(new Long(srcId));
                IOFSwitch dstSw = switches.get(new Long(dstId));
                int srcIndex = searchArr(srcSw, switchesArr, switchCount);
                int dstIndex = searchArr(dstSw, switchesArr, switchCount);
                if (dist[srcIndex] != Integer.MAX_VALUE && dist[srcIndex] + 1 < dist[dstIndex]) {
                    dist[dstIndex] = dist[srcIndex] + 1;
                    prev[dstIndex] = srcIndex;
                    ports[dstIndex] = dstPort;
                }
            }
        }
        // no need to check negative cycles

        spInfo rtn = new spInfo(dist, prev, switchesArr, ports);

        return rtn;

    }
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }

    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
    private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }

    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
    @Override
    public void deviceAdded(IDevice device)
    {
        Host host = new Host(device, this.floodlightProv);
        // We only care about a new host if we know its IP
        if (host.getIPv4Address() != null)
        {
            log.info(String.format("Host %s added", host.getName()));
            this.knownHosts.put(device, host);

            /*****************************************************************/
            /* TODO: Update routing: add rules to route to new host          */

            installRuleForHost(host);



            /*****************************************************************/
		}
    }

    /**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
    @Override
    public void deviceRemoved(IDevice device)
    {
        Host host = this.knownHosts.get(device);
        if (null == host)
        { return; }
        this.knownHosts.remove(device);

        log.info(String.format("Host %s is no longer attached to a switch",
                host.getName()));

        /*********************************************************************/
        /* TODO: Update routing: remove rules to route to host               */
        removeRuleForHost(host);

        /*********************************************************************/
    }

    /**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
    @Override
    public void deviceMoved(IDevice device)
    {
        Host host = this.knownHosts.get(device);
        if (null == host)
        {
            host = new Host(device, this.floodlightProv);
            this.knownHosts.put(device, host);
        }

        if (!host.isAttachedToSwitch())
        {
            this.deviceRemoved(device);
            return;
        }
        log.info(String.format("Host %s moved to s%d:%d", host.getName(),
                host.getSwitch().getId(), host.getPort()));

        /*********************************************************************/
        /* TODO: Update routing: change rules to route to host               */
        //first delete old rules
        //then recalculate sp and install new rules
        removeRuleForHost(host);
        installRuleForHost(host);

        /*********************************************************************/
    }

    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
    @Override
    public void switchAdded(long switchId)
    {
        IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
        log.info(String.format("Switch s%d added", switchId));

        /*********************************************************************/
        /* TODO: Update routing: change routing rules for all hosts          */
        //basically startup but remove rules first
        Collection<Host> hosts = this.getHosts();
        //Map<Long, IOFSwitch> switches = this.getSwitches();
        //Collection<Link> links = this.getLinks();
        Iterator<Host> it = hosts.iterator();
        while (it.hasNext()) {
            Host h = it.next();
            removeRuleForHost(h);
            installRuleForHost(h);
        }
        /*********************************************************************/
    }

    /**
     * Event handler called when a switch leaves the network.
     * @param DPID for the switch
     */
    @Override
    public void switchRemoved(long switchId)
    {
        IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
        log.info(String.format("Switch s%d removed", switchId));

        /*********************************************************************/
        /* TODO: Update routing: change routing rules for all hosts          */
        Collection<Host> hosts = this.getHosts();
        Iterator<Host> it = hosts.iterator();
        while (it.hasNext()) {
            Host h = it.next();
            removeRuleForHost(h);
            installRuleForHost(h);
        }
        /*********************************************************************/
    }

    /**
     * Event handler called when multiple links go up or down.
     * @param updateList information about the change in each link's state
     */
    @Override
    public void linkDiscoveryUpdate(List<LDUpdate> updateList)
    {
        for (LDUpdate update : updateList)
        {
            // If we only know the switch & port for one end of the link, then
            // the link must be from a switch to a host
            if (0 == update.getDst())
            {
                log.info(String.format("Link s%s:%d -> host updated",
                        update.getSrc(), update.getSrcPort()));
            }
            // Otherwise, the link is between two switches
            else
            {
                log.info(String.format("Link s%s:%d -> s%s:%d updated",
                        update.getSrc(), update.getSrcPort(),
                        update.getDst(), update.getDstPort()));
            }
        }

        /*********************************************************************/
        /* TODO: Update routing: change routing rules for all hosts          */
        Collection<Host> hosts = this.getHosts();
        Iterator<Host> it = hosts.iterator();
        while (it.hasNext()) {
            Host h = it.next();
            removeRuleForHost(h);
            installRuleForHost(h);
        }
        /*********************************************************************/
    }

    /**
     * Event handler called when link goes up or down.
     * @param update information about the change in link state
     */
    @Override
    public void linkDiscoveryUpdate(LDUpdate update)
    { this.linkDiscoveryUpdate(Arrays.asList(update)); }

    /**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
    @Override
    public void deviceIPV4AddrChanged(IDevice device)
    { this.deviceAdded(device); }

    /**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
    @Override
    public void deviceVlanChanged(IDevice device)
    { /* Nothing we need to do, since we're not using VLANs */ }

    /**
     * Event handler called when the controller becomes the master for a switch.
     * @param DPID for the switch
     */
    @Override
    public void switchActivated(long switchId)
    { /* Nothing we need to do, since we're not switching controller roles */ }

    /**
     * Event handler called when some attribute of a switch changes.
     * @param DPID for the switch
     */
    @Override
    public void switchChanged(long switchId)
    { /* Nothing we need to do */ }

    /**
     * Event handler called when a port on a switch goes up or down, or is
     * added or removed.
     * @param DPID for the switch
     * @param port the port on the switch whose status changed
     * @param type the type of status change (up, down, add, remove)
     */
    @Override
    public void switchPortChanged(long switchId, ImmutablePort port,
                                  PortChangeType type)
    { /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

    /**
     * Gets a name for this module.
     * @return name for this module
     */
    @Override
    public String getName()
    { return this.MODULE_NAME; }

    /**
     * Check if events must be passed to another module before this module is
     * notified of the event.
     */
    @Override
    public boolean isCallbackOrderingPrereq(String type, String name)
    { return false; }

    /**
     * Check if events must be passed to another module after this module has
     * been notified of the event.
     */
    @Override
    public boolean isCallbackOrderingPostreq(String type, String name)
    { return false; }

    /**
     * Tell the module system which services we provide.
     */
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices()
    { return null; }

    /**
     * Tell the module system which services we implement.
     */
    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService>
    getServiceImpls()
    { return null; }

    /**
     * Tell the module system which modules we depend on.
     */
    @Override
    public Collection<Class<? extends IFloodlightService>>
    getModuleDependencies()
    {
        Collection<Class<? extends IFloodlightService >> floodlightService =
                new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(ILinkDiscoveryService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
    }
}
