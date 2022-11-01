package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl()) //send time exceeded message1
        { 
			Ethernet ether = new Ethernet();
            
			ether.setEtherType(Ethernet.TYPE_IPv4);
			//find the MACaddr of the interface of packet arrival
			int srcIP = ipPacket.getSourceAddress();
            RouteEntry entry1 = this.routeTable.lookup(srcIP);
            Iface outIface = entry1.getInterface();
			ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
            //Destination MAC, which is of where the packet comes from			
			int nextHop = entry1.getGatewayAddress();
        	if (0 == nextHop)
        		{ nextHop = srcIP; }

        	// Set destination MAC address in Ethernet header
        	ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        	if (null == arpEntry)
        		{ return; }
        	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
			
			IPv4 ip = new IPv4();
			//set something
			ip.setTtl((byte) 64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(outIface.getIpAddress());
			ip.setDestinationAddress(srcIP);
			ICMP icmp = new ICMP();
			//set something
			icmp.setIcmpType((byte) 11);
			icmp.setIcmpCode((byte) 0);
			Data data = new Data();
			//4 byte padding + orig IP header + following 8 bytes of the orig IP header
			//assume the padding is full of zeros
			//serialize IP and take part of it
			
			byte[] serializedIP = ipPacket.serialize();
			byte headerLen = 4 * ipPacket.getHeaderLength();			
			byte[] dt = new byte[4+headerLen+8];
            for (int i = 4; i < dt.length; i++) {
				dt[i] = serializedIP[i-4];
			}
			data.setData(dt);

			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);
			//send it
			this.sendPacket(ether, outIface);
			return; 
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP || ipPacket.getProtocol() == IPv4.PROTOCOL_TCP) {
					Ethernet ether = new Ethernet();
					ether.setEtherType(Ethernet.TYPE_IPv4);
			
					int srcIP = ipPacket.getSourceAddress();
            		RouteEntry entry1 = this.routeTable.lookup(srcIP);
            		Iface outIface = entry1.getInterface();
					ether.setSourceMACAddress(outIface.getMacAddress().toBytes());           			
					int nextHop = entry1.getGatewayAddress();
        			if (0 == nextHop)
        				{ nextHop = srcIP; }
        			ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        			if (null == arpEntry)
        				{ return; }
        			ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
					IPv4 ip = new IPv4();			
					ip.setTtl((byte) 64);
					ip.setProtocol(IPv4.PROTOCOL_ICMP);
					ip.setSourceAddress(outIface.getIpAddress());
					ip.setDestinationAddress(srcIP);
					ICMP icmp = new ICMP();			
					icmp.setIcmpType((byte) 3);//type: 3
					icmp.setIcmpCode((byte) 0);
					Data data = new Data();
					byte[] serializedIP = ipPacket.serialize();
					byte headerLen = 4 * ipPacket.getHeaderLength();			
					byte[] dt = new byte[4+headerLen+8];
            		for (int i = 4; i < dt.length; i++) {
						dt[i] = serializedIP[i-4];
					}
					data.setData(dt);
					ether.setPayload(ip);
					ip.setPayload(icmp);
					icmp.setPayload(data);
					this.sendPacket(ether, outIface);
					return;
				} else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP)ipPacket.getPayload();
					if (icmpPacket.getIcmpType == 8) {
						//echo
						Ethernet ether = new Ethernet();
            
						ether.setEtherType(Ethernet.TYPE_IPv4);
						//find the MACaddr of the interface of packet arrival
						int srcIP = ipPacket.getSourceAddress();
						RouteEntry entry1 = this.routeTable.lookup(srcIP);
						Iface outIface = entry1.getInterface();
						ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
						//Destination MAC, which is of where the packet comes from			
						int nextHop = entry1.getGatewayAddress();
						if (0 == nextHop)
							{ nextHop = srcIP; }

						// Set destination MAC address in Ethernet header
						ArpEntry arpEntry = this.arpCache.lookup(nextHop);
						if (null == arpEntry)
							{ return; }
						ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
						
						IPv4 ip = new IPv4();
						//set something
						ip.setTtl((byte) 64);
						ip.setProtocol(IPv4.PROTOCOL_ICMP);
						ip.setSourceAddress(ipPacket.getDestinationAddress());//different from time exceeded
						ip.setDestinationAddress(srcIP);
						ICMP icmp = new ICMP();
						//set something
						icmp.setIcmpType((byte) 0);
						icmp.setIcmpCode((byte) 0);
						//different payload: entire payload from original ICMP header
						Data data = (Data) icmpPacket.getPayload();
						
						ether.setPayload(ip);
						ip.setPayload(icmp);
						icmp.setPayload(data);
						//send it
						this.sendPacket(ether, outIface);
						return; //do we need this line of return?
					} else {
						return;
					}
				}
				
				 
			}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, ICMP destination net unreachable 
        if (null == bestMatch)
        { 
			//copy and paste from TTL part code
			Ethernet ether = new Ethernet();
			ether.setEtherType(Ethernet.TYPE_IPv4);
			
			int srcIP = ipPacket.getSourceAddress();
            RouteEntry entry1 = this.routeTable.lookup(srcIP);
            Iface outIface = entry1.getInterface();
			ether.setSourceMACAddress(outIface.getMacAddress().toBytes());           			
			int nextHop = entry1.getGatewayAddress();
        	if (0 == nextHop)
        		{ nextHop = srcIP; }
        	ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        	if (null == arpEntry)
        		{ return; }
        	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
			IPv4 ip = new IPv4();			
			ip.setTtl((byte) 64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(outIface.getIpAddress());
			ip.setDestinationAddress(srcIP);
			ICMP icmp = new ICMP();			
			icmp.setIcmpType((byte) 3);//type: 3
			icmp.setIcmpCode((byte) 0);
			Data data = new Data();
			byte[] serializedIP = ipPacket.serialize();
			byte headerLen = 4 * ipPacket.getHeaderLength();			
			byte[] dt = new byte[4+headerLen+8];
            for (int i = 4; i < dt.length; i++) {
				dt[i] = serializedIP[i-4];
			}
			data.setData(dt);
			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);
			this.sendPacket(ether, outIface);
			return; 
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { 
			Ethernet ether = new Ethernet();
			ether.setEtherType(Ethernet.TYPE_IPv4);
			
			int srcIP = ipPacket.getSourceAddress();
            RouteEntry entry1 = this.routeTable.lookup(srcIP);
            Iface outIface = entry1.getInterface();
			ether.setSourceMACAddress(outIface.getMacAddress().toBytes());           			
			int nextHop = entry1.getGatewayAddress();
        	if (0 == nextHop)
        		{ nextHop = srcIP; }
        	ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        	if (null == arpEntry)
        		{ return; }
        	ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
			IPv4 ip = new IPv4();			
			ip.setTtl((byte) 64);
			ip.setProtocol(IPv4.PROTOCOL_ICMP);
			ip.setSourceAddress(outIface.getIpAddress());
			ip.setDestinationAddress(srcIP);
			ICMP icmp = new ICMP();			
			icmp.setIcmpType((byte) 3);//type: 3
			icmp.setIcmpCode((byte) 1);
			Data data = new Data();
			byte[] serializedIP = ipPacket.serialize();
			byte headerLen = 4 * ipPacket.getHeaderLength();			
			byte[] dt = new byte[4+headerLen+8];
            for (int i = 4; i < dt.length; i++) {
				dt[i] = serializedIP[i-4];
			}
			data.setData(dt);
			ether.setPayload(ip);
			ip.setPayload(icmp);
			icmp.setPayload(data);
			this.sendPacket(ether, outIface);
			return; 
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
}
