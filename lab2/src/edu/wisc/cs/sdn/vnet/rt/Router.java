package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

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
		/* DONE: Handle packets                                             */
		// check packet type
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// verify checksum
		IPv4 header = (IPv4) etherPacket.getPayload();
		short checksum = header.getChecksum();
		header.resetChecksum();
		byte[] serializedBytes = header.serialize();
		header = (IPv4) header.deserialize(serializedBytes, 0, serializedBytes.length);
		if (checksum != header.getChecksum()) {
			return;
		}

		// verify ttl
		header.setTtl((byte) (header.getTtl() - 1));
		if (header.getTtl() == 0) {
			return;
		}

		// check interfaces
		for (Iface iface : interfaces.values()) {
			if (iface.getIpAddress() == header.getDestinationAddress()) {
				return;
			}
		}

		// forward packets
		RouteEntry routeEntry = routeTable.lookup(header.getDestinationAddress());
		if (routeEntry == null) {
			return;
		}

		if (routeEntry.getInterface().equals(inIface)) {
			return;
		}

		ArpEntry arpEntry;
		if (routeEntry.getGatewayAddress() == 0) {
			arpEntry = arpCache.lookup(header.getDestinationAddress());
		} else {
			arpEntry = arpCache.lookup(routeEntry.getGatewayAddress());
		}

		if (arpEntry == null) {
			return;
		}

		// since TTL changed, checksum needs to be recomputed.
		header.resetChecksum();
		serializedBytes = header.serialize();
		header = (IPv4) header.deserialize(serializedBytes, 0, serializedBytes.length);
		Ethernet nextPacket = (Ethernet) etherPacket.setPayload(header);
		MACAddress destinationMac = arpEntry.getMac();
		MACAddress sourceMac = routeEntry.getInterface().getMacAddress();
		nextPacket.setDestinationMACAddress(destinationMac.toBytes());
		nextPacket.setSourceMACAddress(sourceMac.toBytes());
		sendPacket(nextPacket, routeEntry.getInterface());
		/********************************************************************/
	}
}
