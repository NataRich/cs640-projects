package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	private static long ROUTE_ENTRY_EXP = 30000;  // in milliseconds

	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Queue for packets */
	private ConcurrentHashMap<Integer, Queue<EthernetStore>> queueMap;

	/** Map for extended route entries */
	private ConcurrentHashMap<Integer, ExtendedRouteEntry> entryMap;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.queueMap = new ConcurrentHashMap<>();
		this.entryMap = new ConcurrentHashMap<>();
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
	 * Initializes RIP - sends a RIP request to all the interfaces.
	 */
	public void ripInit() {
		System.out.println("Initializing route table");
		for (Iface iface : interfaces.values()) {
			int dest = iface.getIpAddress();
			int mask = iface.getSubnetMask();
			int net = dest & mask;
			ExtendedRouteEntry ere = new ExtendedRouteEntry(dest, mask, 1, dest, -1);
			entryMap.put(net, ere);
			routeTable.insert(dest, 0, mask, iface);
		}
		printRoutes();
		System.out.println("Sending RIP request to all interfaces after initialization");
		for (Iface iface : interfaces.values()) {
			sendPacket(generateRIP(null, iface, RIPType.REQUEST), iface);
		}
		// Send unsolicited RIP responses every 10 seconds
		new Timer(true).schedule(new RipUnsolicitedResponseTask(), 0, 10000);
		// Time out route table entries that have not been updated for 30 seconds
		new Timer(true).schedule(new RouteTableTimeOutTask(), 0, 1000);  // check every second
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
			IPv4 ip = (IPv4) etherPacket.getPayload();
			if (ip.getProtocol() == IPv4.PROTOCOL_UDP) {
				if (ip.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")
						|| ip.getDestinationAddress() == inIface.getIpAddress()) {
					UDP udp = (UDP) ip.getPayload();
					if (udp.getDestinationPort() == UDP.RIP_PORT) {
						RIPv2 rip = (RIPv2) udp.getPayload();
						this.handleRipPacket(etherPacket, inIface, rip.getCommand());
						break;
					}
				}
			}
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}


	private void handleRipPacket(Ethernet ethernet, Iface inIface, byte type) {
		if (type == RIPv2.COMMAND_REQUEST) {
			System.out.println("Handling a RIP request / sending an RIP response");
			sendPacket(generateRIP(ethernet, inIface, RIPType.RESPONSE), inIface);
		} else if (type == RIPv2.COMMAND_RESPONSE) {
			System.out.println("Handling a RIP response / updating route table as needed");
			IPv4 ip = (IPv4) ethernet.getPayload();
			UDP udp = (UDP) ip.getPayload();
			RIPv2 rip = (RIPv2) udp.getPayload();
			boolean updated = false;

			// the neighbors of the router who sends this packet
			for (RIPv2Entry entry : rip.getEntries()) {
				int dest = entry.getAddress();
				int mask = entry.getSubnetMask();
				int cost = entry.getMetric() + 1;
				int net = dest & mask;
				if (entryMap.containsKey(net)) {
					ExtendedRouteEntry ere = entryMap.get(net);
					if (ere.cost > cost) {
						System.out.println("Before update: " + ere);
						ere.expireAt = System.currentTimeMillis() + ROUTE_ENTRY_EXP;
						ere.cost = cost;
						ere.nextHop = ip.getSourceAddress();
						System.out.println("After update: " + ere);
						this.routeTable.update(dest, mask, ip.getSourceAddress(), inIface);
						updated = true;
					} else if (ere.cost == cost) { // update timestamps when ere.cost == cost
						ere.expireAt = System.currentTimeMillis() + ROUTE_ENTRY_EXP;
					}
				} else {
					long exp = System.currentTimeMillis() + ROUTE_ENTRY_EXP;
					ExtendedRouteEntry ere = new ExtendedRouteEntry(dest, mask, cost, ip.getSourceAddress(), exp);
					System.out.println("Insert: " + ere);
					entryMap.put(net, ere);
					this.routeTable.insert(dest, ip.getSourceAddress(), mask, inIface);
					updated = true;
				}
			}

			if (updated) {
				System.out.println("Routes updated");
				printRoutes();
				sendPacket(generateRIP(ethernet, inIface, RIPType.RESPONSE), inIface);
			}
		}
	}

	/**
	 * Sends an ARP reply if an ARP request was received and its target ip address was equal to the
	 * ip address of the current interface. Saves the source MAC address with the corresponding ip
	 * address in the arpCache and sends all the packets queued with this ip address (then clear the
	 * queue).
	 *
	 * @param etherPacket The packet received.
	 * @param inIface The interface that received the packet.
	 */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		ARP packet = (ARP) etherPacket.getPayload();
		if (packet.getOpCode() == ARP.OP_REQUEST) {
			System.out.println("Handling an ARP request packet / sending an ARP reply");
			int targetIp = ByteBuffer.wrap(packet.getTargetProtocolAddress()).getInt();
			if (targetIp == inIface.getIpAddress()) {
				sendPacket(generateArpReply(etherPacket, inIface), inIface);
			}
		} else if (packet.getOpCode() == ARP.OP_REPLY) {
			System.out.println("Handling an ARP reply packet / updating arpCache");
			int sourceIp = ByteBuffer.wrap(packet.getSenderProtocolAddress()).getInt();
			arpCache.insert(new MACAddress(packet.getSenderHardwareAddress()), sourceIp);
			if (queueMap.containsKey(sourceIp)) {
				System.out.println("Dequeue packets of " + IPv4.fromIPv4Address(sourceIp));
				Queue<EthernetStore> queue = queueMap.remove(sourceIp);
				int sent = 0;
				while (queue != null && !queue.isEmpty()) {
					sent++;
					EthernetStore s = queue.poll();
					s.ether.setDestinationMACAddress(packet.getSenderHardwareAddress());
					sendPacket(s.ether, inIface);
				}
				System.out.println("Sent " + sent + " queued packets");
			}
		}
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
        if (0 == ipPacket.getTtl())
        {
			// time exceeded message
			Ethernet timeExceeded = generateICMP(etherPacket, inIface, ICMPType.TIME_EXCEEDED);
			if (timeExceeded != null) {
				this.sendPacket(timeExceeded, inIface);
			}
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
					// destination port unreachable message
					Ethernet portUnreachable = generateICMP(etherPacket, inIface, ICMPType.PORT_UNREACHABLE);
					if (portUnreachable != null) {
						this.sendPacket(portUnreachable, inIface);
					}
					return;
				} else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP) ipPacket.getPayload();
					if (icmpPacket.getIcmpType() == 8) {
						// echo reply message
						Ethernet echo = generateICMP(etherPacket, inIface, ICMPType.ECHO_REPLY);
						if (echo != null) {
							this.sendPacket(echo, inIface);
						}
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

        // If no entry matched, do nothing
        if (null == bestMatch)
        {
			Ethernet netUnreachable = generateICMP(etherPacket, inIface, ICMPType.NET_UNREACHABLE);
			if (netUnreachable != null) {
				sendPacket(netUnreachable, inIface);
			}
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
			// Change from ICMP host unreachable to ARP request
//			Ethernet hostUnreachable = generateICMP(etherPacket, inIface, ICMPType.HOST_UNREACHABLE);
//			if (hostUnreachable != null) {
//				sendPacket(hostUnreachable, inIface);
//			}
			enqueuePacket(etherPacket, outIface, nextHop);
			new Timer(true).schedule(new ArpRequestTask(nextHop, outIface), 0, 1000);
			return;
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

	/**
	 * Generates a fully constructed ICMP packet.
	 *
	 * @param oldEther The received Ethernet packet.
	 * @param inIface The interface that received the packet.
	 * @param type The type of the ICMP message.
	 * @return the new Ethernet packet if successful, null otherwise.
	 */
	private Ethernet generateICMP(Ethernet oldEther, Iface inIface, ICMPType type) {
		System.out.println("Trying to generate a " + type + " message");
		// First, check if tables have the desired entries
		IPv4 oldIp = (IPv4) oldEther.getPayload();
		RouteEntry re = routeTable.lookup(oldIp.getSourceAddress());
		if (re == null) {
			System.out.println(type + " message construction failed due to null route entry");
			return null;
		}
		ArpEntry ae;
		if (re.getGatewayAddress() != 0) {
			ae = arpCache.lookup(re.getGatewayAddress());
		} else {
			ae = arpCache.lookup(oldIp.getSourceAddress());
		}
		if (ae == null) {
			System.out.println(type + " message construction failed due to null arp entry");
			return null;
		}

		// Then, construct new ICMP packet if the tables have the desired values
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();

		// Set new Ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(ae.getMac().toBytes());

		// Set new IP header
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		if (type == ICMPType.ECHO_REPLY) {
			ip.setSourceAddress(oldIp.getDestinationAddress());
		} else {
			ip.setSourceAddress(inIface.getIpAddress());
		}
		ip.setDestinationAddress(oldIp.getSourceAddress());

		// Set ICMP header
		switch (type) {
			case TIME_EXCEEDED:
				icmp.setIcmpType((byte) 11);
				icmp.setIcmpCode((byte) 0);
				break;
			case NET_UNREACHABLE:
				icmp.setIcmpType((byte) 3);
				icmp.setIcmpCode((byte) 0);
				break;
			case HOST_UNREACHABLE:
				icmp.setIcmpType((byte) 3);
				icmp.setIcmpCode((byte) 1);
				break;
			case PORT_UNREACHABLE:
				icmp.setIcmpType((byte) 3);
				icmp.setIcmpCode((byte) 3);
				break;
			case ECHO_REPLY:
				icmp.setIcmpType((byte) 0);
				icmp.setIcmpCode((byte) 0);
				break;
			default:
				return null;
		}

		// Set Data header
		if (type == ICMPType.ECHO_REPLY) {
			data = (Data) oldIp.getPayload().getPayload();
		} else {
			//4 byte padding + orig IP header + following 8 bytes of the orig IP header
			//assume the padding is full of zeros
			//serialize IP and take part of it
			byte[] serializedIP = oldIp.serialize();
			int headerLen = 4 * oldIp.getHeaderLength();
			byte[] dt = new byte[4 + headerLen + 8];
			for (int i = 4; i < dt.length; i++) {
				dt[i] = serializedIP[i - 4];
			}
			data.setData(dt);
		}

		icmp.setPayload(data);
		ip.setPayload(icmp);
		ether.setPayload(ip);

		System.out.println("Successfully generated a " + type + " message");
		return ether;
	}

	/**
	 * Generates a fully constructed ARP reply.
	 *
	 * @param ethernet The received ARP request.
	 * @param inIface The interface that received the ARP request.
	 * @return An instance of Ethernet whose payload is an ARP reply packet.
	 */
	private Ethernet generateArpReply(Ethernet ethernet, Iface inIface) {
		System.out.println("Generating an ARP reply");
		Ethernet replyEther = new Ethernet();
		ARP requestArp = (ARP) ethernet.getPayload();
		ARP replyArp = new ARP();

		// Populate Ethernet header
		replyEther.setEtherType(Ethernet.TYPE_ARP);
		replyEther.setSourceMACAddress(inIface.getMacAddress().toBytes());
		replyEther.setDestinationMACAddress(ethernet.getSourceMACAddress());

		// Populate ARP header
		replyArp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		replyArp.setProtocolType(ARP.PROTO_TYPE_IP);
		replyArp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		replyArp.setProtocolAddressLength((byte) 4);
		replyArp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		replyArp.setSenderProtocolAddress(inIface.getIpAddress());
		replyArp.setOpCode(ARP.OP_REPLY);
		replyArp.setTargetHardwareAddress(requestArp.getSenderHardwareAddress());
		replyArp.setTargetProtocolAddress(requestArp.getSenderProtocolAddress());

		// Set ARP as Ethernet payload
		replyEther.setPayload(replyArp);
		return replyEther;
	}

	/**
	 * Generates a fully constructed ARP request.
	 *
	 * @param inIface The interface that received the ARP request.
	 * @param nextHop The ip address of the host whose MAC address is desired.
	 * @return An instance of Ethernet whose payload is an ARP request packet.
	 */
	private Ethernet generateArpRequest(Iface inIface, int nextHop) {
		System.out.println("Generating an ARP request");
		Ethernet replyEther = new Ethernet();
		ARP replyPacket = new ARP();
		byte[] BROADCAST_MAC = new byte[6];
		byte[] ZERO_MAC = new byte[6];
		Arrays.fill(BROADCAST_MAC, (byte) 0xff);
		Arrays.fill(ZERO_MAC, (byte) 0);

		// Populate Ethernet header
		replyEther.setEtherType(Ethernet.TYPE_ARP);
		replyEther.setSourceMACAddress(inIface.getMacAddress().toBytes());
		replyEther.setDestinationMACAddress(BROADCAST_MAC);

		// Populate ARP header
		replyPacket.setHardwareType(ARP.HW_TYPE_ETHERNET);
		replyPacket.setProtocolType(ARP.PROTO_TYPE_IP);
		replyPacket.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		replyPacket.setProtocolAddressLength((byte) 4);
		replyPacket.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		replyPacket.setSenderProtocolAddress(inIface.getIpAddress());
		replyPacket.setOpCode(ARP.OP_REQUEST);
		replyPacket.setTargetHardwareAddress(ZERO_MAC);
		replyPacket.setTargetProtocolAddress(nextHop);

		// Set ARP as Ethernet payload
		replyEther.setPayload(replyPacket);
		return replyEther;
	}

	/**
	 * Generates a fully constructed RIP request or response.
	 *
	 * @param ethernet The Ethernet packet received.
	 * @param inIface The interface that received the Ethernet packet.
	 * @param type The type of reply packet.
	 * @return An instance of Ethernet whose payload is a RIP request or response.
	 */
	private Ethernet generateRIP(Ethernet ethernet, Iface inIface, RIPType type) {
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		// Populate Ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		// Populate IP (UDP) header
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setTtl((byte) 64);
		ip.setSourceAddress(inIface.getIpAddress());

		// Populate UDP header
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		switch (type) {
			case REQUEST:
				ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
				ip.setDestinationAddress("224.0.0.9");
				rip.setCommand(RIPv2.COMMAND_REQUEST);
				break;
			case UNSOLICITED:
				ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
				ip.setDestinationAddress("224.0.0.9");
				rip.setCommand(RIPv2.COMMAND_RESPONSE);
				break;
			case RESPONSE:
				IPv4 oldIp = (IPv4) ethernet.getPayload();
				ether.setDestinationMACAddress(ethernet.getSourceMACAddress());
				ip.setDestinationAddress(oldIp.getSourceAddress());
				rip.setCommand(RIPv2.COMMAND_RESPONSE);
				break;
			default:
				return null;
		}

		// Populate my neighbors
		for (ExtendedRouteEntry entry : this.entryMap.values()) {
			rip.addEntry(new RIPv2Entry(entry.dest , entry.mask, entry.cost));
		}
		udp.setPayload(rip);
		ip.setPayload(udp);
		ether.setPayload(ip);

		return ether;
	}

	/**
	 * Enqueues the packets whose MAC address is not yet found.
	 *
	 * @param ether The Ethernet packet to be forwarded.
	 * @param nextHop The ip address of the packet.
	 */
	private void enqueuePacket(Ethernet ether, Iface inIface, int nextHop) {
		System.out.println("Enqueuing " + IPv4.fromIPv4Address(nextHop) + "'s packets");
		Queue<EthernetStore> queue = queueMap.get(nextHop);
		if (queue == null) {
			queue = new ConcurrentLinkedQueue<>();
			Queue<EthernetStore> newQueue = queueMap.putIfAbsent(nextHop, queue);
			if (newQueue == null) {
				queue = queueMap.get(nextHop);
			}
		}
		queue.add(new EthernetStore(ether, inIface));
	}

	public enum ICMPType {
		/** when TTL = 0 */
		TIME_EXCEEDED,

		/** when route entry is not found */
		NET_UNREACHABLE,

		/** when arp entry is not found */
		HOST_UNREACHABLE,

		/** when TCP/UDP comes after IP */
		PORT_UNREACHABLE,

		/** when an echo request ICMP message comes after IP */
		ECHO_REPLY
	}

	public enum RIPType {
		REQUEST,
		RESPONSE,
		UNSOLICITED
	}

	public class EthernetStore {
		/** IP packet whose destination MAC address cannot be found in arpCache */
		public Ethernet ether;

		/** The interface obtained by route table lookup */
		public Iface inIface;

		public EthernetStore(Ethernet ether, Iface inIface) {
			this.ether = ether;
			this.inIface = inIface;
		}
	}

	public class ExtendedRouteEntry {
		private int dest;
		private int mask;
		private int cost;
		private int nextHop;
		private long expireAt;

		public ExtendedRouteEntry(int dest, int mask, int cost, int nextHop, long expireAt) {
			this.dest = dest;
			this.mask = mask;
			this.cost = cost;
			this.nextHop = nextHop;
			this.expireAt = expireAt;
		}

		private int formatExp(long exp) {
			return exp < 0 ? -1 : (int) ((exp - System.currentTimeMillis()) / 1000);
		}

		@Override
		public String toString() {
			return "ExtendedRouteEntry{" +
					"dest=" + IPv4.fromIPv4Address(dest) +
					", mask=" + IPv4.fromIPv4Address(mask) +
					", cost=" + cost +
					", nextHop=" + IPv4.fromIPv4Address(nextHop) +
					", expireAt=" + formatExp(expireAt) +
					'}';
		}
	}

	public class ArpRequestTask extends TimerTask {
		public int count;
		public final int nextHop;
		public final Iface outIface;

		public ArpRequestTask(int nextHop, Iface outIface) {
			this.count = 0;
			this.nextHop = nextHop;
			this.outIface = outIface;
		}

		@Override
		public void run() {
			if (queueMap.containsKey(nextHop)) {
				if (count >= 3) {
					System.out.println("No response after 3 times. Dropping packets of " + IPv4.fromIPv4Address(nextHop));
					// drop all packets associated with the ip
					Queue<EthernetStore> queue = queueMap.remove(nextHop);
					int n = 0;
					while (queue != null && !queue.isEmpty()) {
						EthernetStore s = queue.poll();
						Ethernet hostUnreachable = generateICMP(s.ether, s.inIface, ICMPType.HOST_UNREACHABLE);
						if (hostUnreachable != null) {
							System.out.println("Sending host unreachable message back before dropping: " + ++n);
							sendPacket(hostUnreachable, s.inIface);
						}
					}
					cancel();
				} else {
					count++;
					System.out.printf("Sending (%d) ARP request [%s] to the interface on which it arrived\n", count, IPv4.fromIPv4Address(nextHop));
					sendPacket(generateArpRequest(outIface, nextHop), outIface);
				}
			} else {
				if (arpCache.lookup(nextHop) != null) {
					System.out.println("Should have received an ARP reply because arp cache has the record");
				} else {
					System.out.println("Should have received no ARP replies because both arp cache and queue map don't have the record anymore");
				}
				cancel();
			}
		}
	}

	public class RipUnsolicitedResponseTask extends TimerTask {
		@Override
		public void run() {
			System.out.println("Sending unsolicited RIP responses to all interfaces every 10 seconds");
			for (Iface iface : interfaces.values()) {
				sendPacket(generateRIP(null, iface, RIPType.UNSOLICITED), iface);
			}
		}
	}

	public class RouteTableTimeOutTask extends TimerTask {
		@Override
		public void run() {
			for (ExtendedRouteEntry ere : entryMap.values()) {
				if (ere.expireAt != -1 && ere.expireAt <= System.currentTimeMillis()) {
					System.out.println("Removing " + ere + " due to timeout");
					entryMap.remove(ere.dest & ere.mask);
					routeTable.remove(ere.dest, ere.mask);
				}
			}
		}
	}

	private void printRoutes() {
		String output = "\nEntryMap:\n";
		for (Map.Entry<Integer, ExtendedRouteEntry> entry : entryMap.entrySet()) {
			output += "{" + IPv4.fromIPv4Address(entry.getKey()) + ": " + entry.getValue() + "}\n";
		}
		output += "\nRouteTable:\n";
		output += this.routeTable.toString();
		System.out.println(output);
	}
}
