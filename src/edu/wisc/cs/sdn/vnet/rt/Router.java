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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Queue;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Queue for packets */
	private ConcurrentHashMap<Integer, Queue<EthernetStore>> queueMap;

	private Timer timer;
	
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
		this.timer = new Timer();
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
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
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
				System.out.println("Done sending ARP reply");
			}
		} else if (packet.getOpCode() == ARP.OP_REPLY) {
			System.out.println("Handling an ARP reply packet / updating arpCache");
			int sourceIp = ByteBuffer.wrap(packet.getSenderProtocolAddress()).getInt();
			arpCache.insert(new MACAddress(packet.getSenderHardwareAddress()), sourceIp);
			if (queueMap.containsKey(sourceIp)) {
				System.out.printf("First time found IP (%s)", sourceIp);
				Queue<EthernetStore> queue = queueMap.remove(sourceIp);
				while (queue != null && !queue.isEmpty()) {
					EthernetStore s = queue.poll();
					s.ether.setDestinationMACAddress(packet.getSenderHardwareAddress());
					sendPacket(s.ether, inIface);
				}
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
			System.out.println("Start broadcasting ARP requests");
			TimerTask task = new ArpRequestTask(nextHop, outIface);
			timer.schedule(task, 0, 1000);
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
	 * Enqueues the packets whose MAC address is not yet found.
	 *
	 * @param ether The Ethernet packet to be forwarded.
	 * @param nextHop The ip address of the packet.
	 */
	private void enqueuePacket(Ethernet ether, Iface inIface, int nextHop) {
		System.out.println("Putting " + nextHop + "'s packets in queue");
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

	public class EthernetStore {
		public Ethernet ether;
		public Iface inIface;

		public EthernetStore(Ethernet ether, Iface inIface) {
			this.ether = ether;
			this.inIface = inIface;
		}
	}

	public class ArpRequestTask extends TimerTask {
		public int count;
		public final int nextHop;
		public final Iface outIface;

		public int runtime = 0;

		public ArpRequestTask(int nextHop, Iface outIface) {
			this.count = 0;
			this.nextHop = nextHop;
			this.outIface = outIface;
		}

		@Override
		public void run() {
			System.out.println("runtime = " + ++runtime);

			if (queueMap.containsKey(nextHop)) {
				if (count >= 3) {
					System.out.printf("No response after 3 times. Dropping packets associated with %d\n", nextHop);
					// drop all packets associated with the ip
					Queue<EthernetStore> queue = queueMap.remove(nextHop);
					int n = 0;
					while (queue != null && !queue.isEmpty()) {
						System.out.println("Queue not empty");
						EthernetStore s = queue.poll();
						Ethernet hostUnreachable = generateICMP(s.ether, s.inIface, ICMPType.HOST_UNREACHABLE);
						if (hostUnreachable != null) {
							System.out.println("Sending host unreachable ICMP message back: " + ++n);
							sendPacket(hostUnreachable, s.inIface);
						}
					}
					cancel();
				} else {
					count++;
					System.out.printf("Broadcasting (%d) ARP request associated with %d\n", count, nextHop);
					sendPacket(generateArpRequest(outIface, nextHop), outIface);
				}
			} else {
				cancel();
			}
		}
	}
}
