package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device implements Runnable
{
	private static final long TIMEOUT = 15000;
	private final Thread thread;
	private final ConcurrentHashMap<MACAddress, Record> forwardTable;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.forwardTable = new ConcurrentHashMap<>();
		this.thread = new Thread(this);
		this.thread.start();
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

		MACAddress source = etherPacket.getSourceMAC();
		if (forwardTable.containsKey(source)) {
			Record record = forwardTable.get(source);
			record.setIface(inIface);
			record.setExp(System.currentTimeMillis() + TIMEOUT);
			forwardTable.put(source, record);
		} else {
			forwardTable.put(source, new Record(inIface, System.currentTimeMillis() + TIMEOUT));
		}

		MACAddress destination = etherPacket.getDestinationMAC();
		if (forwardTable.containsKey(destination)) {
			sendPacket(etherPacket, forwardTable.get(destination).iface);
		} else {
			for (Iface iface : interfaces.values()) {
				if (!iface.equals(inIface)) {
					sendPacket(etherPacket, iface);
				}
			}
		}

		/********************************************************************/
	}

	@Override
	public void run() {
		while (true) {
			if (forwardTable != null) {
				for (Map.Entry<MACAddress, Record> entry : forwardTable.entrySet()) {
					Record record = entry.getValue();
					if (record.getExp() <= System.currentTimeMillis()) {
						forwardTable.remove(entry.getKey());
					}
				}
			}
			try {
				Thread.sleep(300);
			} catch (InterruptedException e) {
				//
				System.out.println("ERROR: should not come here.");
			}
		}
	}

	private static class Record {
		private Iface iface;
		private long exp;

		public Record() {
		}

		public Record(Iface iface, long exp) {
			this.iface = iface;
			this.exp = exp;
		}

		public Iface getIface() {
			return iface;
		}

		public void setIface(Iface iface) {
			this.iface = iface;
		}

		public long getExp() {
			return exp;
		}

		public void setExp(long exp) {
			this.exp = exp;
		}
	}
}
