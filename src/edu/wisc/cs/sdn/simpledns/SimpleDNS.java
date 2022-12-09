package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.DNS;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

public class SimpleDNS {
	public static final int BUFFER_SIZE = 2048;
	public static final int SERVER_PORT = 8053;

	public static void main(String[] args) throws IOException {
		String rootServerIp = null;
		String ec2Path = null;

		for (int i = 0; i < args.length; i++) {
			if ("-r".equals(args[i]) && i != args.length - 1) {
				rootServerIp = args[i + 1];
			} else if ("-e".equals(args[i]) && i != args.length - 1) {
				ec2Path = args[i + 1];
			}
		}

		if (rootServerIp == null || ec2Path == null) {
			System.out.println("Usage: java SimpleDNS.java -r <rootServerIp> -e <csvPath>");
			System.exit(-1);
		}

		System.out.println("Received: root server ip = " + rootServerIp);
		System.out.println("Received: ec2 csv path = " + ec2Path);

		start(rootServerIp);
	}

	public static void start(String rootServerIp) throws IOException {
		SocketManager manager = new SocketManager(BUFFER_SIZE, SERVER_PORT);
		DatagramPacket received = manager.receive();
		DNS query = DNS.deserialize(received.getData(), received.getLength());
		DNS result = lookup(manager, query, rootServerIp);
		manager.send(result.serialize(), received.getAddress(), received.getPort());
	}

	public static DNS lookup(SocketManager manager, DNS query, String hostName) throws IOException {
		byte[] data = query.serialize();
		manager.send(data, hostName, 53);
		DatagramPacket received = manager.receive();
		return DNS.deserialize(received.getData(), received.getLength());
	}

	/**
	 * Manages socket operations.
	 */
	public static class SocketManager {
		/**
		 * Size of the buffer when receiving UDP packets.
		 */
		private final int bufferSize;

		/**
		 * Socket established for UDP communication.
		 */
		private final DatagramSocket socket;

		public SocketManager(int bufferSize, int listenPort) throws SocketException {
			this.bufferSize = bufferSize;
			this.socket = new DatagramSocket(listenPort);
		}

		public SocketManager(int bufferSize) throws SocketException {
			this(bufferSize, 0);
		}

		/**
		 * Listens the port specified while establishing the socket and returns the received data.
		 *
		 * @return An instance of {@link DatagramPacket}.
		 * @throws IOException {@link DatagramSocket#receive(DatagramPacket)}.
		 */
		public DatagramPacket receive() throws IOException {
			byte[] buffer = new byte[bufferSize];
			DatagramPacket packet = new DatagramPacket(buffer, bufferSize);
			socket.receive(packet);
			return packet;
		}

		/**
		 * Sends the data to the given host on the given port.
		 *
		 * @param data The data to send.
		 * @param host The host to send to.
		 * @param port The port on the host.
		 * @throws IOException {@link DatagramSocket#send(DatagramPacket)}.
		 */
		public void send(byte[] data, InetAddress host, int port) throws IOException {
			DatagramPacket packet = new DatagramPacket(data, data.length, host, port);
			socket.send(packet);
		}

		/**
		 * Sends the data to the given host on the given port.
		 *
		 * @param data The data to send.
		 * @param hostName The host to send to in the form of IPv4 string.
		 * @param port The port on the host.
		 * @throws IOException {@link DatagramSocket#send(DatagramPacket)}.
		 */
		public void send(byte[] data, String hostName, int port) throws IOException {
			send(data, InetAddress.getByName(hostName), port);
		}
	}
}
