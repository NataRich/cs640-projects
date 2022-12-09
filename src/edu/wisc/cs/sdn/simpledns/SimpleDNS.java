package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.List;

// TODO: additional & authority section
// TODO: EC2 txt
public class SimpleDNS {
	public static final int BUFFER_SIZE = 2048;
	public static final int SERVER_PORT = 8053;
	public static final int DNS_PORT = 53;

	public static String rootNameServerIP = null;
	public static String ec2CsvPath = null;

	public static void main(String[] args) throws IOException {
		for (int i = 0; i < args.length; i++) {
			if ("-r".equals(args[i]) && i != args.length - 1) {
				rootNameServerIP = args[i + 1];
			} else if ("-e".equals(args[i]) && i != args.length - 1) {
				ec2CsvPath = args[i + 1];
			}
		}

		if (rootNameServerIP == null || ec2CsvPath == null) {
			System.out.println("Usage: java SimpleDNS.java -r <rootServerIp> -e <csvPath>");
			System.exit(-1);
		}

		start();
	}

	public static void start() throws SocketException {
		SocketManager manager = new SocketManager(BUFFER_SIZE, SERVER_PORT);

		do {
			try {
				DatagramPacket received = manager.receive();
				DNS rootQuery = DNS.deserialize(received.getData(), received.getLength());
				if (!support(rootQuery)) {
					continue;
				}

				DNS response;
				if (rootQuery.isRecursionDesired()) {
					response = recursiveLookup(manager, rootQuery, rootNameServerIP);
					while (!satisfy(rootQuery, response)) {
						response = resolve(manager, rootQuery, response, rootNameServerIP);
					}
				} else {
					response = lookup(manager, rootQuery, rootNameServerIP);
				}
				System.out.println(response);
				manager.send(response.serialize(), received.getAddress(), received.getPort());
			} catch (IOException ex) {
				System.out.println("DEBUG: an error occurred");
				break;
			}
		} while (true);
	}

	public static DNS lookup(SocketManager manager, DNS query, String hostName) throws IOException {
		manager.send(query.serialize(), hostName, DNS_PORT);
		DatagramPacket received = manager.receive();
		return DNS.deserialize(received.getData(), received.getLength());
	}

	public static DNS recursiveLookup(SocketManager manager, DNS query, String hostName) throws IOException {
		DNS response = lookup(manager, query, hostName);
		if (response.getAnswers().isEmpty()) {
			for (DNSResourceRecord authorityRecord : response.getAuthorities()) {
				String nextHostName = authorityRecord.getData().toString();
				System.out.println("Found next host: " + nextHostName);
				return recursiveLookup(manager, query, nextHostName);
			}
		}
		return response;
	}

	public static DNS resolve(SocketManager manager, DNS query, DNS response, String hostName) throws IOException {
		DNS clonedResponse = clone(response);
		for (DNSResourceRecord answer : response.getAnswers()) {
			if (answer.getType() == DNS.TYPE_CNAME) {
				DNSQuestion q = new DNSQuestion(answer.getData().toString(), DNS.TYPE_A);
				DNS clonedQuery = clone(query);
				clonedQuery.setQuestions(List.of(q));
				DNS resp = recursiveLookup(manager, clonedQuery, hostName);

				boolean duplicate = false;
				for (DNSResourceRecord r1 : resp.getAnswers()) {
					for (DNSResourceRecord r2 : clonedResponse.getAnswers()) {
						if (r1.getName().equals(r2.getName())) {
							duplicate = true;
							break;
						}
					}
					if (!duplicate) {
						clonedResponse.getAnswers().add(r1);
					}
				}
			}
		}
		return clonedResponse;
	}

	/**
	 * Checks if the DNS query question is supported.
	 *
	 * @param query The DNS query to check.
	 * @return {@code true} if the query has opcode 0 and a record type of A, AAAA, CNAME, or NS;
	 * false, otherwise
	 */
	private static boolean support(DNS query) {
		if (query.getOpcode() != DNS.OPCODE_STANDARD_QUERY) {
			return false;
		}
		if (query.getQuestions().isEmpty()) {
			return false;
		}
		switch (query.getQuestions().get(0).getType()) {
			case DNS.TYPE_A:
			case DNS.TYPE_AAAA:
			case DNS.TYPE_CNAME:
			case DNS.TYPE_NS:
				return true;
			default:
				return false;
		}
	}

	/**
	 * Checks if the DNS response satisfies the DNS query, i.e., whether CNAME resolution is needed.
	 *
	 * @param query The query to check.
	 * @param response The response to be checked against.
	 * @return {@code false} if the query has a type of A or AAAA but the response doesn't have a
	 * corresponding answer; {@code true}, otherwise.
	 */
	private static boolean satisfy(DNS query, DNS response) {
		if (query.getQuestions().isEmpty()) {
			return true;
		}
		if (response.getAnswers().isEmpty()) {
			throw new RuntimeException("No answers found");
		}
		DNSQuestion question = query.getQuestions().get(0);
		for (DNSResourceRecord answer : response.getAnswers()) {
			if (answer.getType() == question.getType()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Clones a DNS packet (deep copy).
	 *
	 * @param packet The packet to be cloned.
	 * @return A deep copy of the packet.
	 */
	private static DNS clone(DNS packet) {
		byte[] serialize = packet.serialize();
		return DNS.deserialize(serialize, serialize.length);
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

		/**
		 * Closes the socket.
		 */
		public void close() {
			socket.close();
		}
	}
}
