package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataString;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SimpleDNS {
	public static final int BUFFER_SIZE = 2048;
	public static final int SERVER_PORT = 8053;
	public static final int DNS_PORT = 53;

	public static String rootNameServerIP = null;
	public static String ec2CsvPath = null;
	public static DNS prevLookup = null;
	public static Map<Range, String> cidrLocMap = null;

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
			return;  // for compiler
		}

		read();
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
					response.getAuthorities().addAll(prevLookup.getAuthorities());
					response.getAdditional().addAll(prevLookup.getAdditional());
				} else {
					response = lookup(manager, rootQuery, rootNameServerIP);
				}
				appendTxtIfPresent(response);
				System.out.println(response);  // debug
				manager.send(response.serialize(), received.getAddress(), received.getPort());
			} catch (IOException ex) {
				System.out.println("DEBUG: an error occurred");
				break;
			} catch (RuntimeException ignored) {
			}
		} while (true);

		manager.close();
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
				System.out.println("DEBUG: Found next host: " + nextHostName);
				prevLookup = response;
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
			throw new RuntimeException("DEBUG: no answers found");
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
	 * Appends a txt to the answer section if an answer is of type A and the IP address is within an
	 * EC2 region.
	 *
	 * @param response The response whose answers will be matched.
	 */
	private static void appendTxtIfPresent(DNS response) {
		if (response.getAnswers().isEmpty()) {
			return;
		}
		List<DNSResourceRecord> txt = new ArrayList<>();
		for (DNSResourceRecord answer : response.getAnswers()) {
			if (answer.getType() == DNS.TYPE_A) {
				String host = answer.getName();
				String ip = answer.getData().toString();
				for (Map.Entry<Range, String> entry : cidrLocMap.entrySet()) {
					Range range = entry.getKey();
					if (range.contains(ip)) {
						System.out.println("DEBUG: Found a containing range");
						DNSRdataString data = new DNSRdataString(entry.getValue() + "-" + ip);
						txt.add(new DNSResourceRecord(host, (short) 16, data));
						break;
					}
				}
			}
		}
		response.getAnswers().addAll(txt);
	}

	/**
	 * Reads the given file path to parse cidr expressions and location into the static map whose
	 * key is the cidr expression and value the corresponding location.
	 */
	public static void read() {
		try {
			cidrLocMap = new HashMap<>();
			BufferedReader br = new BufferedReader(new FileReader(ec2CsvPath));
			String line;
			while ((line = br.readLine()) != null) {
				String[] pair = line.split(",");
				cidrLocMap.put(new Range(pair[0]), pair[1]);
			}
		} catch (FileNotFoundException ex) {
			System.out.println("DEBUG: no such file - " + ec2CsvPath);
			System.exit(-1);
		} catch (IOException e) {
			System.out.println("DEBUG: an error occurred while reading");
			System.exit(-1);
		}
	}

	/**
	 * Converts an IPv4 address from string format to integer format. Copied from previous projects.
	 *
	 * @param ipAddress IPv4 address in string format.
	 * @return The same IPv4 address in integer format.
	 */
	public static int toIPv4Address(String ipAddress) {
		if (ipAddress == null) {
			throw new IllegalArgumentException("Specified IPv4 address mustcontain 4 sets of numerical digits separated by periods");
		} else {
			String[] octets = ipAddress.split("\\.");
			if (octets.length != 4) {
				throw new IllegalArgumentException("Specified IPv4 address mustcontain 4 sets of numerical digits separated by periods");
			} else {
				int result = 0;

				for(int i = 0; i < 4; ++i) {
					int oct = Integer.parseInt(octets[i]);
					if (oct > 255 || oct < 0) {
						throw new IllegalArgumentException("Octet values in specified IPv4 address must be 0 <= value <= 255");
					}

					result |= oct << (3 - i) * 8;
				}

				return result;
			}
		}
	}

	/**
	 * Converts an IPv4 address from integer format to string format. Copied from previous projects.
	 *
	 * @param ipAddress IPv4 address in integer format.
	 * @return The same IPv4 address in string format.
	 */
	public static String fromIPv4Address(int ipAddress) {
		StringBuilder sb = new StringBuilder();
		int result;

		for(int i = 0; i < 4; ++i) {
			result = ipAddress >> (3 - i) * 8 & 255;
			sb.append(Integer.valueOf(result).toString());
			if (i != 3) {
				sb.append(".");
			}
		}

		return sb.toString();
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

	public static class Range {
		private final int first;
		private final int last;

		public Range(String cidr) {
			this.first = first(cidr);
			this.last = last(cidr);

			System.out.println("DEBUG: " + cidr +" (" + fromIPv4Address(first) + " ~ " + fromIPv4Address(last) + ")");
		}

		private int first(String cidr) {
			return toIPv4Address(cidr.split("/")[0]);
		}

		private int last(String cidr) {
			String[] parts = cidr.split("/");
			int first = toIPv4Address(parts[0]);
			int bits = 32 - Integer.parseInt(parts[1]);
			int delta = (int) Math.pow(2, bits) - 1;
			return first + delta;
		}

		public boolean contains(String ip) {
			int intIp = toIPv4Address(ip);
			return intIp >= first && intIp <= last;
		}
	}
}
