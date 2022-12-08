package edu.wisc.cs.sdn.simpledns;

import edu.wisc.cs.sdn.simpledns.packet.DNS;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class SimpleDNS {
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

		start();
	}

	public static void start() throws IOException {
		byte[] buffer = new byte[2048];
		DatagramSocket socket = new DatagramSocket(8053);
		DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
		socket.receive(inPacket);
		DNS dns = DNS.deserialize(inPacket.getData(), inPacket.getLength());
		System.out.println("Received: dns query \n" + dns);
	}
}
