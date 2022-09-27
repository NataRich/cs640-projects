import java.io.IOException;

public class Iperfer {
    private static void clientMode(String hostname, int serverPort, int time) throws IOException {
        //do something
        Client client = new Client(hostname, serverPort, time);
        client.send();
    }
    private static void serverMode(int listenPort) throws IOException {
        Server server = new Server(listenPort);
        server.receive();
    }
    public static void main(String[] args) throws IOException {
        boolean isClient = true; //a flag that determines client/server mode
        if (args[0].equals("-c")) { //use client mode
            //validate argument number and sequence
            if (args.length != 7 || !args[1].equals("-h") || !args[3].equals("-p") || !args[5].equals("-t")) {
                System.out.println("Error: invalid arguments");
                return;
            }
            //validate server port
            int serverPort;
            try {
                serverPort = Integer.parseInt(args[4]);
                if (serverPort > 65535 || serverPort < 1024) {
                    System.out.println("Error: port number must be in the range 1024 to 65535");
                    return;
                }
            } catch (NumberFormatException e) {
                System.out.println("Error: port number must be in the range 1024 to 65535");
                return;
            }
            //validate time and hostname
            String hostname = args[2]; //hostname: no validation, just take whatever is there
            //time: positve integer, print "Error: invalid arguments" otherwise
            int time;
            try {
                time = Integer.parseInt(args[6]);
                if (time < 0) {
                    System.out.println("Error: invalid arguments");
                    return;
                }
            } catch (NumberFormatException e) {
                System.out.println("Error: invalid arguments");
                return;
            }

            //test
            clientMode(hostname, serverPort, time);
        } else if (args[0].equals("-s")) { //use server mode
            if (args.length != 3 || !args[1].equals("-p")) {
                System.out.println("Error: invalid arguments");
                return;
            }
            //validate listen port
            int listenPort;
            try {
                listenPort = Integer.parseInt(args[2]);
                if (listenPort > 65535 || listenPort < 1024) {
                    System.out.println("Error: port number must be in the range 1024 to 65535");
                    return;
                }
            } catch (NumberFormatException e) {
                System.out.println("Error: port number must be in the range 1024 to 65535");
                return;
            }

            //test
            serverMode(listenPort);
        } else { // if the first argument is not -c or -s
            System.out.println("Error: invalid arguments");
        }

    }

}

