import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    private final int port;
    private static final byte[] DATA_HOLDER = new byte[1000];

    public Server(int port) {
        this.port = port;
    }

    public void receive() throws IOException {
        ServerSocket server = new ServerSocket(port);
        Socket socket = server.accept();
        InputStream in = socket.getInputStream();
        long dataReceived = 0;  // in Bytes
        double speed;  // in Mbps
        long part;  // in Bytes
        long startTime = System.currentTimeMillis();
        while ((part = in.read(DATA_HOLDER)) != -1) {
            dataReceived += part;
        }
        long endTime = System.currentTimeMillis();
        // dataReceived / 1000 / 1000 => MB
        // 8.0 * prev => Mb
        // (endTime - startTime) * 1000 => s
        speed = (8.0 * dataReceived / 1000 / 1000) / (endTime - startTime) * 1000;
        // dataReceived / 1000 => KB
        System.out.printf("received=%d KB rate=%.3f Mbps%n", dataReceived / 1000, speed);
        socket.close();
        server.close();
    }
}
