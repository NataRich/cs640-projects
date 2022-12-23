import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class Client {
    private final String host;
    private final int port;
    private final long duration;  // in seconds
    private static final byte[] DATA = new byte[1000];

    public Client(String host, int port, long duration) {
        this.host = host;
        this.port = port;
        this.duration = duration;
    }

    public void send() throws IOException {
        Socket socket = new Socket(host, port);
        OutputStream out = socket.getOutputStream();
        long dataSent = 0;  // in KB
        double speed;  // in Mbps
        long startTime = System.currentTimeMillis();
        long endTime = startTime + duration * 1000;
        long currTime = startTime;
        while (currTime < endTime) {
            out.write(DATA);
            out.flush();
            dataSent++;
            currTime = System.currentTimeMillis();
        }
        // dataSent / 1000 => MB
        // 8.0 * prev => Mb
        // (currTime - startTime) * 1000 =>
        speed = (8.0 * dataSent / 1000) / (currTime - startTime) * 1000;
        System.out.printf("sent=%d KB rate=%.3f Mbps%n", dataSent, speed);
        out.close();
        socket.close();
    }
}
