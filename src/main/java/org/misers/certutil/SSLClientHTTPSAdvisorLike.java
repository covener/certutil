package org.misers.certutil;


import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLSocket;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.time.FastDateFormat;

import javax.net.ssl.*;


import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class SSLClientHTTPSAdvisorLike
{
    public boolean quitting = false;

    // Must be set as non-JVM prop
    static {
      java.security.Security.setProperty("jdk.tls.disabledAlgorithms", "NONE");
    }
    
    SSLContext sc;
    private String responseLine;
    public ServerDocLog log;
    private static final String CRLF = "\r\n";
    private Object sem1 = new Object();
    public int failed;
    List<String> failures;
    
    /**
     * Constructs a new SSLClient instance:
     * 
     * @param host Hostname to connect to
     * @param port Port to connect to
     * @param uri URI to request
     * @param cipherSuites A list of names of cipher suites that are allowed.
     * @param protocol can be null to use the default of "SSL", otherwise is used
     * to get an instance of an SSLContext.
     * @throws NoSuchAlgorithmException 
     * @throws KeyManagementException 
     */
    public SSLClientHTTPSAdvisorLike() throws NoSuchAlgorithmException, KeyManagementException { 
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[1];
        javax.net.ssl.TrustManager tm = new LenientTrustManager();
        trustAllCerts[0] = tm;

        if (sc == null) { 
            sc = javax.net.ssl.SSLContext.getInstance("TLSv1.2");
            sc.init(null, trustAllCerts, null);
        } 
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());   
        
        log = new ServerDocLog();
        failures = new ArrayList<String>();
    }
    
    public boolean get(String host, int port, String url) throws IOException {
        SSLSocket socket = (SSLSocket) sc.getSocketFactory().createSocket(host, port);
        socket.setEnabledProtocols(socket.getSupportedProtocols());

       OutputStreamWriter out = new OutputStreamWriter(socket.getOutputStream(), "ISO-8859-1");
       BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                        socket.getInputStream(),
                        "ISO-8859-1"));
       
       socket.startHandshake();
       StringBuffer output = new StringBuffer("");

       try {
           out.write("GET " + url + " HTTP/1.1\r\n");
           out.write("Host: " + host + ":" + port + "\r\n");
           out.write("Agent: SSL-TEST\r\n");
           out.write("Connection: close\r\n");
           out.write("\r\n");
           out.flush();
           String line = null;
           while ((line = in.readLine()) != null) {
               if (!line.startsWith("HTTP")) {
                   /* Haven't gotten to start of actual output yet.  (gnutls-cli is chatty). */
                   continue;
               }
               responseLine = line;
               break;  // read the rest of the response without using readLine()
           }
           
           /* Read the rest of it */
           char[] tmpbuf = new char[512]; 
           int rc = in.read(tmpbuf);
           while (-1 != rc) {
               // throw it away so we can test with large responses.
               //output.append(tmpbuf, 0, rc);
               rc = in.read(tmpbuf);
           }
           
           if (responseLine == null) {
               return false;
           }
           
       }
       catch (Exception e) { 
           log.println("Exception client=" +socket.getLocalPort() + ", server=" + host + ":" + port + url + ", " + e.toString());
       }
       finally { 
           if (socket != null) { 
               socket.close();
           }
       }
       log.println("client=" +socket.getLocalPort() + ", server=" + host + ":" + port + url + ", response line: " + responseLine);
       return responseLine.contains("200");
   }
    
   public Thread getRunnable(String host, String port, String url) { 
       return new Thread(this.new GET(this, host, port, url));
   }
   public void burst() { 
       synchronized(sem1) {
           log.println("Burst...");
           sem1.notifyAll();
       }
   }
   public String toString() { 
       if (failed == 0) { 
           return("OK");
       }
       else { 
           return("FAIL: " + Arrays.asList(this.failures).toString());
       }
   }
   
    public static void main(String[] args) throws KeyManagementException, NoSuchAlgorithmException {
        CommandLineParser parser = new DefaultParser();
        CommandLine line = null;
        Options options = new Options();
        int reqs = 100;
        
        options.addOption("count", true, "number of requests per input triplet");
        options.addOption("hosts", true, "comma-separated hosts");
        options.addOption("ports", true, "comma-separated ports");
        options.addOption("urls", true, "comma-separated URL paths");
        options.addOption("h", false, "help");

        HelpFormatter formatter = new HelpFormatter();
    
        try {
            line = parser.parse(options, args);
        } catch (ParseException exp) {
            System.out.println(exp);
            formatter.printHelp("SSLClientHTTPSAdvisorLike", options);
            return;
        }
        
        SSLClientHTTPSAdvisorLike client = new SSLClientHTTPSAdvisorLike();
        if (line.hasOption("count")) { 
            reqs = Integer.parseInt(line.getOptionValue("count"));
        }
        
        System.setErr(client.log); // XXX don't use this anywhere but on the command line!
        System.setOut(client.log);
        
        args = line.getArgs();
        
        String[] hosts = new String[] {};
        String[] ports = new String[] {};
        String[] urls  = new String[]  {};
        
        if (args.length == 3) { 
            hosts = args[0].split(",");
            ports = args[1].split(",");
            urls  = args[2].split(",");
        }
        else if (args.length == 0) { 
            if (!(line.hasOption("hosts") && line.hasOption("ports") && line.hasOption("urls"))) { 
                formatter.printHelp("SSLClientHTTPSAdvisorLike [-count N] -hosts host1[,host2]... -ports 443[,443]... /[,/]...", options);
                return;
            }
            hosts = line.getOptionValue("hosts").split(",");
            ports = line.getOptionValue("ports").split(",");
            urls  = line.getOptionValue("urls").split(",");

        }
        else { 
            formatter.printHelp("SSLClientHTTPSAdvisorLike", options);
            return;
        }

        int nthreads = hosts.length;
        
        if (hosts.length != ports.length || ports.length != urls.length) { 
            System.err.println("All comma-separated args must be the same length");
            formatter.printHelp("SSLClientHTTPSAdvisorLike", options);
            System.exit(1);
        }
        
        boolean ok = false;
        
        try {
            ok = client.get(hosts[0], Integer.parseInt(ports[0]), urls[0]);
        } catch (NumberFormatException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        if (!ok) { 
            client.log.println(client.toString());
        }
        
        Thread[] threads;
        threads = new Thread[nthreads];
        for (int i = 0; i < nthreads; i++) {
            threads[i] = client.getRunnable(hosts[i], ports[i], urls[i]);
            threads[i].start();
        }
        
        for(int i = 0; i < reqs; i++) { 
            client.burst();
            if (client.failed > 0) { 
                break;
            }
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        
        client.quitting = true;

        for (int i =0; i < nthreads; i++) {
            if (threads[i] != null && threads[i].isAlive()) {
                threads[i].interrupt();
                try {
                    threads[i].join();
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        if (client.failed > 0) { 
            if (!ok) { 
                client.log.println(client.toString());
            }
            System.exit(1);
        }

    }

    private class GET implements Runnable {
        private SSLClientHTTPSAdvisorLike client;
        private String host;
        private String port;
        private String url;
        private boolean ok = false;

        public boolean isOK() { 
            return ok;
        }
        
        public GET(SSLClientHTTPSAdvisorLike c, String host, String port, String url) {
            this.client = c;
            this.host = host;
            this.port = port;
            this.url = url;
        }

        public void run() {
            int port = Integer.parseInt(this.port);
            while (!client.quitting) {
                log.println("synch on sem");
                synchronized(sem1) {
                    log.println("... notified on synch");
                    try {
                        log.println("Wait on sem");
                        client.sem1.wait();
                        log.println("... notified on wait");

                    } catch (InterruptedException e) {
                    }
                }
                try {
                    ok = false;
                    // first we synch, then we stagger.
                    Double delay = Math.random() * 20; // 0-20ms 
                    Thread.sleep(delay.longValue());
                    client.get(host, port, url);
                } catch (IOException e) {
                    client.fail(host+":"+port+url + " " + e.toString());
                } catch (InterruptedException e) {
                }
                ok = true;
            }
        }
        
    } // SSLClientHTTPSAdvisorLike
    
    class ServerDocLog extends PrintStream {
        private final FastDateFormat  timeFormatter = FastDateFormat.getInstance("HH:mm:ss.SSS");
        OutputStream out;
        @Override
        public void println(String x) {
            StringBuilder sb = new StringBuilder(x);
            if (sectionTitle != null) {
                super.println(x);
            } else {
                String timestamp = getTimeStamp();
                sb = new StringBuilder(timestamp).append(" ");
                if (Thread.currentThread().getId() != 1) { 
                    sb.append("t").append(Thread.currentThread().getId()).append(" ");
                }
                sb.append(x);
                synchronized(this) { 
                    super.println(sb.toString());
                }
            }
        }

        private byte[] addPrefix(byte buf[], String prefix) { 
            byte[] out = new byte[buf.length + prefix.length() + 1];
            System.arraycopy(prefix.getBytes(), 0, out, 0, prefix.length());
            buf[prefix.length() + 1] = ' ';
            System.arraycopy(buf, 0, out, prefix.length() + 1, buf.length);
            return out;
        }
        protected String getLogPrefix() { 
            StringBuilder sb = new StringBuilder(getTimeStamp());
            long tid = Thread.currentThread().getId();
            sb.append("t").append(tid).append(" ");
            return sb.toString();
        }
        
        public void write(byte buf[], int off, int len) {
            try {
                String prefix = getLogPrefix();
                if (off == 0) { 
                    out.write(buf, off, len);
                }
                else { 
                    out.write(addPrefix(buf, prefix), off, len+prefix.length()+1);
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        
        private synchronized String getTimeStamp() {
            return timeFormatter.format(new Date()) + " ";
        }

        public void println_no_timestamp(String x) {
            super.println(x);
        }

        private String sectionTitle = null;

        /**
         * Constructs an instance that logs to the given stream.
         * @param out
         */
        public ServerDocLog(OutputStream out) {
            super(out, true);
            this.out = out;
        }

        /**
         * Constructs an instance that logs to stderr.
         */
        public ServerDocLog() {
            this(System.out);
            this.out = System.out;
        }

        /**
         * Constructs and returns an instance that logs to the named file.
         * @param logFile
         * @return the ServerDocLog instance
         */
        public ServerDocLog openLog(String logFile) {
            ServerDocLog log = null;
            BufferedOutputStream bos = null;
            FileOutputStream fos = null;
         
            try {
                fos = new FileOutputStream(logFile);
                bos = new BufferedOutputStream(fos);
                log = new ServerDocLog(bos);
                System.out.println("Using log file "+logFile);
            } catch (FileNotFoundException e) {
                System.err.println(
                    "Fatal error: Log file " + logFile + " could not be created.");
                System.err.println("  " + e);
                System.err.println(
                    "Make sure you have permissions to create files in the directory.");
                System.exit(1);
            }
            
            return log;
        }

        /**
         * Logs that we're about to run the given command.
         * @param cmd
         */
        public void running(String cmd) {
            println("about to run \"" + cmd + "\"");
            flush();
        }

       /**
         * Logs the start of a new section
         * with the given title.  Sections
         * don't nest.
         * @param title
         */
        public void startSection(String title) {
            println(
                "********** start of "
                    + title
                    + " **********");
            sectionTitle = title;
        }

        /**
         * Logs the end of a section, including
         * the title that was given when it started.
         */
        public void stopSection() {
            String title;

            if (sectionTitle != null) {
                title = sectionTitle;
                sectionTitle = null;
            } else {
                title = "unknown section";
            }
            println("********** end of " + title + " **********");
        }

        /**
         * Formats an integer as hex digits,
         * padding with 0 to the desired length
         * if necessary.  (Does not truncate if
         * the result is longer.)
         * @param in The integer value to format
         * @param n The minimum length
         * @return The formatted string.
         */
        String hexNDigits(int in, int n) {
            String result = Integer.toHexString(in);
            while (result.length() < n) {
                result = "0" + result;
            }
            return result;
        }

        /**
         * Returns the integer value of the given byte,
         * interpreting it as unsigned.
         * <p>(Sigh - why doesn't Java have unsigned types?)
         * @param b - the byte value 
         * @return the integer value of the byte
         */
        private int unsignedByte(byte b) {
            return 0xff & (b + 0x100);
        }

        /**
         * Logs some byte data in the traditional hexdump format.
         * Allows specifying what charset the data should be interpreted
         * as.
         * @param data - the data.  the whole byte array is logged.
         * @param charset - the Java charset name to use when interpreting
         * the data for the right side of the dump.
         */
        public void hexdump(byte[] data, String charset) {
            int start = 0;

            if (null == data) {
                println("hexdump attempted from null pointer");
                return;
            }
            int remaining = data.length - start;
            while (remaining > 0) {
                // Show starting offset
                print(hexNDigits(start,8) + "  ");
                for (int i = 0; i < 16; i++) {
                    if ((start+i) < data.length) {
                        print(hexNDigits(unsignedByte(data[start + i]),2) + " ");
                    }
                    else {
                        print("   ");
                    }
                    if (i == 7) {
                        print(" ");
                    }
                }
                print(" |");

                // convert to a string
                int len = 16;
                if (len > remaining) {
                    len = remaining;
                }
                String s;
                try {
                    s = new String(data, start, len, charset);
                } catch (java.io.UnsupportedEncodingException e) {
                    println("\n\n" + e);
                    return;
                }
                // Fix some non-printables
                s = s.replace('\n','.').replace('\r', '.');
                
                print(s);
                print("|");

                print("\n");

                start += 16;
                remaining = data.length - start;
            }
        }
    }

    public void fail(String s) {
        log.println(s);
        failures.add(s);
        this.failed++;  
    }
    
    private class LenientTrustManager implements javax.net.ssl.TrustManager, javax.net.ssl.X509TrustManager {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }
        public boolean isServerTrusted(
            java.security.cert.X509Certificate[] certs) {
            return true;
        }
        public boolean isClientTrusted(
            java.security.cert.X509Certificate[] certs) {
            return true;
        }
        public void checkServerTrusted(
            java.security.cert.X509Certificate[] certs,
            String authType)
            throws java.security.cert.CertificateException {
            return;
        }
        public void checkClientTrusted(
            java.security.cert.X509Certificate[] certs,
            String authType)
            throws java.security.cert.CertificateException {
            return;
        }
    }
 }
