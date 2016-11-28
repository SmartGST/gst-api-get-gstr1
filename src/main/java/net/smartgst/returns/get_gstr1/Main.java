package net.smartgst.returns.get_gstr1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import net.smartgst.auth.AESEncryption;
import net.smartgst.auth.GSTAuth;
import org.json.JSONObject;

import java.io.InputStream;
import java.util.UUID;

/**
 * Hello world!
 */
public class Main {
    //random User Name
    private static final String USER_NAME = UUID.randomUUID().toString();
    //random Trx Id
    private static final String TXN = UUID.randomUUID().toString();

    //hard coded state code
    private static final String STATE_CD = "11";

    private static final String CLIENT_ID = "l7xx6df7496552824f15b7f4523c0a1fc114";
    private static final String CLIENT_SECRET = "f328fe52752349c893aa93adcffed8f5";


    //hard coded OTP
    private static final String OTP = "102030";

    //hard coded for now
    private static final String IP_USR = "192.168.1.1";

    private static GSTAuth gstAuth;
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String BASE_URL = "http://devapi.gstsystem.co.in";
    private static final String GSTR1_PATH = "/taxpayerapi/v0.1/returns/gstr1";
    private static final String APPLICATION_JSON = "application/json";

    public static void main(String[] args) throws Exception {
        InputStream pubKeyInpStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("GSTN_PublicKey.cer");


        gstAuth = new GSTAuth(
                CLIENT_ID, CLIENT_SECRET,
                USER_NAME, STATE_CD, IP_USR,
                TXN, pubKeyInpStream);

        AESEncryption aesEncryption = gstAuth.getAesEncryption();
        if (gstAuth.otpRequest()) {
            System.out.println("OTP Request Success");
            if (gstAuth.authTokenRequest(OTP)) {
                System.out.println("Auth Token Success");

                String requestUrl = String.format("%s/%s", BASE_URL, GSTR1_PATH);
                HttpResponse<JsonNode> resp =
                        Unirest.get(requestUrl)
                                .queryString("action", "B2B")
                                .queryString("gstin", "04AABFN9870CMZT")
                                .queryString("ret_period", "102016")
                                .queryString("action_required", "Y")
                                .header("Content-Type", APPLICATION_JSON)
                                .header("state-cd", STATE_CD)
                                .header("clientid", CLIENT_ID)
                                .header("client-secret", CLIENT_SECRET)
                                .header("ip-usr", IP_USR)
                                .header("username", USER_NAME)
                                .header("auth-token", gstAuth.getAuthToken())
                                .header("appkey", gstAuth.getAppKeyEncryptedAndCoded())
                                .header("txn", TXN)
                                .asJson();

                System.out.println(resp.getStatus());
                System.out.println(resp.getBody());

                JSONObject gstrRespObj = resp.getBody().getObject();
                String data = gstrRespObj.getString("data");
                String rek = gstrRespObj.getString("rek");

                //recover apiEncryptionKey from Response using our AuthSEK
                byte[] apiEK = aesEncryption.decrypt(rek, gstAuth.getAuthSEK());

                //using the apiEncryptionKey, recover the Json data (in base64 fmt)
                String respJsoninBase64 = new String(aesEncryption.decrypt(data, apiEK));

                //convert base64 to original json (in bytes)
                byte[] respJsonInBytes = aesEncryption.decodeBase64StringTOByte(respJsoninBase64);

                //convery original json in bytes to json string
                String jsonData = new String(respJsonInBytes);
                System.out.println(jsonData);
            }
        }

    }
}
