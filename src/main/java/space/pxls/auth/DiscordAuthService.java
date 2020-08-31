package space.pxls.auth;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import org.json.JSONObject;
import space.pxls.App;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class DiscordAuthService extends AuthService {
    public DiscordAuthService(String id) {
        super(id, App.getConfig().getBoolean("oauth.discord.enabled"), App.getConfig().getBoolean("oauth.discord.registrationEnabled"));
    }

    public String getRedirectUrl(String state) {
        String scope = "identify" + (App.getConfig().hasPath("oauth.discord.memberOfGuilds") ? "+guilds" : "");
        return "https://discord.com/api/oauth2/authorize?client_id=" + App.getConfig().getString("oauth.discord.key") + "&response_type=code&redirect_uri=" + getCallbackUrl() + "&duration=temporary&scope=" + scope + "&state=" + state;
    }

    public String getToken(String code) throws UnirestException {
        HttpResponse<JsonNode> response = Unirest.post("https://discord.com/api/oauth2/token")
                .header("User-Agent", "pxls.space")
                .field("grant_type", "authorization_code")
                .field("code", code)
                .field("redirect_uri", getCallbackUrl())
                .basicAuth(App.getConfig().getString("oauth.discord.key"), App.getConfig().getString("oauth.discord.secret"))
                .asJson();

        JSONObject json = response.getBody().getObject();

        if (json.has("error")) {
            return null;
        } else {
            return json.getString("access_token");
        }
    }

    public String getIdentifier(String token) throws UnirestException, InvalidAccountException {
        HttpResponse<JsonNode> me = Unirest.get("https://discord.com/api/users/@me")
                .header("Authorization", "Bearer " + token)
                .header("User-Agent", "pxls.space")
                .asJson();
        JSONObject meJSON = me.getBody().getObject();
        if (meJSON.has("error")) {
            return null;
        }

        String id = meJSON.getString("id");

        if (App.getConfig().hasPath("oauth.discord.minAge")) {
            long idLong = Long.parseLong(id);
            long signupTimeMillis = (idLong >> 22) + 1420070400000L;
            long ageMillis = System.currentTimeMillis() - signupTimeMillis;

            long minAgeMillis = App.getConfig().getDuration("oauth.discord.minAge", TimeUnit.MILLISECONDS);
            if (ageMillis < minAgeMillis){
                throw new InvalidAccountException("Account too young");
            }
        }

        if (App.getConfig().hasPath("oauth.discord.memberOfGuilds")) {
            final List<Long> allowedGuilds = App.getConfig().getLongList("oauth.discord.memberOfGuilds");
            HttpResponse<JsonNode> guilds = Unirest.get("https://discord.com/api/users/@me/guilds")
                    .header("Authorization", "Bearer " + token)
                    .header("User-Agent", "pxls.space")
                    .asJson();
            if (!guilds.getBody().isArray()) {
                return null;
            }

            boolean isAllowed = false;
            for (Object obj : guilds.getBody().getArray()) {
                if (obj instanceof JSONObject && allowedGuilds.contains(((JSONObject) obj).getLong("id"))) {
                    isAllowed = true;
                    break;
                }
            }
            if (!isAllowed) {
                throw new InvalidAccountException("Account isn't in any allowed server.");
            }
        }

        return meJSON.getString("id");
    }

    public String getName() {
        return "Discord";
    }

    @Override
    public void reloadEnabledState() {
        this.enabled = App.getConfig().getBoolean("oauth.discord.enabled");
        this.registrationEnabled = App.getConfig().getBoolean("oauth.discord.registrationEnabled");
    }
}
