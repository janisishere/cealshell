local HttpService = game:GetService("HttpService")
local libs = script.Parent.Parent.libs

local plugin

return {
	name = "updatr",
    constructor = function(pl: Plugin)
		plugin = pl
	end,
	callback = function(p)
		local sub: string = p:arg(1)
        if sub == "login" then
            local k = plugin:GetSetting("cealshell:updatr_key")
            if type(k) ~= "string" or (k):len() < 32 then
                warn("A key is already set, please log out of your previous session before making a new one!")
                return
            end
            if plugin:GetSetting("cealshell:updatr_awaiting") then
                local ok, res = pcall(function(...)
                    return HttpService:GetAsync("https://updatr.merithic.com/api/v1/session-poll", true, "Authorization: Bearer "..plugin:GetSetting("cealshell:updatr_session"))
                end)
                if not ok then
                    warn("Failed poll:", res) 
                    return
                end
                local res_t = HttpService:JSONDecode(res)
                if res_t.status == "pending" then
                    warn("Your authorization is still pending.\nIf you cannot find a authorization request try either refreshing the website or forcing a reset on the session (then prompt another login): `--c updatr hardreset`.")
                    return
                elseif res_t.status == "authorized" then
                    if not res_t.key then
                        warn("Invalid server response.")
                        return
                    end
                    plugin:SetSetting("cealshell:updatr_key", res_t.key)
                    plugin:SetSetting("cealshell:updatr_awaiting", false)
                    plugin:SetSetting("cealshell:updatr_session", "")
                    print("Successfully authorized session!")
                elseif res_t.status == "claimed" then
                    warn("This session has already been claimed.")
                else
                    warn("Invalid server response.")
                end
            else
                local session = HttpService:GenerateGUID(false):gsub("-", "")
                plugin:SetSetting("cealshell:updatr_session", session)
                plugin:SetSetting("cealshell:updatr_awaiting", true)
                HttpService:PostAsync(
                    "https://updatr.merithic.com/api/v1/authorize-session", 
                    session,
                    Enum.HttpContentType.TextPlain
                )
            end
        elseif sub == "logout" then
            HttpService:PostAsync(
                "https://updatr.merithic.com/api/v1/logout",
                "session",
                Enum.HttpContentType.TextPlain,
                nil, 
                "Authorization: Bearer "..plugin:GetSetting("cealshell:updatr_key")
            )
            plugin:SetSetting("cealshell:updatr_key", "")
            print("Successfully logged out.")
        elseif sub == "force" then
            local value = p:arg(2)
            plugin:SetSetting("cealshell:updatr_key", value)
        elseif sub == "hardreset" then
            plugin:SetSetting("cealshell:updatr_key", "")
            plugin:SetSetting("cealshell:updatr_session", "")
            plugin:SetSetting("cealshell:updatr_awaiting", false)
            print("Reset complete.")
        else
            warn("Invalid subcommand. Use `manual updatr` for a list.")
        end
	end,
	description = "Manage cealshell's updatr session.",
	manual = {
		"updatr [command...]",
		"Log-in/out of updatr using this command.",
		"",
		"Subcommands:",
		"  login              # prompts a log in",
		"  logout             # deletes your current api key/session",
		"  force <new key>    # forces a new key",
        "  hardreset          # fully resets all updatr config keys"
	},
	signer = "cealshell",
}
