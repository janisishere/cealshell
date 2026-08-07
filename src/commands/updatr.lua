local HttpService = game:GetService("HttpService")
local libs = script.Parent.Parent.libs
local log = require(libs.log)

local plugin

local CLIENT_SECRET = "38de43d57e8f1fc8466aa1625baf1384ee21dd0bb680e87a0534b7d5cd9e0048d"
local CLIENT_ID = "cealshell-janis"
local DEFAULT_SCOPE = "library:read"

local CODE_URL = "https://updatr.merithic.com/api/updatr/oauth/device/code"
local TOKEN_URL = "https://updatr.merithic.com/api/updatr/oauth/device/token"
local LOGOUT_URL = "https://updatr.merithic.com/api/updatr/oauth/device/revoke"

local pollGeneration = 0

local function request(opts)
	local ok, res = pcall(function()
		return HttpService:RequestAsync(opts)
	end)
	if not ok then
		return false, nil, res
	end
	local decoded
	if res.Body and #res.Body > 0 then
		local dok, d = pcall(HttpService.JSONDecode, HttpService, res.Body)
		if dok then
			decoded = d
		end
	end
	return true, res, decoded
end

local function clearSession()
	plugin:SetSetting("cealshell:updatr_awaiting", false)
	plugin:SetSetting("cealshell:updatr_user", "")
	plugin:SetSetting("cealshell:updatr_device", "")
	plugin:SetSetting("cealshell:updatr_interval", nil)
end

local function pollForToken(deviceCode, interval, myGeneration)
	while true do
		task.wait(interval)

		if myGeneration ~= pollGeneration then
			return -- superseded by a hardreset/forcekey/logout/new login
		end

		local ok, res, body = request({
			Url = TOKEN_URL,
			Method = "POST",
			Headers = { ["Content-Type"] = "application/json" },
			Body = HttpService:JSONEncode({ device_code = deviceCode, Authorization = "Bearer "..CLIENT_SECRET }),
		})

		if myGeneration ~= pollGeneration then
			return
		end

		if not ok then
			log.error("Updatr: network error while polling, will retry:", res)
			continue
		end

		if res.StatusCode == 200 and body and body.access_token then
			plugin:SetSetting("cealshell:updatr_key", body.access_token)
			clearSession()
			log.ok("Successfully authorized session! (studio_id: "..tostring(body.studio_id)..", scope: "..tostring(body.scope)..")")
			return
		end

		local err = body and body.error

		if err == "authorization_pending" then
			-- keep polling at the same interval
		elseif err == "slow_down" then
			interval += 5
		elseif err == "access_denied" then
			log.info("Updatr: authorization was denied.")
			clearSession()
			return
		elseif err == "expired_token" then
			log.info("Updatr: the code expired before it was approved. Run `updatr login` again.")
			clearSession()
			return
		else
			log.error("Updatr: unexpected response while polling (status "..tostring(res.StatusCode)..
				"): "..tostring(body and body.error_description or res.Body))
			clearSession()
			return
		end
	end
end

local function beginLogin(scope)
	pollGeneration += 1
	local myGeneration = pollGeneration

	plugin:SetSetting("cealshell:updatr_awaiting", true)

	local ok, res, body = request({
		Url = CODE_URL,
		Method = "POST",
		Headers = { ["Content-Type"] = "application/json" },
		Body = HttpService:JSONEncode({ client_id = CLIENT_ID, scope = scope }),
	})

	if not ok or not res.Success or not body or not body.device_code then
		log.error("Updatr: failed to start authorization:", (body and body.error_description) or res)
		clearSession()
		return
	end

	plugin:SetSetting("cealshell:updatr_user", body.user_code)
	plugin:SetSetting("cealshell:updatr_device", body.device_code)
	plugin:SetSetting("cealshell:updatr_interval", body.interval)

	log.info("Visit Updatr's site to complete the verification: "..body.verification_uri_complete..
		"\nThis link expires in "..tostring(body.expires_in).." seconds."..
		"\nWaiting for approval, no need to run this again — I'll pick it up automatically.")

	task.spawn(pollForToken, body.device_code, body.interval, myGeneration)
end

return {
	name = "updatr",
	constructor = function(pl: Plugin)
		plugin = pl
	end,
	callback = function(p)
		local sub: string = p:arg(1)
		if sub == "login" then
			local k = plugin:GetSetting("cealshell:updatr_key")
			if k and (k):len() > 32 then
				log.info("A key is already set, please log out of your previous session before making a new one!")
				return
			end
			if plugin:GetSetting("cealshell:updatr_awaiting") then
				local deviceCode = plugin:GetSetting("cealshell:updatr_device")
				local interval = plugin:GetSetting("cealshell:updatr_interval") or 5
				if not deviceCode or deviceCode == "" then
					-- awaiting flag set but nothing to resume, e.g. after a bad state; start clean
					beginLogin(p:arg(2) or DEFAULT_SCOPE)
					return
				end
				log.info("Already waiting on a previous authorization request, resuming polling — "..
					"use `--c updatr hardreset` if you want to start over instead.")
				pollGeneration += 1
				task.spawn(pollForToken, deviceCode, interval, pollGeneration)
			else
				beginLogin(p:arg(2) or DEFAULT_SCOPE)
			end
		elseif sub == "logout" then
			local key = plugin:GetSetting("cealshell:updatr_key")
			if not key or key == "" then
				log.info("Not logged in.")
				return
			end
			local ok, res, body = request({
				Url = LOGOUT_URL,
				Method = "POST",
				Headers = {
					["Content-Type"] = "application/json",
					["Authorization"] = "Bearer "..key,
				},
				Body = "{}",
			})
			if not ok or not res.Success then
				log.error("Updatr: logout request failed (key was cleared locally anyway):",
					(body and body.error_description) or res)
			end
			pollGeneration += 1
			plugin:SetSetting("cealshell:updatr_key", "")
			log.ok("Successfully logged out.")
		elseif sub == "forcekey" then
			local value = p:arg(2)
			pollGeneration += 1
			plugin:SetSetting("cealshell:updatr_key", value)
			clearSession()
		elseif sub == "hardreset" then
			pollGeneration += 1
			plugin:SetSetting("cealshell:updatr_key", "")
			clearSession()
			log.ok("Reset complete.")
		else
			log.usage("Invalid subcommand. Use `manual updatr` for a list.")
		end
	end,
	description = "Manage cealshell's updatr session.",
	manual = {
		"updatr [command...]",
		"Log-in/out of updatr using this command.",
		"",
		"Subcommands:",
		"  login [scope]      # prompts a log in, polls automatically until approved/denied/expired",
		"                     # scope defaults to \""..DEFAULT_SCOPE.."\"; space-separated for multiple",
		"  logout             # revokes and deletes your current api key/session",
		"  forcekey <new key> # forces a new key",
		"  hardreset          # fully resets all updatr config keys, stops any pending poll",
	},
	signer = "cealshell",
}