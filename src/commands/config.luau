local libs = script.Parent.Parent.libs
local log = require(libs.log)

local plugin

-- Settings that hold internal state and shouldn't be poked without advanced mode.
local BLACKLIST = {
	"cealshell:remote",
}

local function coerce(x: string): any
	if x == "true" then
		return true
	elseif x == "false" then
		return false
	elseif x:match("^%-?%d+%.?%d*$") then
		return tonumber(x) or 0
	end
	return x
end

return {
	name = "config",
	constructor = function(pl: Plugin)
		plugin = pl
	end,
	callback = function(p)
		local key = p:arg(1)
		local value = p:arg(2)

		if not key then
			log.usage("config <key> [value]")
			return
		end

		local advanced = plugin:GetSetting("cealshell:advanced") == true
		if not advanced and table.find(BLACKLIST, key) then
			log.warn("This setting is locked. Enable advanced mode: '--c config cealshell:advanced true'.")
			return
		end

		if value ~= nil then
			local coerced = coerce(value)
			plugin:SetSetting(key, coerced)
			-- Mirroring is read once at load, so apply it here too rather than
			-- making the user reload to see the setting take effect.
			if key == "cealshell:log_mirror" then
				log.setMirror(coerced == true)
			end
			log.ok(("Set '%s' = %s (%s)."):format(key, tostring(coerced), typeof(coerced)))
		else
			log.info(("%s = %s"):format(key, tostring(plugin:GetSetting(key))))
		end
	end,
	description = "Get or set a Cealshell setting.",
	manual = {
		"config <key> [value]",
		"With no value, prints the current setting; with a value, sets it.",
		"Values are coerced: true/false -> boolean, numbers -> number.",
		"Some keys are locked behind advanced mode.",
	},
	signer = "cealshell",
	alias = { "cfg" },
}
