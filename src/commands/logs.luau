local libs = script.Parent.Parent.libs
local log = require(libs.log)

local MIRROR_SETTING = "cealshell:log_mirror"

-- How many lines a bare `logs` shows. Enough for one operation without burying
-- the Output window in a whole session's worth of history.
local DEFAULT_COUNT = 50

local RULE = string.rep("-", 60)

local plugin

-- Print a dump: header, the entries themselves, then a hint if there is more.
local function dump(entries: { log.entry }, total: number)
	log.print()
	log.print(("[Cealshell] logs — %d of %d saved line%s"):format(#entries, total, if total == 1 then "" else "s"))

	local lost = log.dropped()
	if lost > 0 then
		log.print(("(%d older line%s dropped)"):format(lost, if lost == 1 then "" else "s"))
	end

	log.print(RULE)
	for _, item in entries do
		log.show(item)
	end
	log.print()
end

return {
	name = "logs",
	constructor = function(pl: Plugin)
		plugin = pl
	end,
	callback = function(p)
		local first = p:arg(1)

		if first == "clear" then
			local removed = log.clear()
			log.print(("[Cealshell] cleared %d saved line%s."):format(removed, if removed == 1 then "" else "s"))
			return
		end

		if first == "mirror" then
			local state = p:arg(2)
			if state ~= "on" and state ~= "off" then
				log.print("[Cealshell] usage: logs mirror <on|off>")
				log.print(("[Cealshell] mirror is currently %s."):format(if log.mirror then "on" else "off"))
				return
			end

			local on = state == "on"
			log.setMirror(on)
			plugin:SetSetting(MIRROR_SETTING, on)
			log.print(("[Cealshell] mirror %s — output %s printed as it happens."):format(
				state,
				if on then "is now also" else "is no longer"
			))
			return
		end

		-- The only positional is a line count; anything else is a typo worth
		-- saying so about, since a silent "last 50" hides the mistake.
		local count = DEFAULT_COUNT
		if first then
			local asked = tonumber(first)
			if not asked or asked < 1 then
				log.print(("[Cealshell] usage: logs [count] — '%s' is not a line count."):format(first))
				return
			end
			count = math.floor(asked)
		end

		-- Filters. `-e` narrows to problems; `--find` to a substring.
		local levels = if p:has("e", "errors") then { warn = true, error = true } else nil
		local find = p:opt("find")

		local matched = log.entries(levels, find)
		if #matched == 0 then
			if levels or find then
				log.print("[Cealshell] no saved output matches that filter.")
			else
				log.print("[Cealshell] no saved output yet — run a command first.")
			end
			return
		end

		-- `logs 20` shows the last 20; `-a` shows everything.
		if p:has("a", "all") then
			count = #matched
		end

		dump(log.recent(count, levels, find), #matched)
	end,
	description = "Show saved command output.",
	manual = {
		"logs [count]",
		"Cealshell saves its output instead of printing it. This prints it back.",
		"With no count, the last " .. DEFAULT_COUNT .. " lines are shown.",
		"",
		"Flags:",
		"  -a, --all       Show every saved line",
		"  -e, --errors    Show only warnings and errors",
		"  --find <text>   Show only lines containing <text>",
		"",
		"Subcommands:",
		"  logs clear           Discard the saved lines",
		"  logs mirror on|off   Also print output as it happens (persists)",
		"",
		"The buffer keeps the newest 500 lines and empties when Studio restarts.",
	},
	signer = "cealshell",
	-- Reading the log shouldn't write to it.
	silent = true,
	alias = { "log", "history" },
}
