--[[
	log.luau
	Buffered output for the CLI.

	Every line a command produces is recorded here with a level and a timestamp,
	so it can be read back later with the `logs` command (or the "cealshell: Logs"
	entry in Commandle) instead of being lost to whatever else scrolled past in
	Studio's shared Output window.

	Recorded lines are printed as they happen too — see `mirror`, which is on
	unless the user turns it off.

	The buffer lives in memory only: it starts empty each time the plugin loads,
	and keeps the newest LIMIT lines.
]]

local PREFIX = "[Cealshell]"
local LIMIT = 500

export type level = "cmd" | "info" | "ok" | "warn" | "error" | "usage" | "line"
export type entry = { level: level, message: string, time: string }

-- Marker printed in front of each line when the buffer is rendered.
local MARKERS: { [string]: string } = {
	cmd = "$",
	info = "-",
	ok = "✓",
	warn = "!",
	error = "✗",
	usage = "?",
	line = " ",
}

-- Levels Studio should colour as warnings when they reach the console.
local WARNING_LEVELS: { [string]: boolean } = {
	warn = true,
	error = true,
}

local log = {}

-- When true, entries are printed as they happen *as well as* saved, so a command
-- still answers in the Output window. On by default; `logs mirror off` (the
-- `cealshell:log_mirror` setting) makes the log the only place output lands.
log.mirror = true

local buffer: { entry } = {}
-- How many lines the LIMIT has pushed out, so the viewer can say so.
local dropped = 0

-- Render one entry as a single line: "12:04:11 ✓ Installed 'signal'."
function log.format(item: entry): string
	return ("%s %s %s"):format(item.time, MARKERS[item.level] or " ", item.message)
end

-- Write one entry to Studio's Output. Used by the viewer and by mirror mode.
local function emit(item: entry)
	local text = log.format(item)
	if WARNING_LEVELS[item.level] then
		warn(text)
	else
		print(text)
	end
end

local function record(level: level, message: string?): entry
	local item: entry = {
		level = level,
		message = message or "",
		time = os.date("%H:%M:%S"),
	}

	table.insert(buffer, item)
	if #buffer > LIMIT then
		table.remove(buffer, 1)
		dropped += 1
	end

	if log.mirror then
		emit(item)
	end
	return item
end

-- Recording ------------------------------------------------------------------
-- These are what commands call. None of them touch the console.

-- Informational line.
function log.info(message: string)
	record("info", message)
end

-- Success / completion line.
function log.ok(message: string)
	record("ok", message)
end

-- Recoverable warning.
function log.warn(message: string)
	record("warn", message)
end

-- Error (still shown as a warn when printed; Studio has no stderr for plugins).
function log.error(message: string)
	record("error", message)
end

-- Usage / help hint for malformed input.
function log.usage(message: string)
	record("usage", ("usage: %s"):format(message))
end

-- Raw line without a marker (for lists, banners, etc.).
function log.line(message: string?)
	record("line", message or "")
end

-- The command that produced the lines below it, so a dump reads like a session.
function log.command(message: string)
	record("cmd", message)
end

-- Console ---------------------------------------------------------------------

-- Record *and* show straight away, whatever `mirror` says. For the few messages
-- that have to be seen without the user asking for them, i.e. startup.
function log.echo(level: level, message: string)
	local item = record(level, ("%s %s"):format(PREFIX, message))
	if not log.mirror then
		-- `record` has already printed it otherwise; don't say it twice.
		emit(item)
	end
end

-- Print one stored entry. This is how the `logs` viewer writes the buffer out.
function log.show(item: entry)
	emit(item)
end

-- Straight to Output, never recorded — headers and footers around a dump.
function log.print(message: string?)
	print(message or "")
end

-- Reading ---------------------------------------------------------------------

-- Every stored entry, oldest first. `levels` optionally narrows to a set of
-- levels ({ warn = true, error = true }); `find` to a case-insensitive substring.
function log.entries(levels: { [string]: boolean }?, find: string?): { entry }
	local needle = if find then find:lower() else nil
	local out = {}

	for _, item in buffer do
		if levels and not levels[item.level] then
			continue
		end
		if needle and not item.message:lower():find(needle, 1, true) then
			continue
		end
		table.insert(out, item)
	end

	return out
end

-- The newest `count` entries matching the same filters as `entries`.
function log.recent(count: number, levels: { [string]: boolean }?, find: string?): { entry }
	local matched = log.entries(levels, find)
	if count >= #matched then
		return matched
	end

	local out = {}
	for i = #matched - count + 1, #matched do
		table.insert(out, matched[i])
	end
	return out
end

-- How many lines are stored right now.
function log.count(): number
	return #buffer
end

-- How many lines the buffer has discarded to stay under LIMIT.
function log.dropped(): number
	return dropped
end

-- Drop everything; returns how many lines went away.
function log.clear(): number
	local had = #buffer
	table.clear(buffer)
	dropped = 0
	return had
end

function log.setMirror(on: boolean)
	log.mirror = on == true
end

return log
