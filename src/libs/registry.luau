--[[
	registry.luau
	Command registry + dispatcher.

	Each command module is registered by name with an optional alias list.
	On dispatch, the raw token list is run through `parser` and the resulting
	structured args object is handed to the command callback. This keeps every
	command on one consistent argument model.
]]

local libs = script.Parent

--// Modules
local types = require(libs:FindFirstChild("types"))
local parser = require(libs:FindFirstChild("parser"))
local log = require(libs:FindFirstChild("log"))

--// Globals
local reg = {}
reg.commands = {} :: { [string]: types.command }

function reg:register(
	command: string,
	args: { types.args }?,
	callback: (parsed: any) -> (),
	description: string?,
	manual: types.manual?,
	signer: string?
): types.command
	local entry: types.command = {
		name = command,
		arguments = args,
		callback = callback,
		description = description,
		manual = manual,
		signer = signer,
		aliases = {},
		-- Opt-out of invocation recording; set from the module's `silent` field.
		silent = false,
	}

	-- Add one or more aliases. Stored as a plain de-duplicated array so that
	-- `table.find` works everywhere (the previous closure-wrapped table had an
	-- empty array part, which silently broke every alias lookup).
	function entry:alias(new: string | { string })
		local list = if typeof(new) == "string" then { new } else new
		for _, name in list do
			if not table.find(self.aliases, name) then
				table.insert(self.aliases, name)
			end
		end
	end

	reg.commands[command] = entry
	return entry
end

-- Resolve a command by its name or any of its aliases.
function reg:resolve(name: string): types.command?
	local direct = reg.commands[name]
	if direct then
		return direct
	end
	for _, entry in reg.commands do
		if table.find(entry.aliases, name) then
			return entry
		end
	end
	return nil
end

-- Dispatch a command by name/alias with its raw token list.
function reg:call(command: string, tokens: { string })
	local entry = reg:resolve(command)

	-- Output is saved rather than printed, so record what was run: a dump then
	-- reads as a session instead of a wall of context-free lines. `silent`
	-- commands (the log viewer) stay out of it — they'd only ever show
	-- themselves back.
	if not entry or not entry.silent then
		log.command((("%s %s"):format(command, table.concat(tokens, " "))):match("^%s*(.-)%s*$"))
	end

	if not entry then
		log.error(("Unknown command '%s'. Type '--c help' for a list."):format(tostring(command)))
		return
	end

	local parsed = parser.parse(tokens)

	local ok, err = pcall(entry.callback, parsed)
	if not ok then
		log.error(("Command '%s' failed: %s"):format(command, tostring(err)))
	end
end

return reg
