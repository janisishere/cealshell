--[[
 ______     ______     ______     __         ______     __  __     ______     __         __        
/\  ___\   /\  ___\   /\  __ \   /\ \       /\  ___\   /\ \_\ \   /\  ___\   /\ \       /\ \       
\ \ \____  \ \  __\   \ \  __ \  \ \ \____  \ \___  \  \ \  __ \  \ \  __\   \ \ \____  \ \ \____  
 \ \_____\  \ \_____\  \ \_\ \_\  \ \_____\  \/\_____\  \ \_\ \_\  \ \_____\  \ \_____\  \ \_____\ 
  \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/   \/_____/ 
                                                                                                   
Simple and easy CLI tool with an integrated package manager.
Designed for Roblox Studio.
Licensed with MIT under (c) janisfox 2026.
Contact: https://github.com/janisfox
GitHub: https://github.com/cealshell/cealshell-cli
Website: https://cealshell.dev/
]]--

local start = tick()
--

local VERSION = "dev v2.3"

--// Services
local LogService = game:GetService("LogService")
local RunService = game:GetService("RunService")
local StudioService = game:GetService("StudioService")

local success, isEdit = pcall(function(...)
	return RunService:IsEdit()
end)

if not success or not isEdit then return end

--// Folders
local libs = script:FindFirstChild("libs")
local cmds = script:FindFirstChild("commands")

--// Modules
local reg = require(libs:FindFirstChild("registry"))
local log = require(libs:FindFirstChild("log"))
local pmanager = require(libs:FindFirstChild("pmanager"))
pmanager:constructor(plugin)

--// Binds
-- Commands are typed into Studio's command bar as `--c <command> ...`. The bar
-- echoes them to the log prefixed with "> ", and the leading `--c` keeps the
-- line a no-op comment so the command bar never errors. We pick those echoes
-- back up here and dispatch them.
local COMMAND_PREFIX = "> --c "
LogService.MessageOut:Connect(function(str: string, messageType: Enum.MessageType)
	if messageType ~= Enum.MessageType.MessageOutput then return end
	if str:sub(1, #COMMAND_PREFIX) ~= COMMAND_PREFIX then return end

	-- Strip the prefix, then split into a clean token list (no nil holes).
	local tokens = str:sub(#COMMAND_PREFIX + 1):split(" ")
	local cmd = table.remove(tokens, 1)
	if not cmd or cmd == "" then return end

	reg:call(cmd, tokens)
end)

--// Script

--// Settings
-- There is a single remote. The active one lives in the `cealshell:remote` setting
-- (managed by the `remote` command); when unset, the built-in default is used. A
-- reference can also carry a one-off remote override (see the install command).

plugin:SetSetting("cealshell:version", VERSION)

-- First-run defaults.
if plugin:GetSetting("cealshell:startup") ~= true then
	plugin:SetSetting("cealshell:startup", true)
	plugin:SetSetting("cealshell:advanced", false)
end

if plugin:GetSetting("cealshell:no_local_warning") == nil then
	plugin:SetSetting("cealshell:no_local_warning", false)
end

-- Command output is saved (see libs/log) *and* printed, unless the user has
-- turned mirroring off. The setting is owned by `logs mirror on|off`.
log.setMirror(plugin:GetSetting("cealshell:log_mirror") ~= false)

-- Delete legacy settings
if plugin:GetSetting("cealshell:remotes") ~= nil then
	plugin:SetSetting("cealshell:remotes", nil)
end
if plugin:GetSetting("cealshell:remotes/default") ~= nil then
	plugin:SetSetting("cealshell:remotes/default", nil)
end

-- Register
local function iterate(folder: Instance)
	for _, item in folder:GetChildren() do
		if not item:IsA("ModuleScript") then
			iterate(item)
			continue
		end
		local cmd = require(item)
		if cmd.constructor then
			cmd.constructor(plugin)
		end
		local r = reg:register(cmd.name, cmd.args, cmd.callback, cmd.description, cmd.manual, cmd.signer)
		if cmd.alias and typeof(cmd.alias) == "table" then
			r:alias(cmd.alias)
		end
		-- The log viewer opts out of being written into the log it prints.
		r.silent = cmd.silent == true
	end
end
iterate(cmds)

--// Command Integrations
-- Commandle (https://github.com/officialmelon/commandle) is a command palette for
-- Studio. It publishes a `commandle_api` folder of BindableEvents under
-- StudioService that any plugin can push its own entries into, so Cealshell is
-- usable without touching the command bar.
--
-- Palette actions run with the Output window out of sight, so every one of them
-- reports back *into* the palette (see `feedback`). The full detail is saved by
-- `libs/log` either way and readable from the palette's own "Logs" entry.
local COMMANDLE_API = "commandle_api"

-- The palette is still animating (and, after a prompt, still in input mode) at
-- the moment a callback returns. Pushing a result view a beat later lets
-- Commandle finish its own transition first.
local FEEDBACK_DELAY = 0.2

local function trim(value: string?): string
	return (value or ""):match("^%s*(.-)%s*$") or ""
end

local function setupCommandle(api: Instance)
	-- Commandle parents the folder first and its bindables after, so a ChildAdded
	-- on StudioService hands us an empty folder — wait for each event.
	local createCommands = api:WaitForChild("createCommands", 10)
	local requestInput = api:WaitForChild("requestInput", 10)
	local pushRequest = api:WaitForChild("pushRequest", 10)
	local popRequest = api:WaitForChild("popRequest", 10)

	if not (createCommands and requestInput and pushRequest and popRequest) then
		log.warn("Commandle was found but its API is incomplete; palette entries were not registered.")
		return
	end

	-- A flow can stack several views: picking a package to remove pushes a list,
	-- the pending operation pushes a confirm step, and confirming pushes the
	-- result on top of that. Commandle pops one view per request, so track how
	-- deep we are and unwind all of it — otherwise "go back" from a result view
	-- lands on the confirm step it just answered.
	local depth = 0

	local function push(entries: { any })
		depth += 1
		pushRequest:Fire(entries)
	end

	local function goBack()
		for _ = 1, math.max(depth, 1) do
			popRequest:Fire()
		end
		depth = 0
	end

	-- Entry points reset the count: the user may have escaped out of a flow
	-- rather than backing out of it, which leaves `depth` stale.
	local function root(callback: () -> ()): () -> ()
		return function()
			depth = 0
			callback()
		end
	end

	-- Show a result as a read-only list in the palette: selecting any line (or
	-- pressing Escape) returns to where the user was. The commands themselves
	-- save the full detail; this is the short version.
	local function feedback(title: string, lines: { string }?)
		local entries = { { title = title, callback = goBack } }
		for _, line in lines or {} do
			table.insert(entries, { title = "   " .. line, callback = goBack })
		end

		task.delay(FEEDBACK_DELAY, function()
			push(entries)
		end)
	end

	-- Package work does blocking HTTP; run it off the palette's callback thread so
	-- Commandle can close its input prompt while we work.
	local function dispatch(command: string, tokens: { string }, done: (() -> ())?)
		task.spawn(function()
			reg:call(command, tokens)
			if done then
				done()
			end
		end)
	end

	-- install/remove/update stage themselves as a pending operation (nothing here
	-- passes -y), so the palette gets the same confirm/cancel step the command bar
	-- has. `fallback` is what to say when nothing was staged at all.
	local function reportPending(fallback: string)
		local kind = pmanager:pending()
		if not kind then
			feedback(fallback)
			return
		end

		task.delay(FEEDBACK_DELAY, function()
			push({
				{
					title = ("Confirm pending %s — the full plan is under 'cealshell: Logs'"):format(kind),
					callback = function()
						task.spawn(function()
							pmanager:confirm()
							feedback(("The %s finished — pick 'cealshell: Logs' for details."):format(kind))
						end)
					end,
				},
				{
					title = "Cancel",
					callback = function()
						pmanager:cancel()
						feedback("Operation cancelled.")
					end,
				},
			})
		end)
	end

	-- Ask for a line of text. Escape cancels the prompt outright (Commandle never
	-- calls back), so only a deliberate empty submit reaches us.
	local function prompt(message: string, handler: (string) -> ())
		requestInput:Fire(message, function(returnedValue: string)
			local value = trim(returnedValue)
			if value == "" then
				feedback("Nothing entered — cancelled.")
				return
			end
			handler(value)
		end)
	end

	local function promptInstall(scope: string, flags: { string })
		prompt(("Package(s) to install%s (provider/owner:package@version)"):format(scope), function(value)
			local tokens = value:split(" ")
			for _, flag in flags do
				table.insert(tokens, flag)
			end
			dispatch("install", tokens, function()
				reportPending("Nothing to install — pick 'cealshell: Logs' for details.")
			end)
		end)
	end

	local function chooseAndRemove()
		local entries = {}
		for _, shared in { false, true } do
			for _, name in pmanager:list(shared) do
				table.insert(entries, {
					title = ("%s  (%s)"):format(name, if shared then "shared" else "server"),
					callback = function()
						local tokens = { name }
						if shared then
							table.insert(tokens, "-s")
						end
						dispatch("remove", tokens, function()
							reportPending(("'%s' could not be removed — pick 'cealshell: Logs' for details."):format(name))
						end)
					end,
				})
			end
		end

		if #entries == 0 then
			feedback("No packages are installed.")
			return
		end

		table.insert(entries, 1, { title = "Select a package to remove:", callback = function() end })
		table.insert(entries, { title = "Return", callback = goBack })
		push(entries)
	end

	local function listPackages()
		local lines = {}
		for _, shared in { false, true } do
			local names = pmanager:list(shared)
			table.insert(lines, ("%s (%d):"):format(if shared then "shared — ReplicatedStorage" else "server — ServerStorage", #names))
			if #names == 0 then
				table.insert(lines, "  (none)")
			end
			for _, name in names do
				table.insert(lines, "  " .. name)
			end
		end
		feedback("Installed packages", lines)
	end

	-- The palette's window into the saved output. Only the tail fits comfortably
	-- in a list, so this shows the newest lines; `--c logs -a` has the rest.
	local LOG_TAIL = 40
	local LOG_WIDTH = 160

	local function showLogs()
		local total = log.count()
		if total == 0 then
			feedback("No saved output yet — run a command first.")
			return
		end

		local entries = {
			{
				title = ("Cealshell logs — newest %d of %d line%s"):format(
					math.min(LOG_TAIL, total),
					total,
					if total == 1 then "" else "s"
				),
				callback = goBack,
			},
		}

		-- Newest first: the palette shows the top of the list without scrolling,
		-- which is where the line you just caused is.
		local tail = log.recent(LOG_TAIL)
		for i = #tail, 1, -1 do
			local line = log.format(tail[i])
			if #line > LOG_WIDTH then
				line = line:sub(1, LOG_WIDTH - 1) .. "…"
			end
			table.insert(entries, { title = "   " .. line, callback = goBack })
		end

		table.insert(entries, {
			title = "Clear saved logs",
			callback = function()
				local removed = log.clear()
				feedback(("Cleared %d saved line%s."):format(removed, if removed == 1 then "" else "s"))
			end,
		})
		table.insert(entries, { title = "Return", callback = goBack })

		push(entries)
	end

	-- The registry already carries every command's description + manual, so the
	-- palette can browse them without a round trip through the Output window.
	local function browseCommands()
		local names = {}
		for name in reg.commands do
			table.insert(names, name)
		end
		table.sort(names)

		local entries = {}
		for _, name in names do
			local entry = reg.commands[name]
			local headline = ("%s — %s"):format(name, entry.description or "no description")

			table.insert(entries, {
				title = headline,
				callback = function()
					local lines = {}
					if #entry.aliases > 0 then
						table.insert(lines, "Aliases: " .. table.concat(entry.aliases, ", "))
						table.insert(lines, "")
					end

					-- A manual is either one line or an array of them; table
					-- manuals may also key subcommands, which we skip here.
					if typeof(entry.manual) == "string" then
						table.insert(lines, entry.manual)
					elseif typeof(entry.manual) == "table" then
						for _, line in ipairs(entry.manual) do
							if typeof(line) == "string" then
								table.insert(lines, line)
							end
						end
					else
						table.insert(lines, "No further information.")
					end

					feedback(headline, lines)
				end,
			})
		end

		table.insert(entries, 1, { title = "Select a command for its manual:", callback = function() end })
		table.insert(entries, { title = "Return", callback = goBack })
		push(entries)
	end

	local function runCommand()
		prompt("Cealshell command to run (e.g. 'install janis:signal -y')", function(value)
			local tokens = value:split(" ")
			local command = table.remove(tokens, 1)
			if not command or command == "" then
				feedback("No command given.")
				return
			end
			if not reg:resolve(command) then
				feedback(("Unknown command '%s'."):format(command), { "Pick 'cealshell: Commands & Manuals' for the full list." })
				return
			end
			dispatch(command, tokens, function()
				reportPending(("Ran '%s' — pick 'cealshell: Logs' for details."):format(command))
			end)
		end)
	end

	local function setRemote()
		local current = plugin:GetSetting("cealshell:remote")
		local shown = if typeof(current) == "string" and current ~= "" then current else "built-in default"

		requestInput:Fire(("Remote URL (empty resets to the default; now: %s)"):format(shown), function(returnedValue: string)
			local url = trim(returnedValue)
			if url == "" then
				dispatch("remote", { "reset" }, function()
					feedback("Remote reset to the built-in default.")
				end)
			else
				dispatch("remote", { "set", url }, function()
					feedback(("Remote set to %s"):format(url))
				end)
			end
		end)
	end

	local function status()
		local remote = plugin:GetSetting("cealshell:remote")
		local server = pmanager:list(false)
		local shared = pmanager:list(true)

		feedback(("Cealshell %s"):format(VERSION), {
			("Remote: %s"):format(if typeof(remote) == "string" and remote ~= "" then remote else "built-in default"),
			("Packages: %d server, %d shared"):format(#server, #shared),
			("Pending operation: %s"):format(pmanager:pending() or "none"),
			("Advanced mode: %s"):format(if plugin:GetSetting("cealshell:advanced") == true then "on" else "off"),
			("Saved log lines: %d"):format(log.count()),
		})
	end

	-- Every callback here starts from the palette's own list, so each is wrapped
	-- in `root` to zero the view counter that `goBack` unwinds.
	createCommands:Fire("main", {
		{
			title = "cealshell: Install Package",
			callback = root(function()
				promptInstall("", {})
			end),
		},
		{
			title = "cealshell: Install Package (Shared)",
			callback = root(function()
				promptInstall(" into ReplicatedStorage", { "-s" })
			end),
		},
		{
			title = "cealshell: Install Package (into Selection)",
			callback = root(function()
				promptInstall(" into the selected instance", { "-i" })
			end),
		},
		{
			title = "cealshell: Update All Packages",
			callback = root(function()
				dispatch("update", { "-a" }, function()
					reportPending("No updates available — pick 'cealshell: Logs' for details.")
				end)
			end),
		},
		{ title = "cealshell: Remove Package", callback = root(chooseAndRemove) },
		{ title = "cealshell: List Installed Packages", callback = root(listPackages) },
		{
			title = "cealshell: Pending Operation (Confirm / Cancel)",
			callback = root(function()
				reportPending("No pending operation.")
			end),
		},
		{ title = "cealshell: Logs", callback = root(showLogs) },
		{ title = "cealshell: Set Remote", callback = root(setRemote) },
		{ title = "cealshell: Run Command", callback = root(runCommand) },
		{ title = "cealshell: Commands & Manuals", callback = root(browseCommands) },
		{ title = "cealshell: Status", callback = root(status) },
	})

	log.info("Commandle detected — palette commands registered.")
end

-- Commandle recreates the whole folder when it reloads, so we key off the folder
-- instance: a new one means a fresh palette that needs our entries again. (The
-- API has no way to unregister, so reloading *Cealshell* against a still-running
-- Commandle leaves the previous entries behind until Commandle reloads too.)
local commandleApi: Instance? = nil
local function handleChild(child: Instance)
	if child.Name ~= COMMANDLE_API or child == commandleApi then
		return
	end
	commandleApi = child
	-- setupCommandle yields on WaitForChild; don't stall the ChildAdded signal.
	task.spawn(setupCommandle, child)
end
StudioService.ChildAdded:Connect(handleChild)
for _, child in StudioService:GetChildren() do
	handleChild(child)
end

--
log.echo("info", ("Loaded %s in %dms — output is saved too; run '--c logs' to read it back."):format(
	VERSION,
	math.floor((tick() - start) * 10 ^ 3)
))
if (string.find(plugin.Name, ".rbxm") or string.find(plugin.Name, ".lua")) and plugin:GetSetting("cealshell:no_local_warning") == false then
	log.echo("warn", "WARNING: Cealshell is running on a local plugin, which can correlate with the official plugin from the marketplace.\nIf you aren't using the marketplace version, use `--c config cealshell:no_local_warning true` to hide this for future startups.\n(Keep in mind that you have to rerun this every reinstallation)")
end