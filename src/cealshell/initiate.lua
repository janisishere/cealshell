return function(plugin: Plugin)
	--// Services
	local LogService = game:GetService("LogService")
	
	--// Locals
	local signer = "iridium"

	--// Folders
	local iridium = script.Parent
	local libs = iridium:FindFirstChild("libs")

	--// Modules
	local registry = require(libs:FindFirstChild("registry"))
	local types = require(libs:FindFirstChild("types"))
	local helper = require(libs:FindFirstChild("helper"))

	--// Settings
	local remotes = {}
	local trustedremotes = {
		"https://iridium.xlch.dev/",
		-- Trusted Partners will be added here in the future.
	}
	
	local function saveRemotes()
		plugin:SetSetting("iridium:remotes", remotes)
	end
	
	local firstTime = plugin:GetSetting("iridium:startup") or false
	if firstTime ~= true then
		plugin:SetSetting("iridium:startup", true)
		
		for _, remote in trustedremotes do
			if not table.find(remotes, remote) then
				table.insert(remotes, remote)
			end
		end
		saveRemotes()
	end
	local savedRemotes = plugin:GetSetting("iridium:remotes")
	if savedRemotes and typeof(savedRemotes) == "table" then
		for _, x in pairs(savedRemotes) do
			table.insert(remotes, x)
		end
	end

	--// Register

	--i help
	registry:register("help", nil, function()
		print(string.rep("\n", 2))
		print("iridium() 2026 ©")
		print("made by janis under Flux Studio")
		print("--------------------------------")
		for cmd:string, data:types.regtable in pairs(registry.commands) do
			if data.arguments then
				local argsString = ""
				local i = 0
				for x, y in data.arguments do
					i += 1
					argsString = argsString .. "<" .. x .. ">" .. (data.arguments[i+1] and " " or "")
				end
				print(cmd, argsString, "-", data.description or "no description")
			else
				print(cmd, "-", data.description or "no description")
			end
		end
	end, "Shows a list of commands.", nil, signer):alias("?")

	--i manual
	registry:register("manual", nil, function(args: {types.args})
		local cmdName = args[1]
		local subName = args[2]

		if not cmdName then
			warn("[Iridium] Usage: manual <command> [subcommand]")
			return
		end

		local vData = registry.commands[cmdName]
		if not vData then
			warn("Failed to load manual for " .. tostring(cmdName) .. ": Invalid Command.")
			return
		end

		-- Subcommand path
		if subName then
			local subManual
			if typeof(vData.manual) == "table" then
				subManual = vData.manual[subName]
			end

			if not subManual then
				warn("No manual entry for subcommand '" .. subName .. "' under '" .. cmdName .. "'.")
				return
			end

			print(cmdName .. " " .. subName .. " — Subcommand Manual")
			if typeof(subManual) == "string" then
				print(subManual)
			else
				for _, line in pairs(subManual) do
					print(line)
				end
			end
			return
		end

		local manual
		if vData.manual then
			if typeof(vData.manual) == "table" then
				local lines = {}
				for k, v in pairs(vData.manual) do
					if typeof(k) == "number" then
						table.insert(lines, v)
					end
				end
				manual = #lines > 0 and lines or {"No further information to display."}
			elseif typeof(vData.manual) == "string" then
				manual = {vData.manual}
			end
		else
			manual = {"No further information to display."}
		end

		print(cmdName .. " Manual")
		print("Description:", vData.description or "No description")
		print("Signer:", vData.signer or "Unknown")
		print("Aliases:", table.concat(vData.stored_aliases, ", ") or "None")
		local argString = "None given."
		if typeof(vData.arguments) == "table" and #vData.arguments > 0 then
			for i, v in pairs(vData.arguments) do
				local parsed = i.." | ".. v
				argString = argString == "None given." and parsed or argString .. ", " .. parsed
			end
		end
		print("Arguments:", argString)
		print("Detailed Description:")
		for _, line in pairs(manual) do
			print(line)
		end
		if typeof(vData.manual) == "table" then
			local subs = {}
			for k in pairs(vData.manual) do
				if typeof(k) == "string" then
					table.insert(subs, k)
				end
			end
			if #subs > 0 then
				print("Subcommand manuals available: " .. table.concat(subs, ", "))
				print("Use: man " .. cmdName .. " <subcommand>")
			end
		end
	end, "Shows more information about a command.", nil, signer):alias("man")

	--i about
	registry:register("about", nil, function()
		print("iridum() 2026 ©")
		print("------------")
		print("developed by janis")
		print("roblox: @the_h0lysandwich")
		print("discord: @_jxnis_")
		print("------------")
		print("published under Flux Studio")
		print("discord: .gg/Vpsyd59r5X")
	end, "Credits & Contacts for Iridium.")

	--i rbxpackage
	local pacAwaiting = false
	local pacData = {}
	
	registry:register("rbxpackage", nil, function(args:{types.args}, cArgs:{string})
		local action = args[1]
		if not action then
			print("No action given.")

		elseif table.find({"i", "install", "add"}, action) then
			local i = helper:ensureIridiumPath()
			print("Looking for package(s) in remotes...")
			print("THIS IS UNFINISHED; NO ACTION CONTINUED")

		elseif table.find({"rm", "uinstall", "uninstall", "remove"}, action) then
			local i = helper:ensureIridiumPath()
			print("Filtering for package(s) installed...")
			
			local _shared = helper:doesArgExist("s", cArgs)
			
			local lookingArgs = table.clone(args)
			lookingArgs[1] = nil; lookingArgs[2] = nil
			local uninstalling = {}
			for _, x in i:GetChildren() do
				for _, y in lookingArgs do
					if x.Name:find(y) then
						table.insert(uninstalling, x)
						return
					end
				end
			end
			
			print("Uninstalling following "..(_shared and "shared" or "").." packages: ", table.concat(uninstalling, ", "))
			print("Continue? [--y/--n]")
			pacAwaiting = "uninstall"
			pacData = uninstalling

		elseif action == "remote" then
			local subaction = args[2]
			if not subaction then
				print("No subcommand given.")
			elseif subaction == "list" then
				print("List of active remotes:")
				for _, x in pairs(remotes) do
					print(x)
				end
			elseif subaction == "add" then
				local remote = args[3]
				if not remote then
					print("No remote given.")
					return
				end
				if not table.find(remotes, remote) then
					table.insert(remotes, remote)
					print("Added remote '" .. remote .. "' to registry.")
				else
					print("Remote '" .. remote .. "' already registered.")
				end
			elseif table.find({"rm", "remove", "delete"}, subaction) then
				local remote = args[3]
				if not remote then
					print("No remote given.")
					return
				end
				if table.find(remotes, remote) then
					table.remove(remotes, table.find(remotes, remote))
					print("Removed remote '" .. remote .. "' from registry.")
				else
					print("Remote '" .. remote .. "' not registered.")
				end
			else
				print("Unknown subcommand.")
			end
			
		elseif action == "list" then
			local i = helper:ensureIridiumPath()
			local p = args[2]
			for _, x in i:GetChildren() do
				if p then
					if x.Name:find(p) then
						print(x.Name)
					end
				else
					print(x.Name)
				end
			end
			
		else
			print("Unknown subcommand.")
		end
	end, "Packet Manager for Iridium.", {
		[1] = "Manages packages from configured remotes.",

		["install"] = {
			"rbxpackage i/install/add <package>",
			"Installs one or more packages from your registered remotes.",
			"Example: rbxpackage install DataStore2",
		},
		["remove"] = {
			"rbxpackage rm/uninstall/remove <package>",
			"Removes an installed package from your workspace.",
		},
		["search"] = {
			"rbxpackage search <package>",
			"Searches for a package from active remotes.",
		},
		["remote"] = {
			"rbxpackage remote add <url> — adds a remote source",
			"rbxpackage remote rm/remove/delete <url> — removes a remote source",
			"rbxpackage remote list — lists all active remotes",
		},
		["list"] = {
			"rbxpackage list <package?>",
			"lists all installed packages"
		}
	}, signer):alias({"rbxp", "pacman"})

	--i clear
	registry:register("clear", nil, function()
		print(string.rep("\n", 50))
	end, "Clears the console.", nil, signer):alias("cls")
	
	--// Misc
	plugin.Unloading:Connect(function()
		saveRemotes()
	end)
end