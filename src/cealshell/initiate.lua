return function(plugin: Plugin)
	--// Services
	local LogService = game:GetService("LogService")
	local HttpService = game:GetService("HttpService")
	
	--// Locals
	local signer = "cealshell"

	--// Folders
	local Cealshell = script.Parent
	local libs = Cealshell:FindFirstChild("libs")

	--// Modules
	local registry = require(libs:FindFirstChild("registry"))
	local types = require(libs:FindFirstChild("types"))
	local helper = require(libs:FindFirstChild("helper"))
	local packager = require(libs:FindFirstChild("packager"))

	script:SetAttribute("uid", HttpService:GenerateGUID(false))
	registry:sign(script:GetAttribute("uid"))

	--// Settings
	local remotes = {}
	local trustedremotes = {
		"https://api.cealshell.dev/",
		-- Trusted Partners will be added here in the future.
	}
	
	local function saveRemotes()
		plugin:SetSetting("cealshell:remotes", remotes)
	end
	
	local firstTime = plugin:GetSetting("cealshell:startup") or false
	if firstTime ~= true then
		plugin:SetSetting("cealshell:startup", true)
		
		for _, remote in trustedremotes do
			if not table.find(remotes, remote) then
				table.insert(remotes, remote)
			end
		end
		saveRemotes()
	end
	local savedRemotes = plugin:GetSetting("cealshell:remotes")
	if savedRemotes and typeof(savedRemotes) == "table" then
		for _, x in pairs(savedRemotes) do
			table.insert(remotes, x)
		end
	end

	--// Register

	--c help
	registry:register("help", nil, function()
		print(string.rep("\n", 2))
		print("cealshell() 2026 ©")
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

	--c manual
	registry:register("manual", nil, function(args: {types.args})
		local cmdName = args[1]
		local subName = args[2]

		if not cmdName then
			warn("[Cealshell] Usage: manual <command> [subcommand]")
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
		print("cealshell() 2026 ©")
		print("------------")
		print("developed by janis")
		print("roblox: @the_h0lysandwich")
		print("discord: @_jxnis_")
		print("------------")
		print("published under Flux Studio")
		print("discord: .gg/Vpsyd59r5X")
	end, "Credits & Contacts for Cealshell.")

	--c rbxpackage
	registry:register("rbxpackage", nil, function(args:{types.args}, cArgs:{string})
		local action = args[1]
		if not action then
			print("No action given.")

		elseif table.find({"i", "install", "add"}, action) then
			local _shared = helper:doesArgExist("s", cArgs)
			local autoConfirm = helper:doesArgExist("y", cArgs)
			local i = helper:ensureCealshellPath(_shared)
			print("Looking for package(s) in remotes...")
			
			local lookingArgs = table.clone(args)
			lookingArgs[1] = nil
			
			local toInstall = {}
			
			for _, packageName in pairs(lookingArgs) do
				if typeof(packageName) ~= "string" then continue end
				
				local retrievedPackage = nil
				local hasUrl = packageName:find("/") ~= nil
				local hasAuthor = packageName:find(":") ~= nil
				
				if hasUrl then
					-- Full address format: url/author:package@version
					local packageUrl = packager:parse(packageName)
					local packageData = packager:retrieve(packageUrl)
					if packageData then
						local success, parsed = pcall(HttpService.JSONDecode, HttpService, packageData)
						if success and parsed then
							-- Extract data field if it exists (API response format)
							retrievedPackage = parsed.data or parsed
						end
					end
				elseif hasAuthor then
					-- Simplified format: author:package or author:package@version
					-- Use the first trusted remote
					local packageUrl = packager:parse(packageName, remotes[1] or "https://api.cealshell.dev")
					local packageData = packager:retrieve(packageUrl)
					if packageData then
						local success, parsed = pcall(HttpService.JSONDecode, HttpService, packageData)
						if success and parsed then
							-- Extract data field if it exists (API response format)
							retrievedPackage = parsed.data or parsed
						end
					end
				else
					-- Package name only, search all remotes
					for _, remote in pairs(remotes) do
						local packageUrl = remote .. packageName
						local packageData = packager:retrieve(packageUrl)
						if packageData then
							local success, parsed = pcall(HttpService.JSONDecode, HttpService, packageData)
							if success and parsed then
								-- Extract data field if it exists (API response format)
								retrievedPackage = parsed.data or parsed
								break
							end
						end
					end
				end
				
				if retrievedPackage then
					table.insert(toInstall, {name = packageName, data = retrievedPackage})
				else
					warn("Could not find package " .. packageName .. " in any remote")
				end
			end
			
			if #toInstall > 0 then
				-- Show preview of what will be installed
				print("\nPackages to install:")
				for _, pkg in pairs(toInstall) do
					print("  - " .. (pkg.name or "UNKNOWN"))
					if pkg.data and pkg.data.instances then
						print("    └─ " .. #pkg.data.instances .. " instances")
					end
					if pkg.data and pkg.data.dependencies and typeof(pkg.data.dependencies) == "table" then
						for _, dep in pairs(pkg.data.dependencies) do
							print("    └─ " .. dep)
						end
					end
				end
				print()
				
				if autoConfirm then
					-- Auto-confirm with --y flag
					for _, pkg in pairs(toInstall) do
						packager:build(pkg.data, i)
						print("Successfully installed " .. pkg.name)
					end
				end
			end

		elseif table.find({"rm", "uinstall", "uninstall", "remove"}, action) then
			local i = helper:ensureCealshellPath()
			print("Filtering for package(s) installed...")
			
			local _shared = helper:doesArgExist("s", cArgs)
			local autoConfirm = helper:doesArgExist("y", cArgs)
			
			local lookingArgs = table.clone(args)
			lookingArgs[1] = nil; lookingArgs[2] = nil
			local uninstalling = {}
			
			for _, x in i:GetChildren() do
				for _, y in lookingArgs do
					if x.Name:find(y) then
						table.insert(uninstalling, x)
					end
				end
			end
			
			if #uninstalling > 0 then
				local pkgNames = {}
				for _, pkg in pairs(uninstalling) do
					table.insert(pkgNames, pkg.Name)
				end
				print("Packages to uninstall:")
				for _, name in pairs(pkgNames) do
					print("  - " .. name)
				end
				print()
				
				if autoConfirm then
					-- Auto-confirm with --y flag
					for _, pkg in pairs(uninstalling) do
						pkg:Destroy()
						print("Uninstalled " .. pkg.Name)
					end
				else
					-- Wait for confirmation
				print("Type --c --y to confirm or --c --n to cancel")
					pacAwaiting = "uninstall"
					pacData = uninstalling
					pacSharedMode = _shared
				end
			else
				warn("No packages found matching the given names")
			end

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
			local i = helper:ensureCealshellPath()
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
	end, "Packet Manager for Cealshell.", {
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

	--c clear
	registry:register("clear", nil, function()
		print(string.rep("\n", 50))
	end, "Clears the console.", nil, signer):alias("cls")
	
	--// Misc
	plugin.Unloading:Connect(function()
		saveRemotes()
	end)
end