--// Modules
local types = require(script.Parent:FindFirstChild("types"))

--// Globals
local reg = {}
reg.commands = {} :: types.regtable
reg.callevent = Instance.new("BindableEvent", script)

function reg:register(command:string, args:{types.args}?, callback: (args:{types.args}, cArgs:{string}) -> (), description:string?, manual:string|{string}?, signer:string?)
	reg.commands[command] = {
		arguments=args,
		callback=callback,
		description=description,
		stored_aliases={},
		alias=function(self, new:string|{string})
			if typeof(new) == "string" then
				table.insert(self.stored_aliases, new)
				return
			end
			for _, x in pairs(new) do
				table.insert(self.stored_aliases, x)
			end
		end,
		signer=signer,
		manual=manual,
	}
	return reg.commands[command]
end

function reg:bindToCall(callback: (rcmd: string, args:{types.args}) -> ())
	reg.callevent.Event:Connect(callback)
end

function reg:call(command: string, givenArgs: {string})
	-- Resolve command or alias
	local rcmd = reg.commands[command]
	if not rcmd then
		for _, data in pairs(reg.commands) do
			if table.find(data.stored_aliases, command) then
				rcmd = data
				break
			end
		end
	end
	if not rcmd then warn("[Iridium] Invalid Command: " .. command); return end

	-- Transform Arguments
	local args = {}
	local cArgs = {}
	for _, x in pairs(givenArgs) do
		local xNum = tonumber(x)
		local xIsBool = (x == "true") or (x == "false")

		if xNum ~= nil then
			table.insert(args, xNum)
		elseif xIsBool then
			table.insert(args, x == "true")
		elseif x:sub(1,1) == "-" then
			table.insert(cArgs, x)
		else
			table.insert(args, x)
		end
	end

	-- Call Functions
	reg.callevent:Fire(rcmd, args, cArgs)
	rcmd.callback(args, cArgs)
end

return reg