--// Services
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerStorage = game:GetService("ServerStorage")

--// Modules
local types = require(script.Parent:FindFirstChild("types"))

--// Globals
local helper = {}

function helper:getNamedArg(argName:string, args:{types.args})
	for _, x in pairs(args) do
		if typeof(x) ~= "string" then continue end
		if x:sub(1, 2+argName:len()+1) == "--"..argName.."=" then
			return x:sub(2+argName:len()+1)
		end
	end
    return nil
end

function helper:doesArgExist(argName:string, args:{types.args})
	for _, x in pairs(args) do
		if typeof(x) ~= "string" then continue end
		if x:sub(1, 2+argName:len()) == "--"..argName then
			return true
		end
		if x:sub(1, 1+argName:len()) == "-"..argName then
			return true
		end
	end
    return nil
end

function helper:ensureIridiumPath(_shared: boolean?)
	local f
	if _shared then
		f = ReplicatedStorage:FindFirstChild(".iridium")
		if not f then
			f = Instance.new("Configuration", ReplicatedStorage)
			f.Name = ".iridium"
		end
	else
		f = ServerStorage:FindFirstChild(".iridium")
		if not f then
			f = Instance.new("Configuration", ServerStorage)
			f.Name = ".iridium"
		end
	end
	return f
end

return helper