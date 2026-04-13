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
		if x:sub(1, 1+argName:len()) == "--"..argName then
			return true
		end
		if x:sub(1, 1) == "-" then
			local flags = x:sub(2)
			for i = 1, #flags do
				if flags:sub(i,i) == argName then
					return true
				end
			end
		end
	end
    return nil
end

function helper:ensureCealshellPath(_shared: boolean?)
	local f
	if _shared then
		f = ReplicatedStorage:FindFirstChild(".cealshell")
		if not f then
			f = Instance.new("Configuration", ReplicatedStorage)
			f.Name = ".cealshell"
		end
	else
		f = ServerStorage:FindFirstChild(".cealshell")
		if not f then
			f = Instance.new("Configuration", ServerStorage)
			f.Name = ".cealshell"
		end
	end

	if not f:FindFirstChild("src") then
		local src = Instance.new("Folder", f)
		src.Name = "src"
	end

	return f
end

return helper