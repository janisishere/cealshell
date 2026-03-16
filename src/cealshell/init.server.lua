local start = tick()
--

--// Services
local LogService = game:GetService("LogService")

--// Folders
local libs = script:FindFirstChild("libs")

--// Modules
local reg = require(libs:FindFirstChild("registry"))
require(script.initiate)(plugin)

--// Binds
LogService.MessageOut:Connect(function(str: string, messageType: Enum.MessageType) 
	if messageType ~= Enum.MessageType.MessageOutput then return end

	local target = "> --c "
	if str:sub(1, target:len()) == target then
		str = str:sub(target:len()+1)
	else
		return
	end
	
	local split = str:split(" ")
	local cmd = split[1]
	split[1] = nil
	reg:call(cmd, split)
end)


--
print("[Cealshell] Loaded in", math.floor((tick() - start)*10^3) .."ms")