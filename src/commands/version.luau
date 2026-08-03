local libs = script.Parent.Parent.libs
local log = require(libs.log)

local plugin

return {
    name = "version",
    args = nil,
    constructor = function(pl: Plugin)
		plugin = pl
	end,
    callback = function()
        log.info(("Running Cealshell on version %s"):format(tostring(plugin:GetSetting("cealshell:version"))))
    end,
    description = "Shows your cealshell version.",
    manual = nil,
    signer = "cealshell",
    alias = nil,
}
