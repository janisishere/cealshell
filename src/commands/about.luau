local libs = script.Parent.Parent.libs
local log = require(libs.log)

return {
    name = "about",
    args = nil,
    callback = function()
        log.line("cealshell() 2026 MIT ©")
		log.line("------------")
		log.line("developed by janis")
		log.line("roblox: @the_h0lysandwich")
		log.line("discord: @_jxnis_")
		log.line("------------")
		log.line("discord: cealshell.dev/discord")
    end,
    description = "Credits & Contacts for Cealshell.",
    manual = nil,
    signer = "cealshell",
    alias = nil,
}
