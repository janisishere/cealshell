--[[
	types.luau
	Shared type definitions for the Cealshell CLI.
]]

export type args = string | number | boolean

-- A command's manual: a single string, a list of lines, or a map of
-- subcommand name -> lines (for `manual <command> <subcommand>`).
export type manual = string | { string } | { [string]: string | { string } }

export type command = {
	name: string,
	arguments: { args }?,
	callback: (parsed: any) -> (),
	description: string?,
	manual: manual?,
	signer: string?,
	aliases: { string },
	-- Keep this command's own invocations out of the saved log.
	silent: boolean,
	alias: (self: command, new: string | { string }) -> (),
}

return {}
