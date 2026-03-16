export type args = string|number|boolean
export type regtable = {
	arguments: {args},
	callback: () -> (),
	description: string?,
	manual: string | {string} | { [string]: string | {string} }?,
	signer: string?,
	stored_aliases: {string},
}
return {}