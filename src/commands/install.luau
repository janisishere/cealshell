local libs = script.Parent.Parent.libs
local pmanager = require(libs.pmanager)
local log = require(libs.log)

local Selection = game:GetService("Selection")

return {
	name = "install",
	callback = function(p)
		local into
		if p:has("i", "into") then
			local selection = Selection:Get()
			if not selection or #selection == 0 then
				log.warn("No instance selected. Select one in the Explorer to use -i.")
				return
			end
			into = selection[1]
		end

		pmanager:install({
			shared = p:has("s", "shared"),
			into = into,
			yes = p:has("y", "yes"),
		}, p.positionals)
	end,
	description = "Install one or more packages from GitHub, Wally or pesde.",
	manual = {
		"install <owner:repo>[@version] [...]",
		"Installs packages on demand through the proxy. Each package is referenced",
		"by its source repository or registry name — there is no central catalogue.",
		"",
		"Reference format:",
		"  owner:repo[@version]            (default provider + remote)",
		"  github/owner:repo[@version]     (explicit provider)",
		"  wally/scope:name[@range]        (the Wally registry)",
		"  pesde/scope:name[@range]        (the pesde registry)",
		"  host/owner:repo[@version]       (one-off remote override)",
		"",
		"Registry packages (wally, pesde) bring their dependencies with them: the",
		"whole graph is installed together and the package's own requires keep",
		"working. Their version accepts a semver range, e.g. '@^2' or '@>=1.0.0, <2.0.0'.",
		"",
		"A host prefix overrides the configured remote for that install only, e.g.",
		"'cshl.xlch.dev/janisfox:marble' resolves against https://cshl.xlch.dev. To",
		"change the remote for every install, use the 'remote set' command.",
		"",
		"Flags:",
		"  -s, --shared   Install into ReplicatedStorage instead of ServerStorage",
		"  -i, --into     Install into the currently selected instance (untracked)",
		"  -y, --yes      Skip the confirmation prompt",
		"",
		"Examples:",
		"  --c install janis:signal",
		"  --c install janis:signal@1.2.0 -s -y",
		"  --c install cshl.xlch.dev/janisfox:marble",
		"  --c install wally/sleitnick:component",
		"  --c install pesde/jiwonz:signal -s",
	},
	signer = "cealshell",
	alias = { "add", "i" },
}
