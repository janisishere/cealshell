--[[
	.index — the per-scope package registry.

	Each installed package is recorded as a Configuration child of this module,
	carrying metadata as attributes (owner / slug / version / remote / installedAt)
	so packages can later be listed and updated. The built instance is tagged
	with `Cealshell` and annotated with CealshellPackage / CealshellVersion /
	CealshellOwner attributes so it's identifiable in the Explorer.
]]

local CollectionService = game:GetService("CollectionService")

local INSTALL_TAG = "Cealshell"

export type meta = {
	owner: string?,
	slug: string?,
	version: string?,
	remote: string?,
	-- Which provider resolved this package (github, codeberg, wally, pesde…).
	-- Recorded so `update` re-requests it from the same place; absent on
	-- packages installed before providers other than GitHub existed.
	provider: string?,
}

local ix = {}

-- Exposed so callers (e.g. the package manager) can find/skip tagged instances
-- without hard-coding the tag name.
ix.INSTALL_TAG = INSTALL_TAG

-- Tag + annotate a built instance so it's identifiable in the Explorer AND
-- self-describing enough to be updated later — even when it was installed into a
-- selected instance and isn't tracked by any .index. Every field needed to
-- re-fetch the package (name / slug / owner / version / remote) is stored as an
-- attribute on the instance itself.
function ix:annotate(source: Instance, name: string, packageMeta: meta?)
	if typeof(source) ~= "Instance" then return end

	CollectionService:AddTag(source, INSTALL_TAG)
	source:SetAttribute("CealshellName", name)
	source:SetAttribute("CealshellPackage", (packageMeta and packageMeta.slug) or name)
	if packageMeta then
		if packageMeta.slug then source:SetAttribute("CealshellSlug", packageMeta.slug) end
		if packageMeta.owner then source:SetAttribute("CealshellOwner", packageMeta.owner) end
		if packageMeta.version then source:SetAttribute("CealshellVersion", packageMeta.version) end
		if packageMeta.remote then source:SetAttribute("CealshellRemote", packageMeta.remote) end
		if packageMeta.provider then source:SetAttribute("CealshellProvider", packageMeta.provider) end
	end
end

-- Read back the metadata stored on a tagged instance by ix:annotate.
function ix:readAnnotation(source: Instance): { name: string, slug: string?, owner: string?, version: string?, remote: string?, provider: string? }?
	if typeof(source) ~= "Instance" then return nil end
	local name = source:GetAttribute("CealshellName") or source:GetAttribute("CealshellPackage")
	if not name then return nil end
	return {
		name = name :: any,
		slug = source:GetAttribute("CealshellSlug") :: any,
		owner = source:GetAttribute("CealshellOwner") :: any,
		version = source:GetAttribute("CealshellVersion") :: any,
		remote = source:GetAttribute("CealshellRemote") :: any,
		provider = source:GetAttribute("CealshellProvider") :: any,
	}
end

function ix:read()
    local t = {}
    for _, x: Configuration in script:GetChildren() do
        t[x.Name] = x
    end
    return t
end

-- Read back the stored metadata for an installed package, if present.
function ix:meta(name: string): meta?
    local entry = script:FindFirstChild(name)
    if not entry then return nil end
    return {
        owner = entry:GetAttribute("owner") :: any,
        slug = entry:GetAttribute("slug") :: any,
        version = entry:GetAttribute("version") :: any,
        remote = entry:GetAttribute("remote") :: any,
        provider = entry:GetAttribute("provider") :: any,
    }
end

function ix:register(name: string, source: Instance, packageMeta: meta?) : Configuration
    if type(name) ~= "string" then return end
    if typeof(source) ~= "Instance" then return end

    local x = Instance.new("Configuration", script)
    x.Name = name

    -- Record metadata as attributes on the registry entry (drives updates).
    if packageMeta then
        if packageMeta.owner then x:SetAttribute("owner", packageMeta.owner) end
        if packageMeta.slug then x:SetAttribute("slug", packageMeta.slug) end
        if packageMeta.version then x:SetAttribute("version", packageMeta.version) end
        if packageMeta.remote then x:SetAttribute("remote", packageMeta.remote) end
        if packageMeta.provider then x:SetAttribute("provider", packageMeta.provider) end
    end
    x:SetAttribute("installedAt", os.time())

    local src = Instance.new("ObjectValue", x)
    src.Name = "source"
    src.Value = source

    -- Tag + annotate the built instance for visibility in the Explorer and so it
    -- carries everything an update needs (shared with untracked into-selection installs).
    ix:annotate(source, name, packageMeta)

    local idx = Instance.new("ModuleScript", script.Parent)
    idx.Name = name
    if source:FindFirstChild(".index") then
        idx.Source = source[".index"].Source
    elseif typeof(source) == "Instance" and source:IsA("ModuleScript") then
        idx.Source = ([[return require(script.Parent.src.%s)]]):format(source.Name)
    else
        warn(("[Cealshell] Unable to register '%s', no valid API found."):format(name))
    end

    local idxv = Instance.new("ObjectValue", x)
    idxv.Name = "index"
    idxv.Value = idx

    return x
end

function ix:deregister(name: string)
    if type(name) ~= "string" then return end
    if not script:FindFirstChild(name) then return end
    script[name].index.Value:Destroy()
    script[name]:Destroy()
end

return ix
