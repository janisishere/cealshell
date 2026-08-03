--[[
	pmanager.luau
	The package manager core: install, uninstall, update and list.
	Commands are thin wrappers around these methods.

	Cealshell is a pure proxy — there is no central catalogue/keyring. Every
	package is installed by an explicit reference and resolved on demand:
		GET <remote>/github/<owner>:<repo>@<version>  -> install payload

	The same shape serves package registries, which additionally resolve the
	package's dependency graph before returning it:
		GET <remote>/wally/<scope>:<name>@<range>
		GET <remote>/pesde/<scope>:<name>@<range>
]]

local libs = script.Parent
local packager = require(libs:FindFirstChild("packager"))
local helper = require(libs:FindFirstChild("helper"))
local log = require(libs:FindFirstChild("log"))
-- The .index template module also exposes the tag name + annotate/readAnnotation
-- helpers used to tag and rediscover instance-installed (into-selection) packages.
local ixlib = require(libs:FindFirstChild("helper"):FindFirstChild("index"))

local HttpService = game:GetService("HttpService")
local Selection = game:GetService("Selection")
local CollectionService = game:GetService("CollectionService")

-- The built-in remote, used when neither the reference nor the setting overrides it.
local DEFAULT_REMOTE = "https://api.cealshell.dev"

local plugin: Plugin
local pmanager = {}
pmanager.pendingOperation = nil :: any

function pmanager:constructor(_plugin: Plugin)
	plugin = _plugin
end

-- The single configured remote, falling back to the built-in default.
local function configuredRemote(): string
	local remote = plugin:GetSetting("cealshell:remote")
	if typeof(remote) == "string" and remote ~= "" then
		return remote
	end
	return DEFAULT_REMOTE
end

-- Check if a package is installed (in the given storage scope).
function pmanager:check(share: boolean, name: string): boolean
	local f = helper:ensureCealshellPath(share)
	return require(f[".index"]):read()[name] ~= nil
end

-- A prefix segment is a remote host (rather than a provider name) when it looks
-- like a domain: it carries a dot, a port colon, or is bare `localhost`. Provider
-- names (github, codeberg, …) are plain identifiers and never match.
local function looksLikeRemote(segment: string): boolean
	return segment:find("%.") ~= nil or segment:find(":") ~= nil or segment == "localhost"
end

-- Parse a `[remote/][provider/]owner:repo[@version]` reference for the proxy.
--   janisfox:marble                      -> github, latest, configured remote
--   github/janisfox:marble@1.0.0         -> provider github, 1.0.0
--   wally/sleitnick:component@^2         -> the Wally registry, semver range
--   pesde/jiwonz:signal                  -> the pesde registry, latest
--   cshl.xlch.dev/janisfox:marble        -> one-off remote https://cshl.xlch.dev
--   cshl.xlch.dev/github/janisfox:marble -> one-off remote + explicit provider
--   https://host:8080/janisfox:marble    -> one-off remote with explicit scheme
-- A remote override applies to this install only and never touches the setting.
-- Returns nil for a bare slug (no ':') — every install needs a full reference.
local function parseProxyRef(reference: string)
	local remaining, remote = reference, nil

	-- An explicit scheme means the leading token is a full remote base URL; pull
	-- it off whole so its own `:`/`/` characters don't confuse the segment split.
	local scheme = remaining:match("^https?://")
	if scheme then
		local rest = remaining:sub(#scheme + 1)
		local slash = rest:find("/")
		if not slash then
			return nil
		end
		remote = scheme .. rest:sub(1, slash - 1)
		remaining = rest:sub(slash + 1)
	end

	local head, version = remaining, "latest"
	local at = remaining:find("@")
	if at then
		head = remaining:sub(1, at - 1)
		version = remaining:sub(at + 1)
	end
	if version == "" then
		version = "latest"
	end

	-- `owner:repo` is always the final slash-delimited segment; any segments
	-- before it are an optional remote host and/or provider name (any order).
	local segments = head:split("/")
	local target = table.remove(segments)
	if not target then
		return nil
	end

	local provider = "github"
	for _, segment in segments do
		if segment == "" then
			continue
		elseif looksLikeRemote(segment) then
			remote = "https://" .. segment
		else
			provider = segment
		end
	end

	local colon = target:find(":")
	if not colon then
		return nil
	end
	local owner = target:sub(1, colon - 1)
	local repo = target:sub(colon + 1)
	if provider == "" or owner == "" or repo == "" then
		return nil
	end
	return { provider = provider, owner = owner, repo = repo, version = version, remote = remote }
end

-- Validate + decode a proxy/v2 response envelope, returning its `data` payload.
local function decodeEnvelope(body: string?): any?
	if not body then
		return nil
	end
	local ok, parsed = pcall(HttpService.JSONDecode, HttpService, body)
	if not ok or typeof(parsed) ~= "table" or not parsed.ok or typeof(parsed.data) ~= "table" then
		return nil
	end
	return parsed.data
end

-- Fetch an install payload straight from the GitHub proxy. A per-reference remote
-- (parsed from the reference, or a remote stored on an installed package) overrides
-- the configured remote for that one call; otherwise the configured remote is used.
local function fetchProxyPayload(
	ref: { owner: string, repo: string, version: string, provider: string?, remote: string? }
): (any?, string?)
	local remote = ref.remote or configuredRemote()
	local url = packager:proxyUrl(ref.owner, ref.repo, ref.version, remote, ref.provider)
	local data = decodeEnvelope(packager:retrieve(url))
	if data then
		return data, remote
	end
	return nil
end

-- Internal: actually create the instances.
local function executeInstall(toInstall: { any }, targetFolder: Instance, intoSelection: boolean)
	local ix = if intoSelection then nil else require(targetFolder:FindFirstChild(".index"))

	for _, pkg in toInstall do
		local parent = ix and targetFolder:FindFirstChild("src") or targetFolder
		local source = packager:build(pkg.data, parent)
		local meta = {
			owner = pkg.owner,
			slug = pkg.slug,
			version = pkg.version,
			remote = pkg.remote,
			provider = pkg.provider,
		}
		if ix and source then
			ix:register(pkg.name, source, meta)
		elseif source then
			-- Untracked install into a selected instance: still tag + annotate it so
			-- it's identifiable and `update` can rediscover and upgrade it later.
			ixlib:annotate(source, pkg.name, meta)
		end
		log.ok(("Installed '%s' (%s)."):format(pkg.name, pkg.version or "latest"))
	end

	-- Tell the user how to require what they just installed.
	if not intoSelection and #toInstall > 0 then
		local root = targetFolder.Parent
		local manifestName = if root:FindFirstChild("CealPackages") then "CealPackages" else "Packages"
		log.info(("Require with: local Packages = require(game.%s.%s)"):format(root.Name, manifestName))
	end
end

-- Internal: replace an already-installed package in place (used by update).
local function rebuildInstalled(folder: Instance, name: string, data: any, meta: any)
	local ix = require(folder:FindFirstChild(".index"))
	local existing = ix:read()[name]
	if existing and existing:FindFirstChild("source") and existing.source.Value then
		existing.source.Value:Destroy()
	end
	ix:deregister(name)

	local source = packager:build(data, folder:FindFirstChild("src"))
	if source then
		ix:register(name, source, meta)
	end
end

-- Internal: replace an instance-installed (into-selection) package in place.
-- These have no .index entry — they're identified solely by the Cealshell tag +
-- attributes — so we rebuild into the old instance's parent and re-annotate.
local function rebuildStandalone(source: Instance, name: string, data: any, meta: any): Instance?
	local parent = source.Parent
	source:Destroy()
	local newSource = packager:build(data, parent)
	if newSource then
		ixlib:annotate(newSource, name, meta)
	end
	return newSource
end

-- Internal: actually remove the instances.
local function executeUninstall(toRemove: { string }, folder: Instance)
	local ix = require(folder:FindFirstChild(".index"))
	local packages = ix:read()
	for _, name in toRemove do
		local pkgConfig = packages[name]
		if pkgConfig and pkgConfig:FindFirstChild("source") and pkgConfig.source.Value then
			pkgConfig.source.Value:Destroy()
		end
		ix:deregister(name)
		log.ok(("Uninstalled '%s'."):format(name))
	end
end

-- opts: { shared: boolean?, into: Instance?, yes: boolean? }
function pmanager:install(opts: { shared: boolean?, into: Instance?, yes: boolean? }, packages: { string })
	if #packages == 0 then
		log.usage("install <package>[@version] [...]  (flags: -s shared, -y yes, -i into selection)")
		return
	end

	local intoSelection = opts.into ~= nil
	local targetFolder = if intoSelection then opts.into :: Instance else helper:ensureCealshellPath(opts.shared)

	local toInstall = {}
	-- Names already queued this run, so the same package referenced twice in one
	-- command isn't built twice. Tracked installs are additionally checked against
	-- what's already in the scope's .index below.
	local queued: { [string]: boolean } = {}

	-- Resolve a single proxy reference into a toInstall entry (or warn).
	local function addFromProxy(proxyRef: any, reference: string)
		local data, remote = fetchProxyPayload(proxyRef)
		if not data then
			log.warn(("Package '%s' not found on any remote (tried the %s proxy)."):format(reference, proxyRef.provider))
			return
		end
		local name = (data.package and data.package.repo) or proxyRef.repo

		-- Don't install the same package twice. Within a single command we skip a
		-- repeated reference; for tracked installs we also skip anything already in
		-- the target scope's .index (into-selection installs aren't tracked, so the
		-- caller is free to place multiple copies in different instances).
		if queued[name] or (not intoSelection and pmanager:check(opts.shared :: any, name)) then
			log.info(("'%s' is already installed; skipping."):format(name))
			return
		end
		queued[name] = true

		table.insert(toInstall, {
			name = name,
			slug = (data.package and data.package.slug) or proxyRef.repo:lower(),
			owner = (data.package and data.package.owner) or proxyRef.owner,
			remote = remote,
			-- Recorded so `update` re-resolves through the same provider; a
			-- wally package must not be looked up on GitHub later.
			provider = (data.package and data.package.provider) or proxyRef.provider,
			version = (data.package and data.package.version) or proxyRef.version,
			-- Registry packages (wally/pesde) report what the dependency walk
			-- pulled in; source providers omit this entirely.
			dependencies = data.dependencies,
			data = data,
		})
	end

	for _, reference in packages do
		if typeof(reference) ~= "string" or reference == "" then continue end

		-- Every install is resolved on demand through the GitHub proxy. A bare
		-- slug can't be resolved without an owner, so require a full reference.
		local proxyRef = parseProxyRef(reference)
		if proxyRef then
			addFromProxy(proxyRef, reference)
		else
			log.warn(("Invalid reference '%s'. Use owner:repo[@version], e.g. 'janis:signal' or 'wally/sleitnick:component'."):format(reference))
		end
	end

	if #toInstall == 0 then
		log.info("Nothing to install.")
		return
	end

	log.line()
	log.line("Packages to install:")
	for _, pkg in toInstall do
		local count = if pkg.data.instances then #pkg.data.instances else 0
		log.line(("  - %s (%d instance%s)"):format(pkg.name, count, if count == 1 then "" else "s"))
		-- Registry packages bring their dependency graph with them; list it so
		-- the confirmation prompt shows everything that is about to be added.
		if pkg.dependencies then
			for _, dep in pkg.dependencies do
				log.line(("      + %s/%s@%s"):format(dep.owner, dep.name, dep.version))
			end
		end
	end
	log.line()

	if opts.yes then
		executeInstall(toInstall, targetFolder, intoSelection)
	else
		pmanager.pendingOperation = {
			kind = "install",
			run = function()
				executeInstall(toInstall, targetFolder, intoSelection)
			end,
		}
		log.info("Type '--c confirm' to proceed or '--c cancel' to abort.")
	end
end

-- opts: { shared: boolean?, yes: boolean? }
function pmanager:uninstall(opts: { shared: boolean?, yes: boolean? }, packages: { string })
	if #packages == 0 then
		log.usage("remove <package> [...]  (flags: -s shared, -y yes)")
		return
	end

	local folder = helper:ensureCealshellPath(opts.shared)
	local installed = require(folder[".index"]):read()

	local toRemove = {}
	for _, name in packages do
		if typeof(name) == "string" and installed[name] then
			table.insert(toRemove, name)
		else
			log.warn(("Package '%s' is not installed."):format(tostring(name)))
		end
	end

	if #toRemove == 0 then
		log.info("Nothing to uninstall.")
		return
	end

	log.line()
	log.line("Packages to remove:")
	for _, name in toRemove do
		log.line("  - " .. name)
	end
	log.line()

	if opts.yes then
		executeUninstall(toRemove, folder)
	else
		pmanager.pendingOperation = {
			kind = "uninstall",
			run = function()
				executeUninstall(toRemove, folder)
			end,
		}
		log.info("Type '--c confirm' to proceed or '--c cancel' to abort.")
	end
end

-- Update installed packages to their latest version on the GitHub proxy.
-- opts: { shared: boolean?, all: boolean?, yes: boolean? }
--   default scope is server; `shared` targets ReplicatedStorage; `all` does both.
-- `packages` optionally restricts the update to specific names/slugs.
function pmanager:update(opts: { shared: boolean?, all: boolean?, yes: boolean? }, packages: { string })
	local scopes = if opts.all then { false, true } elseif opts.shared then { true } else { false }
	local filtering = #packages > 0

	-- Build the plan: every installed package whose latest differs from installed.
	local plan = {}

	-- Track every .index-managed source instance (across BOTH scopes, regardless
	-- of the requested scope) so the standalone pass below never double-handles
	-- a tracked package's instance.
	local managedSources: { [Instance]: boolean } = {}
	for _, shared in { false, true } do
		local folder = helper:ensureCealshellPath(shared)
		local ix = require(folder[".index"])
		for _, entry in ix:read() do
			local srcVal = entry:FindFirstChild("source")
			if srcVal and srcVal.Value then
				managedSources[srcVal.Value] = true
			end
		end
	end

	for _, shared in scopes do
		local folder = helper:ensureCealshellPath(shared)
		local ix = require(folder[".index"])
		for name, entry in ix:read() do
			local slug = entry:GetAttribute("slug") or name
			if filtering and not table.find(packages, name) and not table.find(packages, slug) then
				continue
			end

			local owner = entry:GetAttribute("owner")
			if not owner then
				log.warn(("'%s' has no source owner recorded; reinstall it to enable updates."):format(name))
				continue
			end

			local installedVersion = entry:GetAttribute("version")
			-- Re-resolve through the provider the package came from, and by the
			-- slug it was published under: registry package names are lowercase
			-- while the installed instance is capitalised ('component' vs
			-- 'Component'), so `name` is not a valid lookup key there.
			local payload, remote = fetchProxyPayload({
				provider = entry:GetAttribute("provider"),
				owner = owner,
				repo = slug,
				version = "latest",
				remote = entry:GetAttribute("remote"),
			})
			local latest = payload and payload.package and payload.package.version
			if latest and latest ~= installedVersion then
				table.insert(plan, {
					shared = shared,
					name = name,
					slug = slug,
					owner = owner,
					remote = remote,
					provider = entry:GetAttribute("provider"),
					data = payload,
					from = installedVersion or "?",
					to = latest,
				})
			end
		end
	end

	-- Standalone pass: instance-installed (into-selection) packages aren't in any
	-- .index — they're identified by the Cealshell tag + attributes. Rediscover
	-- them so they can be updated too, resolving the latest from the proxy.
	for _, source in CollectionService:GetTagged(ixlib.INSTALL_TAG) do
		if managedSources[source] then
			continue
		end
		local ann = ixlib:readAnnotation(source)
		if not ann or not ann.owner then
			continue
		end
		local slug = ann.slug or ann.name
		if filtering and not table.find(packages, ann.name) and not table.find(packages, slug) then
			continue
		end

		local payload, remote = fetchProxyPayload({
			provider = ann.provider,
			owner = ann.owner,
			repo = slug,
			version = "latest",
			remote = ann.remote,
		})
		local latest = payload and payload.package and payload.package.version

		if latest and latest ~= ann.version then
			table.insert(plan, {
				standalone = source,
				name = ann.name,
				slug = slug,
				owner = ann.owner,
				remote = remote,
				provider = ann.provider,
				data = payload,
				from = ann.version or "?",
				to = latest,
			})
		end
	end

	if #plan == 0 then
		log.ok("Everything is up to date.")
		return
	end

	log.line()
	log.line("Packages to update:")
	for _, item in plan do
		local scopeLabel = if item.standalone then "selection" elseif item.shared then "shared" else "server"
		log.line(("  - %s  %s → %s  (%s)"):format(item.name, item.from, item.to, scopeLabel))
	end
	log.line()

	local run = function()
		for _, item in plan do
			-- The latest payload was already fetched during planning.
			local data = item.data
			if not data and item.owner then
				data = fetchProxyPayload({
					provider = item.provider,
					owner = item.owner,
					repo = item.slug or item.name,
					version = "latest",
					remote = item.remote,
				})
			end
			if not data then
				log.warn(("Failed to fetch update for '%s'."):format(item.name))
				continue
			end

			local meta = {
				owner = item.owner,
				slug = item.slug,
				version = (data.package and data.package.version) or item.to,
				remote = item.remote,
				provider = item.provider,
			}

			if item.standalone then
				rebuildStandalone(item.standalone, item.name, data, meta)
			else
				local folder = helper:ensureCealshellPath(item.shared)
				rebuildInstalled(folder, item.name, data, meta)
			end
			log.ok(("Updated '%s' to %s."):format(item.name, item.to))
		end
	end

	if opts.yes then
		run()
	else
		pmanager.pendingOperation = { kind = "update", run = run }
		log.info("Type '--c confirm' to proceed or '--c cancel' to abort.")
	end
end

-- List installed package names (optionally filtered by a substring pattern).
function pmanager:list(share: boolean?, pattern: string?): { string }
	local folder = helper:ensureCealshellPath(share)
	local names = {}
	for name in require(folder[".index"]):read() do
		if not pattern or name:find(pattern) then
			table.insert(names, name)
		end
	end
	table.sort(names)
	return names
end

-- Confirm the pending operation.
function pmanager:confirm(): boolean
	local op = pmanager.pendingOperation
	if not op then
		log.info("No pending operation to confirm.")
		return false
	end
	pmanager.pendingOperation = nil
	op.run()
	return true
end

-- Describe the pending operation (used by the confirm command's preview).
function pmanager:pending(): string?
	return pmanager.pendingOperation and pmanager.pendingOperation.kind or nil
end

-- Cancel the pending operation.
function pmanager:cancel(): boolean
	if pmanager.pendingOperation then
		pmanager.pendingOperation = nil
		log.info("Operation cancelled.")
		return true
	end
	log.info("No pending operation to cancel.")
	return false
end

return pmanager
