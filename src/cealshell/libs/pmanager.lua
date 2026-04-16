local libs = script.Parent
local packager = require(libs:FindFirstChild("packager"))
local helper = require(libs:FindFirstChild("helper"))

local UIS = game:GetService("UserInputService")
local HttpService = game:GetService("HttpService")

local plugin: Plugin
local pmanager = {}
pmanager.queue = {}

local function install(toInstall: {{any}}, i: Configuration)
    local ix = require(i[".index"])
    for _, pkg in pairs(toInstall) do
        ix:register(pkg.name, packager:build(pkg.data, i["src"]))
        print("Successfully installed " .. pkg.name)
    end
end

UIS.InputBegan:Connect(function(input)
    if #pmanager.queue > 0 then
        if input.KeyCode == Enum.KeyCode.Y then
            install(table.unpack(pmanager.queue[1]))
        elseif input.KeyCode == Enum.KeyCode.N then
            print("[Cealshell] Cancelling installation.")
        else
            return
        end
        table.remove(pmanager.queue, 1)
    end
end)

function pmanager:constructor(_plugin: Plugin)
    plugin = _plugin
end

function pmanager:check(share: boolean, name: string)
    local f = helper.ensureCealshellPath(share)
    local ix = require(f[".index"])
    return ix:read()[name] ~= nil
end

function pmanager:install(share: boolean, autoConfirm: boolean, remotes: {string}, packages: {string})
    local f = helper.ensureCealshellPath(share);
    local ix = require(f[".index"])

    -- Get package data
    local toInstall = {}
    for _, pkg in pairs(packages) do
        if type(pkg) ~= "string" then continue end
        
        local retrievedPackage = nil
        local hasUrl = pkg:find("/") ~= nil
        local hasAuthor = pkg:find(":") ~= nil

        if hasUrl then
            local packageUrl = packager:parse(pkg)
            local packageData = packager:retrieve(packageUrl)
            if packageData then
                local success, parsed = pcall(HttpService.JSONDecode, HttpService, packageData)
                if success and parsed then
                    retrievedPackage = parsed.data or parsed
                end
            end
        elseif hasAuthor then
            local packageUrl = packager:parse(pkg, remotes[1] or plugin:GetSetting("cealshell:remotes/default"))
            local packageData = packager:retrieve(packageUrl)
            if packageData then
                local success, parsed = pcall(HttpService.JSONDecode, HttpService, packageData)
                if success and parsed then
                    retrievedPackage = parsed.data or parsed
                end
            end
        else
            for _, remote in pairs(remotes) do
                local packageUrl = remote .. pkg
                local packageData = packager:retrieve(packageUrl)
                if packageData then
                    local success, parsed = pcall(HttpService.JSONDecode, HttpService, packageData)
                    if success and parsed then
                        retrievedPackage = parsed.data or parsed
                        break
                    end
                end
            end
        end
        
        if retrievedPackage then
            table.insert(toInstall, {name = pkg, data = retrievedPackage})
        else
            warn("[Cealshell] Could not find package " .. pkg .. " in any remote")
        end
    end

    -- Installation
    print()
    if #toInstall > 0 then
        print("Packages to install:")
        for _, pkg in pairs(toInstall) do
            print("  - " .. (pkg.name or "UNKNOWN"))
            if pkg.data and pkg.data.instances then
                print("    └─ " .. #pkg.data.instances .. " instances")
            end
            if pkg.data and pkg.data.dependencies and typeof(pkg.data.dependencies) == "table" then
                for _, dep in pairs(pkg.data.dependencies) do
                    print("    └─ " .. dep)
                end
            end
        end
        print()
        
        if autoConfirm then
            install(toInstall, f)
        else
            print("Continue installation? [Press y/n]")
            table.insert(pmanager.queue, {toInstall, f})
        end
    end
end

function pmanager:uninstall(share: boolean, autoConfirm: boolean, packages: {string})
    local f = helper.ensureCealshellPath(share);
    local ix = require(f[".index"])

    local t = ix:read()
    for _, pkg in pairs(packages) do
        if t[pkg] ~= nil then
            t[pkg].source.Value:Destroy()
            t[pkg]:Destroy()
            ix:deregister(pkg)
        end
    end
end

return pmanager