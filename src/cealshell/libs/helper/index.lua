local ix = {}

function ix:read()
    local t = {}
    for _, x: Configuration in script:GetChildren() do
        t[x.Name] = x
    end
    return t
end

function ix:register(name: string, source: Instance) : Configuration
    if type(name) ~= "string" then return end
    if typeof(source) ~= "Instance" then return end

    local x = Instance.new("Configuration", script)
    x.Name = name

    local src = Instance.new("ObjectValue", x)
    src.Name = "source"
    src.Value = source

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