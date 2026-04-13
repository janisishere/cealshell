local submodules = {}
local folder = script.Parent.Parent:FindFirstChild("submodules")

export type submodule = {
    key: string,
	source: string,
    module: ModuleScript,
	loaded: boolean,
	load: (submodule) -> (),
}

export type listing = {
	any
}

submodules.__index = submodules
submodules.list = {} :: {listing}

local function stripComments(src)
    local result = {}
    local i = 1
    while i <= #src do
        -- Long comment
        if src:sub(i, i+3) == "--[[" then
            local close = src:find("]]", i+4, true)
            if close then
                -- preserve newlines so line tracking stays intact
                local chunk = src:sub(i, close+1)
                result[#result+1] = chunk:gsub("[^\n]", "")
                i = close + 2
            else
                break
            end
        -- Short comment
        elseif src:sub(i, i+1) == "--" then
            local close = src:find("\n", i, true) or #src
            i = close
        -- Long string
        elseif src:sub(i, i+1) == "[[" then
            local close = src:find("]]", i+2, true)
            result[#result+1] = src:sub(i, close+1)
            i = close + 2
        -- Short string
        elseif src:sub(i,i) == '"' or src:sub(i,i) == "'" then
            local q = src:sub(i,i)
            local j = i+1
            while j <= #src do
                if src:sub(j,j) == "\\" then j = j + 2
                elseif src:sub(j,j) == q then break
                else j = j + 1 end
            end
            result[#result+1] = src:sub(i, j)
            i = j + 1
        else
            result[#result+1] = src:sub(i, i)
            i = i + 1
        end
    end
    return table.concat(result)
end

local function getTopLevelFunctions(src)
    local cleaned = stripComments(src)
    local result = {}
    local i = 1
    local depth = 0

    while i <= #cleaned do
        local ch = cleaned:sub(i, i)

        -- Skip strings (already stripped comments, but strings remain)
        if ch == '"' or ch == "'" then
            local q = ch
            local j = i + 1
            while j <= #cleaned do
                if cleaned:sub(j,j) == "\\" then j = j + 2
                elseif cleaned:sub(j,j) == q then break
                else j = j + 1 end
            end
            if depth > 0 then
                result[#result+1] = cleaned:sub(i, j)
            end
            i = j + 1

        -- Long strings
        elseif cleaned:sub(i, i+1) == "[[" then
            local close = cleaned:find("]]", i+2, true)
            if depth > 0 then
                result[#result+1] = cleaned:sub(i, close+1)
            end
            i = close + 2

        -- Block openers that aren't functions
        elseif cleaned:sub(i):match("^%f[%w]if%f[%W]")
            or cleaned:sub(i):match("^%f[%w]while%f[%W]")
            or cleaned:sub(i):match("^%f[%w]for%f[%W]")
            or cleaned:sub(i):match("^%f[%w]do%f[%W]")
            or cleaned:sub(i):match("^%f[%w]repeat%f[%W]") then
            local kw = cleaned:sub(i):match("^(%a+)")
            if depth > 0 then
                result[#result+1] = kw
            end
            depth = depth + 1
            i = i + #kw

        elseif cleaned:sub(i):match("^%f[%w]then%f[%W]") then
            if depth > 0 then result[#result+1] = "then" end
            i = i + 4

        elseif cleaned:sub(i):match("^%f[%w]elseif%f[%W]") then
            if depth > 0 then result[#result+1] = "elseif" end
            i = i + 6

        elseif cleaned:sub(i):match("^%f[%w]else%f[%W]") then
            if depth > 0 then result[#result+1] = "else" end
            i = i + 4

        elseif cleaned:sub(i):match("^%f[%w]until%f[%W]") then
            depth = depth - 1
            if depth > 0 then result[#result+1] = "until" end
            i = i + 5

        elseif cleaned:sub(i):match("^%f[%w]end%f[%W\0]") then
            depth = depth - 1
            if depth > 0 then
                result[#result+1] = "end"
            else
                result[#result+1] = "end\n"
            end
            i = i + 3

        -- Function definitions (top-level or nested)
        elseif cleaned:sub(i):match("^%f[%w]function%f[%W]") then
            depth = depth + 1
            result[#result+1] = "function"
            i = i + 8

        elseif cleaned:sub(i):match("^%f[%w]local%s+function%f[%W]") then
            depth = depth + 1
            result[#result+1] = "local function"
            i = i + #(cleaned:sub(i):match("^local%s+function"))

        -- local x = function() — anonymous assigned to local
        elseif depth == 0 and cleaned:sub(i):match("^%f[%w]local%s+%w+%s*=%s*function%f[%W]") then
            depth = depth + 1
            local full = cleaned:sub(i):match("^(local%s+%w+%s*=%s*function)")
            result[#result+1] = full
            i = i + #full

        else
            if depth > 0 then
                result[#result+1] = ch
            end
            i = i + 1
        end
    end

    return table.concat(result)
end

function submodules.get(key: string) : submodule
    if type(key) ~= "string" then return nil end
    return submodules.list[key]
end

function submodules.new(key: string, source: string) : submodule
    if type(key) ~= "string" then return nil end
    if type(source) ~= "string" then return nil end
    local self = setmetatable({}, submodules)

    local identificator = "--@submodule"
    if source:sub(1, #identificator) ~= identificator then
        warn(("[Cealshell] Submodule '%s' has invalid syntax. (Missing --@submodule operator at first line)"))
    end

    self.key = key
    self.source = source
    self.loaded = false
    submodules.list[key] = self
    return self
end

function submodules:load()
    if not self.source or type(self.source) ~= "string" then return nil end

    local initialSource = self.source

    local identificator = "--@submodule"
    if initialSource:sub(1, #identificator) ~= identificator then
        warn(("[Cealshell] Submodule '%s' has invalid syntax. (Missing --@submodule operator at first line)"))
    end

    --[[
    local pubKey
    local pubKeyI = initialSource:find("--#")
    if pubKeyI then
        local endSuffix = initialSource:find("\n", #identificator+2)
        pubKey = initialSource:sub(pubKeyI+3, endSuffix-1)
    end
    ]]

    local funcs = getTopLevelFunctions(initialSource:sub(#identificator+2))--#pubKey+6))
        :gsub("function%s+(%w+)", "function submodule.%1")

    local source =
        ([[local submodule = {}

%s

return submodule]])
        :format(funcs)--pubKey, funcs)

    local module = Instance.new("ModuleScript", folder)
    module.Source = source
    module.Name = self.key

    self.loaded = true
end

return submodules