--// Services
local HttpService = game:GetService("HttpService")

--// Globals
local packager = {}

function packager:parse(package: string, remoteUrl: string?)
    remoteUrl = remoteUrl or "https://api.cealshell.dev"

    -- Normalize remote URL: remove trailing slash if present
    if remoteUrl:sub(-1) == "/" then
        remoteUrl = remoteUrl:sub(1, -2)
    end

    -- Check if package address contains "/" (full URL format)
    if package:find("/") then
        local s1 = package:split("/")
        assert(#s1 >= 2, "Invalid address")

        local s2 = s1[2]:split(":")
        assert(#s2 >= 2, "Missing ':'")

        local s3 = s2[2]:split("@")
        assert(#s3 >= 2, "Missing '@'")

        local url = s1[1]
        local author = s2[1]
        local packageName = s3[1]
        local version = s3[2]

        -- Preserve scheme from URL or default to https
        local scheme = "https"
        if url:match("^https?://") then
            scheme = url:match("^(https?)://")
            url = url:match("^https?://(.*)$")
        end
        
        local final = ("%s://%s/%s/%s/%s"):format(scheme, url, author, packageName, version)
        return final
    else
        -- Simplified format: author:package[@version]
        local parts = package:split(":")
        assert(#parts >= 2, "Invalid format. Use author:package or author:package@version")

        local author = parts[1]
        local restParts = table.concat(parts, ":", 2):split("@")
        local packageName = restParts[1]
        local version = restParts[2] or "latest"

        -- Build URL from remote, appending /api/packages if not already present
        local apiPath = "/api/packages"
        if not remoteUrl:match(apiPath .. "/?$") then
            remoteUrl = remoteUrl .. apiPath
        end
        
        local final = remoteUrl .. "/" .. author .. "/" .. packageName .. "/" .. version
        return final
    end
end

function packager:retrieve(address: string)
    local success, data = pcall(function() 
        return HttpService:GetAsync(address)
    end)
    if not success then 
        warn("[Packager] Failed to retrieve: " .. tostring(data))
        return nil 
    end
    return data
end

function packager:build(package: {any}, parent: Instance)
    if not package or not package.instances or #package.instances == 0 then
        warn("Invalid package data - no instances found")
        return
    end
    
    local function buildInstance(data, parentInstance)
        local instance = Instance.new(data.ClassName)
        instance.Name = data.Name

        if data.Properties then
            for propertyName, propertyData in pairs(data.Properties) do
                if propertyName ~= "ClassName" and propertyName ~= "Name" and propertyName ~= "Parent" then
                    if type(propertyData) == "table" and propertyData.type and propertyData.value then
                        pcall(function()
                            instance[propertyName] = propertyData.value
                        end)
                    elseif type(propertyData) ~= "table" or (propertyData.type ~= "Instance" and propertyData.type ~= "Object") then
                        pcall(function()
                            instance[propertyName] = propertyData
                        end)
                    end
                end
            end
        end

        if data.Children and #data.Children > 0 then
            for _, childData in ipairs(data.Children) do
                buildInstance(childData, instance)
            end
        end
        
        instance.Parent = parentInstance
        
        return instance
    end
    
    if type(package.instances) == "table" then
        for _, instanceData in ipairs(package.instances) do
            return buildInstance(instanceData, parent)
        end
    end
end

return packager