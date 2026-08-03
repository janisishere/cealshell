return {
    name = "clear",
    args = nil,
    callback = function()
        print(string.rep("\n", 50))
    end,
    description = "Clears the console.",
    manual = {
        "clear",
        "Scrolls Studio's Output window clean.",
        "Saved Cealshell output is untouched — use 'logs clear' for that.",
    },
    signer = "cealshell",
    alias = {"cls"},
}
