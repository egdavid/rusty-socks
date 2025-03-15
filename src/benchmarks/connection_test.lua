-- benchmarks/connection_test.lua
local counter = 0
local threads = {}

function setup(thread)
    thread:set("id", counter)
    table.insert(threads, thread)
    counter = counter + 1
end

function init(args)
    -- WebSocket initialization
end