
--     address : string  -  URI authority (no userinfo)
--    resource : string  -  Sanitized remainder of URI, including first '/'
-- fingerprint : string  -  SHA-1 client certificate fingerprint
--      expiry : integer -  Client certificate expiration time (POSIX timestamp)

--[==[
return function(address, resource, fingerprint, expiry)
  print(address, resource, fingerprint, expiry);
  content =
[[# Page Heading

## WARNING: Lua-generated page

XD

]]
  return '20 text/gemini\r\n'..content
end
]==]

return function(address, resource, fingerprint, expiry)
  print(address, resource, fingerprint, expiry);
  local count = 10
  return coroutine.wrap(function()
    coroutine.yield('20 text/gemini\r\n')
    for i=0,10 do
      coroutine.yield('test '..tostring(i)..' : '..resource..' from '..address..'\n')
    end
  end)
end

