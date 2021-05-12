return function()
  coroutine.yield('dummy response')
  coroutine.yield({})
end
