return function()
  coroutine.yield('dummy response')
  a()
end
