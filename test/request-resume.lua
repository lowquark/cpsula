return function()
  coroutine.yield('dummy response')
  return 'dummy response'
end
