import proxy

if __name__ == '__main__':
  proxy.main([
    '--plugins', 'app_plugin.MessageAVPlugin, app_plugin.ProxyPassPlugin',
    '--hostname', '::1',
    '--log-level', 'INFO',
  ])
