import proxy

if __name__ == '__main__':
  proxy.main([
    '--plugins', 'app_plugin.RedirectPlugin, app_plugin.MessageAVPlugin, proxy.plugin.WebServerPlugin',
    '--hostname', '::1',
    '--enable-web-server',
    '--log-level', 'INFO',
    # '--num-workers', '1',
  ])
