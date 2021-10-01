import proxy

if __name__ == '__main__':
  proxy.main([
    '--plugins', 'app_plugin.RedirectPlugin',
    # '--disable-http-proxy',
    '--hostname', '::1',
    '--log-level', 'debug',
  ])
