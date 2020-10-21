module.exports = {
  'presets': [
    [ '@babel/preset-env', {
      'targets': {
        'browsers': [
          'last 2 chrome versions',
          'last 2 firefox versions'
        ],
        'node': 'current'
      },
      'useBuiltIns': false
    } ]
  ],
  'ignore': [ 'node_modules' ],
  //'only': [ 'src', 'test' ],
  'plugins': [
    [
      '@babel/plugin-transform-runtime',
      {
        '@babel/polyfill': true,
        'regenerator': true
      }
    ]
  ],
  'env': {
    'production': {
      'plugins': ['babel-plugin-transform-remove-console']
    },
    'development': {
      'plugins': ['babel-plugin-istanbul']
    },
    'test': {
      'plugins': ['babel-plugin-istanbul']
    }
  }
};
