// Karma configuration
// Generated on Wed Jun 13 2018 13:09:34 GMT+0900 (JST)

const path = require('path');

module.exports = (config) => {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['jasmine', 'browserify'],


    // list of files / patterns to load in the browser
    files: [
      './node_modules/js-crypto-utils/dist/jscu.bundle.js',
      { pattern: 'dist/**/*.bundle.js'},
      { pattern: 'test/**/*.js' },
    ],


    // list of files / patterns to exclude
    exclude: [
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      //'./src/**/*.js': [],
      './test/**/*.js': ['browserify']
    },

    browserify: {
      debug: true,
      transform: [
        ['babelify', { 'presets': ['@babel/preset-env'], plugins: ['istanbul']}],
      ],
      extensions: ['js', 'jsx']
    },

    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['coverage-istanbul'],
    coverageIstanbulReporter: {
      // reports can be any that are listed here: https://github.com/istanbuljs/istanbuljs/tree/73c25ce79f91010d1ff073aa6ff3fd01114f90db/packages/istanbul-reports/lib
      reports: ['html', 'lcovonly', 'text'],

      // base output directory. If you include %browser% in the path it will be replaced with the karma browser name
      dir: path.join(__dirname, 'coverage'),

      // Combines coverage information from multiple browsers into one report rather than outputting a report
      // for each browser.
      combineBrowserReports: true,

      // if using webpack and pre-loaders, work around webpack breaking the source path
      fixWebpackSourcePaths: true,

      // Omit files with no statements, no functions and no branches covered from the report
      skipFilesWithNoCoverage: true,

      // Most reporters accept additional config options. You can pass these through the `report-config` option
      'report-config': {
        // all options available at: https://github.com/istanbuljs/istanbuljs/blob/73c25ce79f91010d1ff073aa6ff3fd01114f90db/packages/istanbul-reports/lib/html/index.js#L257-L261
        html: {
          // outputs the report in ./coverage/html
          subdir: 'karma'
        }
      }
    },

    // karmaTypescriptConfig: {
    //   bundlerOptions: {
    //     constants: {
    //       'process.env': (typeof process.env.TEST_ENV !== 'undefined') ? { TEST_ENV: process.env.TEST_ENV } : {},
    //     }
    //   },
    //   coverageOptions:{
    //     exclude: /(test\/.*|\.(d|spec|test)\.ts)/i,
    //   },
    //   reports:
    //     {
    //       'html': {
    //         directory: 'coverage',
    //         subdirectory: 'karma/html'
    //       },
    //       'text':'',
    //       'lcovonly': {
    //         directory: 'coverage',
    //         subdirectory: 'karma'
    //       },
    //     }
    // },


    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    // autoWatch: true,


    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    // browsers: ['ChromeHeadless'],
    browsers: ['Chrome-headless'],
    customLaunchers: {
      'Chrome-headless': {
        base: 'Chrome',
        flags: ['--headless', '--remote-debugging-port=9222', '--no-sandbox']
      }
    },


    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: true,

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity
  });
};
