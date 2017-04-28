# devops-dashboard-widget-virustotal

virustotal widget for the [devops-dashboard](https://stash.secure.root9b.com/projects/DEV/repos/devops-dashboard).

## Build

The widget is built with the help of [node](https://nodejs.org/), [npm](https://www.npmjs.com/), [bower](http://bower.io/) and [gulp](http://gulpjs.com/). For install instructions for node and npm, please have a look [here](https://docs.npmjs.com/getting-started/installing-node).

#### Installing bower and gulp

```bash
npm install -g bower
npm install -g gulp
```

#### Installing dependencies

```bash
npm install
bower install
```

#### Build devops-dashboard-widget-virustotal

```bash
gulp
```

The compiled and optimized files can be found in the *dist* directory.

#### Other build goals

Each goal can be used as a parameter for the gulp command.

* *clean*: removes the dist folder
* *lint*: checks css and javascript files for common errors
* *serve*: starts an webserver to test the widget

## Usage

### Add your built widget to the DevOps Dashboard
```bash
cp -r devops-dashboard-widget-virustotal/dist [devops-dashboard path]/src/app/widgets/devops-dashboard-widget-virustotal
```

### Update [devops-dashboard path]/src/app/widgets/widgets.module.js to load your new widget
```javascript
(function () {
  'use strict';

  angular.module('DevopsDashboard.widgets', [
    ...
    'DevopsDashboard.widgets.virustotal'
    ...
  ]);

})();
```
# devops-dashboard-widget-virustotal
